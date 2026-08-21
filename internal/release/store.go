package release

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"nginx-acl-manager/internal/generator"
	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/validation"
)

// ErrNoCurrent 表示尚未创建初始 release。
var ErrNoCurrent = errors.New("当前发布版本不存在")

// Manifest 记录不可变 release 的来源和文件摘要。
type Manifest struct {
	Revision       string            `json:"revision"`
	CreatedAt      time.Time         `json:"createdAt"`
	Previous       string            `json:"previous,omitempty"`
	ChangedProject string            `json:"changedProject,omitempty"`
	Action         string            `json:"action"`
	Files          map[string]string `json:"files"`
}

// Store 管理候选文件、不可变 release 和 current 指针。
type Store struct {
	AccessControlRoot string
	CandidatePath     string
	TransactionPath   string
	ResultPath        string
	Now               func() time.Time
}

// LoadCandidate 从固定 staging 文件严格读取完整候选状态。
func (s Store) LoadCandidate() (model.Candidate, error) {
	data, err := os.ReadFile(s.CandidatePath)
	if err != nil {
		return model.Candidate{}, fmt.Errorf("读取发布候选: %w", err)
	}
	var candidate model.Candidate
	if err := decodeStrict(data, &candidate); err != nil {
		return model.Candidate{}, fmt.Errorf("解析发布候选: %w", err)
	}
	if candidate.Action != "publish" && candidate.Action != "restore" {
		return model.Candidate{}, errors.New("发布候选动作无效")
	}
	if err := validation.ValidateProjects(candidate.Projects); err != nil {
		return model.Candidate{}, err
	}
	return candidate, nil
}

// SaveCandidate 在 Web 所有的 staging 目录中原子保存完整候选状态。
func (s Store) SaveCandidate(candidate model.Candidate) error {
	if candidate.Action != "publish" && candidate.Action != "restore" {
		return errors.New("发布候选动作无效")
	}
	if err := validation.ValidateProjects(candidate.Projects); err != nil {
		return err
	}
	return writeJSONAtomic(s.CandidatePath, candidate, 0o600)
}

// CurrentRevision 只接受指向 releases 直接子目录的 current 符号链接。
func (s Store) CurrentRevision() (string, error) {
	target, err := os.Readlink(filepath.Join(s.AccessControlRoot, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoCurrent
	}
	if err != nil {
		return "", fmt.Errorf("读取 current 指针: %w", err)
	}
	clean := filepath.Clean(target)
	if filepath.IsAbs(clean) || filepath.Dir(clean) != "releases" || filepath.Base(clean) == "." || filepath.Base(clean) == ".." {
		return "", errors.New("current 指针目标无效")
	}
	return filepath.Base(clean), nil
}

// LoadCurrentProjects 读取当前 release 的全部项目快照。
func (s Store) LoadCurrentProjects() ([]model.Project, string, error) {
	revision, err := s.CurrentRevision()
	if err != nil {
		return nil, "", err
	}
	projects, err := s.LoadRevisionProjects(revision)
	return projects, revision, err
}

// LoadRevisionProjects 读取并校验指定不可变 revision 的全部项目快照。
func (s Store) LoadRevisionProjects(revision string) ([]model.Project, error) {
	if !validRevision(revision) {
		return nil, errors.New("revision 格式无效")
	}
	directory := filepath.Join(s.AccessControlRoot, "releases", revision, "projects")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []model.Project{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 release 项目目录: %w", err)
	}
	projects := make([]model.Project, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name(), "source.json"))
		if err != nil {
			return nil, fmt.Errorf("读取 release 项目 %q: %w", entry.Name(), err)
		}
		var project model.Project
		if err := decodeStrict(data, &project); err != nil {
			return nil, err
		}
		if project.Slug != entry.Name() {
			return nil, errors.New("release 项目目录与内部标识不一致")
		}
		projects = append(projects, project)
	}
	if err := validation.ValidateProjects(projects); err != nil {
		return nil, err
	}
	slices.SortFunc(projects, func(a, b model.Project) int { return strings.Compare(a.Slug, b.Slug) })
	return projects, nil
}

// ListManifests 返回按创建时间倒序排列的全部发布历史。
func (s Store) ListManifests() ([]Manifest, error) {
	directory := filepath.Join(s.AccessControlRoot, "releases")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []Manifest{}, nil
	}
	if err != nil {
		return nil, err
	}
	manifests := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name(), "manifest.json"))
		if err != nil {
			return nil, err
		}
		var manifest Manifest
		if err := decodeStrict(data, &manifest); err != nil {
			return nil, err
		}
		if manifest.Revision != entry.Name() {
			return nil, errors.New("manifest revision 与目录名不一致")
		}
		manifests = append(manifests, manifest)
	}
	slices.SortFunc(manifests, func(a, b Manifest) int {
		if comparison := b.CreatedAt.Compare(a.CreatedAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(b.Revision, a.Revision)
	})
	return manifests, nil
}

// PrepareProjectCandidate 只用目标草稿替换当前同项目快照。
func (s Store) PrepareProjectCandidate(project model.Project, action string) (model.Candidate, error) {
	if err := validation.ValidateProject(project); err != nil {
		return model.Candidate{}, err
	}
	projects, revision, err := s.LoadCurrentProjects()
	if errors.Is(err, ErrNoCurrent) {
		projects = []model.Project{}
		revision = ""
	} else if err != nil {
		return model.Candidate{}, err
	}
	projects = replaceProject(projects, project)
	return model.Candidate{Action: action, ChangedProject: project.Slug, SourceRevision: revision, Projects: projects}, nil
}

// PrepareRestoreCandidate 从历史版本恢复一个项目，同时保留其他当前项目。
func (s Store) PrepareRestoreCandidate(slug, revision string) (model.Candidate, error) {
	historical, err := s.LoadRevisionProjects(revision)
	if err != nil {
		return model.Candidate{}, err
	}
	var selected *model.Project
	for index := range historical {
		if historical[index].Slug == slug {
			copy := historical[index]
			selected = &copy
			break
		}
	}
	if selected == nil {
		return model.Candidate{}, errors.New("历史版本中不存在该项目")
	}
	return s.PrepareProjectCandidate(*selected, "restore")
}

// Preview 生成候选文件及其相对当前 release 的可读统一差异。
func (s Store) Preview(candidate model.Candidate) (generator.FileSet, string, error) {
	files, err := generator.Generate(candidate.Projects)
	if err != nil {
		return nil, "", err
	}
	current := generator.FileSet{}
	revision, err := s.CurrentRevision()
	if err == nil {
		current, err = readGeneratedFiles(filepath.Join(s.AccessControlRoot, "releases", revision))
	}
	if err != nil && !errors.Is(err, ErrNoCurrent) {
		return nil, "", err
	}
	return files, UnifiedDiff(current, files), nil
}

func replaceProject(projects []model.Project, replacement model.Project) []model.Project {
	result := make([]model.Project, 0, len(projects)+1)
	found := false
	for _, project := range projects {
		if project.Slug == replacement.Slug {
			result = append(result, replacement)
			found = true
		} else {
			result = append(result, project)
		}
	}
	if !found {
		result = append(result, replacement)
	}
	slices.SortFunc(result, func(a, b model.Project) int { return strings.Compare(a.Slug, b.Slug) })
	return result
}

func validRevision(revision string) bool {
	return revision != "" && filepath.Base(revision) == revision && !strings.ContainsAny(revision, "/\\\x00\r\n")
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON 只能包含一个值")
		}
		return err
	}
	return nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data, mode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, ".atomic-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func newRevision(now time.Time) (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return now.UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random), nil
}
