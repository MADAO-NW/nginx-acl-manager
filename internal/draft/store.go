package draft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/validation"
)

// ErrNotFound 表示指定项目草稿尚不存在。
var ErrNotFound = errors.New("项目草稿不存在")

// projectLocks 为同一进程内的项目读改写提供细粒度互斥。
var projectLocks sync.Map

// Store 将每个项目草稿保存为独立 JSON 文件。
type Store struct {
	Directory string
}

// List 返回按 slug 排序的全部项目草稿。
func (s Store) List() ([]model.Project, error) {
	entries, err := os.ReadDir(s.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return []model.Project{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取项目草稿目录: %w", err)
	}
	projects := make([]model.Project, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		slug := strings.TrimSuffix(entry.Name(), ".json")
		project, err := s.Load(slug)
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	slices.SortFunc(projects, func(a, b model.Project) int { return strings.Compare(a.Slug, b.Slug) })
	return projects, nil
}

// Load 读取并重新校验一个项目草稿。
func (s Store) Load(slug string) (model.Project, error) {
	if !validSlugForPath(slug) {
		return model.Project{}, errors.New("项目标识格式无效")
	}
	data, err := os.ReadFile(filepath.Join(s.Directory, slug+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return model.Project{}, ErrNotFound
	}
	if err != nil {
		return model.Project{}, fmt.Errorf("读取项目草稿: %w", err)
	}
	project, err := decodeProject(data)
	if err != nil {
		return model.Project{}, fmt.Errorf("解析项目 %q 草稿: %w", slug, err)
	}
	if project.Slug != slug {
		return model.Project{}, errors.New("项目草稿文件名与内部标识不一致")
	}
	return project, nil
}

// Create 创建新项目草稿，已存在时拒绝覆盖。
func (s Store) Create(project model.Project) error {
	if err := validation.ValidateProject(project); err != nil {
		return err
	}
	lock := lockFor(project.Slug)
	lock.Lock()
	defer lock.Unlock()
	path := filepath.Join(s.Directory, project.Slug+".json")
	if _, err := os.Lstat(path); err == nil {
		return errors.New("项目标识已存在")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("检查项目草稿: %w", err)
	}
	return writeProject(path, project)
}

// Update 在项目锁内重新读取最新草稿并应用单项修改。
func (s Store) Update(slug string, mutate func(*model.Project) error) error {
	if mutate == nil {
		return errors.New("草稿修改函数不能为空")
	}
	lock := lockFor(slug)
	lock.Lock()
	defer lock.Unlock()
	project, err := s.Load(slug)
	if err != nil {
		return err
	}
	if err := mutate(&project); err != nil {
		return err
	}
	if project.Slug != slug {
		return errors.New("项目稳定标识不可修改")
	}
	if err := validation.ValidateProject(project); err != nil {
		return err
	}
	return writeProject(filepath.Join(s.Directory, slug+".json"), project)
}

func lockFor(slug string) *sync.Mutex {
	value, _ := projectLocks.LoadOrStore(filepath.Clean(slug), &sync.Mutex{})
	return value.(*sync.Mutex)
}

func validSlugForPath(slug string) bool {
	if slug == "" || strings.ContainsAny(slug, `/\`) {
		return false
	}
	return filepath.Base(slug) == slug
}

func decodeProject(data []byte) (model.Project, error) {
	var project model.Project
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&project); err != nil {
		return model.Project{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Project{}, errors.New("草稿只能包含一个 JSON 对象")
		}
		return model.Project{}, err
	}
	if err := validation.ValidateProject(project); err != nil {
		return model.Project{}, err
	}
	return project, nil
}

func writeProject(path string, project model.Project) error {
	data, err := json.MarshalIndent(project, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化项目草稿: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建项目草稿目录: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".project-*.tmp")
	if err != nil {
		return fmt.Errorf("创建项目草稿临时文件: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
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
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
