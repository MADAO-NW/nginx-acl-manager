package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"nginx-acl-manager/internal/generator"
	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/nginxprofile"
)

const transactionStageSwitched = "current-switched"

// Transaction 保存切换 current 后尚未完成 reload 的恢复依据。
type Transaction struct {
	OldRevision string `json:"oldRevision,omitempty"`
	NewRevision string `json:"newRevision"`
	Stage       string `json:"stage"`
}

// Result 是 Web 可以安全展示的发布结果摘要。
type Result struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	Revision  string    `json:"revision,omitempty"`
	Project   string    `json:"project,omitempty"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
}

// Publisher 由固定 root oneshot 调用并负责 release 切换与回滚。
type Publisher struct {
	Store       Store
	Profiles    nginxprofile.Store
	Validator   nginxprofile.RuntimeValidator
	Runner      nginxprofile.CommandRunner
	Systemctl   string
	LockPath    string
	ResultGID   int
	Now         func() time.Time
	AfterSwitch func() error
}

// EnsureInitialRelease 创建无项目的初始版本并设置 current。
func (s Store) EnsureInitialRelease() (string, error) {
	if revision, err := s.CurrentRevision(); err == nil {
		return revision, nil
	} else if !errors.Is(err, ErrNoCurrent) {
		return "", err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	revision, err := newRevision(now())
	if err != nil {
		return "", err
	}
	candidate := model.Candidate{Action: "initial", Projects: []model.Project{}}
	if err := s.buildRelease(revision, "", candidate); err != nil {
		return "", err
	}
	if err := s.switchCurrent(revision); err != nil {
		return "", err
	}
	return revision, nil
}

// RollbackInitial 只删除本次 Profile apply 创建且仍为 current 的空初始 release。
func (s Store) RollbackInitial(revision string) error {
	if !validRevision(revision) {
		return errors.New("revision 格式无效")
	}
	current, err := s.CurrentRevision()
	if err != nil || current != revision {
		return errors.New("初始 release 已不再是 current")
	}
	manifestData, err := os.ReadFile(filepath.Join(s.AccessControlRoot, "releases", revision, "manifest.json"))
	if err != nil {
		return err
	}
	var manifest Manifest
	if err := decodeStrict(manifestData, &manifest); err != nil || manifest.Action != "initial" {
		return errors.New("目标不是可回滚的初始 release")
	}
	if err := os.Remove(filepath.Join(s.AccessControlRoot, "current")); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(s.AccessControlRoot, "releases", revision))
}

// Publish 从固定候选文件重新校验并发布完整 release。
func (p Publisher) Publish(ctx context.Context) (result Result, err error) {
	if p.Runner == nil || p.Systemctl == "" {
		return Result{}, errors.New("发布命令依赖未配置")
	}
	unlock, err := acquireLock(p.LockPath)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := p.recoverUnlocked(); err != nil {
		return Result{}, err
	}
	candidate, err := p.Store.LoadCandidate()
	if err != nil {
		return p.failure(candidate, "发布候选无效"), err
	}
	profile, err := p.Profiles.LoadActive()
	if err != nil {
		return p.failure(candidate, "请先验证并应用 Nginx 设置"), err
	}
	oldRevision, err := p.Store.CurrentRevision()
	if err != nil {
		return p.failure(candidate, "当前发布版本无效"), err
	}
	if candidate.SourceRevision != oldRevision {
		return p.failure(candidate, "发布候选已过期，请重新预览后发布"), errors.New("候选来源版本与 current 不一致")
	}
	now := p.now()
	newRevision, err := newRevision(now)
	if err != nil {
		return p.failure(candidate, "无法生成发布编号"), err
	}
	if err := p.Store.buildRelease(newRevision, oldRevision, candidate); err != nil {
		return p.failure(candidate, "生成发布版本失败"), err
	}
	transaction := Transaction{OldRevision: oldRevision, NewRevision: newRevision, Stage: transactionStageSwitched}
	if err := writeJSONAtomic(p.Store.TransactionPath, transaction, 0o600); err != nil {
		return p.failure(candidate, "记录发布事务失败"), err
	}
	if err := p.Store.switchCurrent(newRevision); err != nil {
		_ = os.Remove(p.Store.TransactionPath)
		return p.failure(candidate, "切换发布版本失败"), err
	}
	rollback := func(cause error) error {
		if restoreErr := p.Store.switchCurrent(oldRevision); restoreErr != nil {
			return fmt.Errorf("%v；恢复旧版本失败: %w", cause, restoreErr)
		}
		_, _ = p.runNginxTest(ctx, profile)
		_, _ = p.Runner.Run(ctx, p.Systemctl, "reload", profile.ServiceName)
		_ = os.Remove(p.Store.TransactionPath)
		return cause
	}
	if p.AfterSwitch != nil {
		if err := p.AfterSwitch(); err != nil {
			return p.failure(candidate, "发布切换后校验失败"), rollback(err)
		}
	}
	if _, err := p.Validator.Validate(ctx, profile); err != nil {
		return p.failure(candidate, "Nginx Profile 漂移或配置校验失败"), rollback(err)
	}
	expanded, err := p.runNginxTest(ctx, profile)
	if err != nil {
		return p.failure(candidate, "Nginx 配置测试失败"), rollback(err)
	}
	if err := p.checkInstanceIncludes(candidate.Projects, newRevision, expanded); err != nil {
		return p.failure(candidate, "实例尚未完成 Nginx 接入"), rollback(err)
	}
	if _, err := p.Runner.Run(ctx, p.Systemctl, "reload", profile.ServiceName); err != nil {
		return p.failure(candidate, "Nginx reload 失败"), rollback(err)
	}
	if _, err := p.Runner.Run(ctx, p.Systemctl, "is-active", "--quiet", profile.ServiceName); err != nil {
		return p.failure(candidate, "Nginx reload 后未保持 active"), rollback(err)
	}
	if err := os.Remove(p.Store.TransactionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return p.failure(candidate, "清理发布事务失败"), err
	}
	result = Result{Success: true, Action: candidate.Action, Revision: newRevision, Project: candidate.ChangedProject, Message: "发布成功", CreatedAt: now}
	if writeErr := p.writeResult(result); writeErr != nil {
		return result, writeErr
	}
	return result, nil
}

// Recover 在 Nginx 启动或新发布前恢复未完成事务的旧 current。
func (p Publisher) Recover() error {
	unlock, err := acquireLock(p.LockPath)
	if err != nil {
		return err
	}
	defer unlock()
	return p.recoverUnlocked()
}

func (p Publisher) recoverUnlocked() error {
	data, err := os.ReadFile(p.Store.TransactionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var transaction Transaction
	if err := decodeStrict(data, &transaction); err != nil {
		return fmt.Errorf("发布事务文件损坏: %w", err)
	}
	if transaction.Stage != transactionStageSwitched || !validRevision(transaction.OldRevision) {
		return errors.New("发布事务无法自动恢复")
	}
	if err := p.Store.switchCurrent(transaction.OldRevision); err != nil {
		return err
	}
	return os.Remove(p.Store.TransactionPath)
}

func (s Store) buildRelease(revision, previous string, candidate model.Candidate) error {
	files, err := generator.Generate(candidate.Projects)
	if err != nil {
		return err
	}
	releasesDirectory := filepath.Join(s.AccessControlRoot, "releases")
	if err := os.MkdirAll(releasesDirectory, 0o755); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(releasesDirectory, ".release-*.tmp")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	hashes := make(map[string]string, len(files))
	for path, content := range files {
		destination := filepath.Join(temporary, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(destination, content, 0o644); err != nil {
			return err
		}
		digest := sha256.Sum256(content)
		hashes[path] = hex.EncodeToString(digest[:])
	}
	for _, project := range candidate.Projects {
		path := filepath.Join(temporary, "projects", project.Slug, "source.json")
		if err := writeJSONAtomic(path, project, 0o644); err != nil {
			return err
		}
	}
	manifest := Manifest{Revision: revision, CreatedAt: s.now(), Previous: previous, ChangedProject: candidate.ChangedProject, Action: candidate.Action, Files: hashes}
	if err := writeJSONAtomic(filepath.Join(temporary, "manifest.json"), manifest, 0o644); err != nil {
		return err
	}
	// root oneshot 的 UMask 不得阻止 Web 只读访问已完成的不可变 release。
	if err := filepath.WalkDir(temporary, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		mode := os.FileMode(0o644)
		if entry.IsDir() {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	}); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(releasesDirectory, revision)); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s Store) switchCurrent(revision string) error {
	if !validRevision(revision) {
		return errors.New("revision 格式无效")
	}
	if info, err := os.Stat(filepath.Join(s.AccessControlRoot, "releases", revision)); err != nil || !info.IsDir() {
		return errors.New("目标 release 不存在")
	}
	if err := os.MkdirAll(s.AccessControlRoot, 0o755); err != nil {
		return err
	}
	temporary := filepath.Join(s.AccessControlRoot, ".current.tmp")
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("releases", revision), temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(s.AccessControlRoot, "current")); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (p Publisher) runNginxTest(ctx context.Context, profile nginxprofile.Profile) (string, error) {
	command, args, err := nginxprofile.NginxTestCommand(profile)
	if err != nil {
		return "", err
	}
	output, err := p.Runner.Run(ctx, command, args...)
	return output.Stdout + "\n" + output.Stderr, err
}

func (p Publisher) checkInstanceIncludes(projects []model.Project, revision, expanded string) error {
	for _, project := range projects {
		for _, instance := range project.Instances {
			if !instance.Enabled || !hasEnabledRules(instance) {
				continue
			}
			base := filepath.Join(p.Store.AccessControlRoot, "releases", revision, "projects", project.Slug, "instances", instance.Key)
			currentBase := filepath.Join(p.Store.AccessControlRoot, "current", "projects", project.Slug, "instances", instance.Key)
			for _, relative := range []string{"http/10-allowlist.conf", "http/20-routes.conf", "location/10-enforce.conf"} {
				if !strings.Contains(expanded, "# configuration file "+filepath.Join(base, relative)+":") &&
					!strings.Contains(expanded, "# configuration file "+filepath.Join(currentBase, relative)+":") {
					return fmt.Errorf("实例 %s/%s 缺少 %s include", project.Slug, instance.Key, relative)
				}
			}
		}
	}
	return nil
}

func hasEnabledRules(instance model.Instance) bool {
	for _, rule := range instance.Rules {
		if rule.Enabled {
			return true
		}
	}
	return false
}

func (p Publisher) failure(candidate model.Candidate, message string) Result {
	result := Result{Success: false, Action: candidate.Action, Project: candidate.ChangedProject, Message: message, CreatedAt: p.now()}
	_ = p.writeResult(result)
	return result
}

func (p Publisher) writeResult(result Result) error {
	if p.Store.ResultPath == "" {
		return nil
	}
	if err := writeJSONAtomic(p.Store.ResultPath, result, 0o640); err != nil {
		return err
	}
	if p.ResultGID > 0 {
		return os.Chown(p.Store.ResultPath, 0, p.ResultGID)
	}
	return nil
}

func (p Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func acquireLock(path string) (func(), error) {
	if path == "" {
		return nil, errors.New("发布锁路径未配置")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}

// LoadResult 读取最近一次发布的安全摘要。
func (s Store) LoadResult() (Result, error) {
	data, err := os.ReadFile(s.ResultPath)
	if err != nil {
		return Result{}, err
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return Result{}, err
	}
	return result, nil
}
