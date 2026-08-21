package nginxprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"nginx-acl-manager/internal/generator"
)

const managedIncludePrefix = "# managed-by: nginx-acl-manager; scope=http; version=1\n"

const managedSystemdPrefix = "# managed-by: nginx-acl-manager\n"

// ApplyResult 是 Web 可以读取的最近一次 Profile 应用摘要。
type ApplyResult struct {
	Success   bool      `json:"success"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"createdAt"`
}

// InitialReleaseStore 提供 Profile 首次接管所需的空 current 初始化能力。
type InitialReleaseStore interface {
	CurrentRevision() (string, error)
	EnsureInitialRelease() (string, error)
	RollbackInitial(revision string) error
}

// ApplyOptions 固定 root Profile apply 所需的路径和命令边界。
type ApplyOptions struct {
	Profiles          Store
	Releases          InitialReleaseStore
	AccessControlRoot string
	Validator         RuntimeValidator
	Runner            CommandRunner
	SystemctlPath     string
	ApplicationUID    int
	ApplicationGID    int
	ResultPath        string
	RecoverUnitPath   string
	SystemdRoot       string
	BinaryPath        string
	Now               func() time.Time
}

// ApplyCandidate 重新读取固定候选文件并事务式应用正式 Profile。
func ApplyCandidate(ctx context.Context, options ApplyOptions) (err error) {
	profile, err := options.Profiles.LoadCandidate()
	if err != nil {
		return writeApplyFailure(options, "候选 Profile 无效", err)
	}
	if options.Runner == nil {
		return writeApplyFailure(options, "root 命令执行器未配置", errors.New("runner missing"))
	}
	if options.Releases == nil || options.AccessControlRoot == "" {
		return writeApplyFailure(options, "release 初始化依赖未配置", errors.New("release store missing"))
	}
	oldProfile, oldProfileErr := options.Profiles.LoadActive()
	if oldProfileErr != nil && !errors.Is(oldProfileErr, ErrNotFound) {
		return writeApplyFailure(options, "原正式 Profile 无法读取", oldProfileErr)
	}
	committed := false
	reloadStarted := false
	defer func() {
		if !committed && reloadStarted {
			_, _ = options.Runner.Run(context.Background(), options.SystemctlPath, "daemon-reload")
			_, _ = options.Runner.Run(context.Background(), options.SystemctlPath, "reload", profile.ServiceName)
		}
	}()
	for label, path := range map[string]string{
		"Nginx 二进制":       profile.BinaryPath,
		"Nginx 主配置":       profile.ConfigPath,
		"real IP snippet": profile.RealIPSnippetPath,
	} {
		if err := validateProtectedPath(label, path, options.ApplicationUID, options.ApplicationGID); err != nil {
			return writeApplyFailure(options, "候选路径权限不安全", err)
		}
	}
	if err := requirePathType("Nginx 二进制", profile.BinaryPath, false, true); err != nil {
		return writeApplyFailure(options, "候选路径类型无效", err)
	}
	for label, path := range map[string]string{"Nginx 主配置": profile.ConfigPath, "real IP snippet": profile.RealIPSnippetPath} {
		if err := requirePathType(label, path, false, false); err != nil {
			return writeApplyFailure(options, "候选路径类型无效", err)
		}
	}
	if profile.PrefixPath != "" {
		if err := validateProtectedPath("Nginx prefix", profile.PrefixPath, options.ApplicationUID, options.ApplicationGID); err != nil {
			return writeApplyFailure(options, "候选路径权限不安全", err)
		}
		if err := requirePathType("Nginx prefix", profile.PrefixPath, true, false); err != nil {
			return writeApplyFailure(options, "候选路径类型无效", err)
		}
	}
	if err := validateProtectedAncestors(filepath.Dir(profile.HTTPIncludeFile), options.ApplicationUID, options.ApplicationGID); err != nil {
		return writeApplyFailure(options, "全局入口父目录权限不安全", err)
	}

	oldInclude, includeExisted, err := prepareManagedInclude(profile.HTTPIncludeFile)
	if err != nil {
		return writeApplyFailure(options, "全局入口文件不可接管", err)
	}
	rollbackInclude := true
	defer func() {
		if rollbackInclude {
			_ = restoreInclude(profile.HTTPIncludeFile, oldInclude, includeExisted)
		}
	}()
	_, currentErr := options.Releases.CurrentRevision()
	initialRevision, err := options.Releases.EnsureInitialRelease()
	if err != nil {
		return writeApplyFailure(options, "初始化空发布版本失败", err)
	}
	rollbackInitial := currentErr != nil
	defer func() {
		if !committed && rollbackInitial {
			_ = options.Releases.RollbackInitial(initialRevision)
		}
	}()

	probe := append(generator.HTTPIncludeContent(options.AccessControlRoot), []byte("\nmap $request_method $nginx_acl_manager_profile_probe { default 0; }\n")...)
	if err := writeProfileFile(profile.HTTPIncludeFile, probe, 0o644); err != nil {
		return writeApplyFailure(options, "写入全局入口探针失败", err)
	}
	if err := validateProtectedPath("管理器全局入口", profile.HTTPIncludeFile, options.ApplicationUID, options.ApplicationGID); err != nil {
		return writeApplyFailure(options, "全局入口权限不安全", err)
	}
	if _, err := runNginxTest(ctx, options.Runner, profile); err != nil {
		return writeApplyFailure(options, "全局入口不在 http 上下文或配置测试失败", err)
	}
	if err := writeProfileFile(profile.HTTPIncludeFile, generator.HTTPIncludeContent(options.AccessControlRoot), 0o644); err != nil {
		return writeApplyFailure(options, "写入全局入口失败", err)
	}
	if _, err := options.Validator.Validate(ctx, profile); err != nil {
		return writeApplyFailure(options, "Nginx 运行对象强校验失败", err)
	}

	oldServiceName := ""
	if oldProfileErr == nil {
		oldServiceName = oldProfile.ServiceName
	}
	unitBackups, err := renderRecoveryUnits(options, profile, oldServiceName)
	if err != nil {
		return writeApplyFailure(options, "生成恢复 unit 失败", err)
	}
	rollbackUnits := true
	defer func() {
		if rollbackUnits {
			_ = restoreFiles(unitBackups)
			_, _ = options.Runner.Run(context.Background(), options.SystemctlPath, "daemon-reload")
		}
	}()
	if _, err := options.Runner.Run(ctx, options.SystemctlPath, "daemon-reload"); err != nil {
		return writeApplyFailure(options, "systemd daemon-reload 失败", err)
	}
	reloadStarted = true
	if _, err := options.Runner.Run(ctx, options.SystemctlPath, "reload", profile.ServiceName); err != nil {
		return writeApplyFailure(options, "Nginx reload 失败", err)
	}
	if _, err := options.Runner.Run(ctx, options.SystemctlPath, "is-active", "--quiet", profile.ServiceName); err != nil {
		return writeApplyFailure(options, "Nginx reload 后未保持 active", err)
	}
	if _, err := options.Validator.Validate(ctx, profile); err != nil {
		return writeApplyFailure(options, "reload 后复验失败", err)
	}
	if err := options.Profiles.SaveActive(profile); err != nil {
		return writeApplyFailure(options, "保存正式 Profile 失败", err)
	}
	rollbackInclude = false
	rollbackUnits = false
	committed = true
	return writeApplyResult(options, ApplyResult{Success: true, Message: "Nginx Profile 已验证并应用", CreatedAt: now(options)})
}

// LoadApplyResult 读取最近一次 Profile 应用摘要。
func LoadApplyResult(path string) (ApplyResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ApplyResult{}, err
	}
	var result ApplyResult
	if err := json.Unmarshal(data, &result); err != nil {
		return ApplyResult{}, err
	}
	return result, nil
}

func validateProtectedPath(label, path string, applicationUID, applicationGID int) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("解析%s: %w", label, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("读取%s: %w", label, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("无法读取%s所有权", label)
	}
	mode := info.Mode().Perm()
	if int(stat.Uid) == applicationUID && mode&0o200 != 0 {
		return fmt.Errorf("%s可被应用用户写入", label)
	}
	if int(stat.Gid) == applicationGID && mode&0o020 != 0 {
		return fmt.Errorf("%s可被应用组写入", label)
	}
	if mode&0o002 != 0 {
		return fmt.Errorf("%s可被任意用户写入", label)
	}
	return nil
}

func validateProtectedAncestors(path string, applicationUID, applicationGID int) error {
	current := filepath.Clean(path)
	for {
		if _, err := os.Stat(current); errors.Is(err, os.ErrNotExist) {
			parent := filepath.Dir(current)
			if parent == current {
				return err
			}
			current = parent
			continue
		} else if err != nil {
			return err
		}
		if err := validateProtectedPath("管理器全局入口父目录", current, applicationUID, applicationGID); err != nil {
			return err
		}
		if current == string(filepath.Separator) {
			return nil
		}
		current = filepath.Dir(current)
	}
}

func requirePathType(label, path string, directory, executable bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("%s必须是目录", label)
	}
	if !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("%s必须是普通文件", label)
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s不可执行", label)
	}
	return nil
}

func prepareManagedInclude(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(data) < len(managedIncludePrefix) || string(data[:len(managedIncludePrefix)]) != managedIncludePrefix {
		return nil, true, errors.New("目标文件已存在且不带管理器标记")
	}
	return data, true, nil
}

func restoreInclude(path string, content []byte, existed bool) error {
	if existed {
		return writeProfileFile(path, content, 0o644)
	}
	return os.Remove(path)
}

func runNginxTest(ctx context.Context, runner CommandRunner, profile Profile) (string, error) {
	command, args, err := NginxTestCommand(profile)
	if err != nil {
		return "", err
	}
	output, err := runner.Run(ctx, command, args...)
	if err != nil {
		return "", err
	}
	return output.Stdout + "\n" + output.Stderr, nil
}

type fileBackup struct {
	path    string
	content []byte
	existed bool
}

func renderRecoveryUnits(options ApplyOptions, profile Profile, oldServiceName string) ([]fileBackup, error) {
	dropIn := filepath.Join(options.SystemdRoot, profile.ServiceName+".d", "50-nginx-acl-manager-recover.conf")
	files := map[string][]byte{
		options.RecoverUnitPath: []byte(fmt.Sprintf(managedSystemdPrefix+"[Unit]\nDescription=Recover unfinished Nginx ACL Manager publish\nBefore=%s\n\n[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0027\nExecStart=%s recover\n", profile.ServiceName, options.BinaryPath)),
		dropIn:                  []byte(managedSystemdPrefix + "[Unit]\nRequires=nginx-acl-manager-recover.service\nAfter=nginx-acl-manager-recover.service\n"),
	}
	backups := make([]fileBackup, 0, len(files))
	if oldServiceName != "" && oldServiceName != profile.ServiceName {
		oldDropIn := filepath.Join(options.SystemdRoot, oldServiceName+".d", "50-nginx-acl-manager-recover.conf")
		content, err := os.ReadFile(oldDropIn)
		if err == nil && string(content) == managedSystemdPrefix+"[Unit]\nRequires=nginx-acl-manager-recover.service\nAfter=nginx-acl-manager-recover.service\n" {
			backups = append(backups, fileBackup{path: oldDropIn, content: content, existed: true})
			if err := os.Remove(oldDropIn); err != nil {
				return nil, err
			}
		} else if err == nil {
			return nil, errors.New("原 Nginx service 的恢复 drop-in 已被外部修改")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	for path, content := range files {
		backup := fileBackup{path: path}
		old, err := os.ReadFile(path)
		if err == nil {
			if len(old) < len(managedSystemdPrefix) || string(old[:len(managedSystemdPrefix)]) != managedSystemdPrefix {
				_ = restoreFiles(backups)
				return nil, fmt.Errorf("systemd 文件 %s 已存在且不带管理器标记", path)
			}
			backup.content = old
			backup.existed = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		backups = append(backups, backup)
		if err := writeProfileFile(path, content, 0o644); err != nil {
			_ = restoreFiles(backups)
			return nil, err
		}
	}
	return backups, nil
}

func restoreFiles(backups []fileBackup) error {
	for _, backup := range backups {
		if backup.existed {
			if err := writeProfileFile(backup.path, backup.content, 0o644); err != nil {
				return err
			}
		} else if err := os.Remove(backup.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeProfileFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".nginx-acl-manager-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func writeApplyFailure(options ApplyOptions, message string, cause error) error {
	_ = writeApplyResult(options, ApplyResult{Success: false, Message: message, CreatedAt: now(options)})
	return fmt.Errorf("%s: %w", message, cause)
}

func writeApplyResult(options ApplyOptions, result ApplyResult) error {
	if options.ResultPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := writeProfileFile(options.ResultPath, append(data, '\n'), 0o640); err != nil {
		return err
	}
	if options.ApplicationGID > 0 {
		return os.Chown(options.ResultPath, 0, options.ApplicationGID)
	}
	return nil
}

func now(options ApplyOptions) time.Time {
	if options.Now != nil {
		return options.Now().UTC()
	}
	return time.Now().UTC()
}
