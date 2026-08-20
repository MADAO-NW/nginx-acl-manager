package nginxprofile

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// CommandOutput 保存受控命令执行的标准输出和标准错误。
type CommandOutput struct {
	Stdout string
	Stderr string
}

// CommandRunner 是 root 校验器唯一允许使用的外部命令边界。
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (CommandOutput, error)
}

// RuntimeReport 只保存校验结论，不携带完整 Nginx 配置输出。
type RuntimeReport struct {
	BinaryPath      string
	ConfigPath      string
	PrefixPath      string
	HTTPIncludeFile string
	RealIPSnippet   string
	ServiceName     string
	MainPID         int
}

// RuntimeValidator 确认测试配置与实际 systemd Nginx 是同一个运行对象。
type RuntimeValidator struct {
	SystemctlPath string
	Runner        CommandRunner
	EvalSymlinks  func(string) (string, error)
}

// Validate 执行只读强校验；全局入口文件必须已经由外层事务准备好。
func (v RuntimeValidator) Validate(ctx context.Context, profile Profile) (RuntimeReport, error) {
	if err := ValidateCandidate(profile); err != nil {
		return RuntimeReport{}, err
	}
	if v.Runner == nil {
		return RuntimeReport{}, errors.New("root 命令执行器未配置")
	}
	if !filepath.IsAbs(v.SystemctlPath) || filepath.Clean(v.SystemctlPath) != v.SystemctlPath {
		return RuntimeReport{}, errors.New("systemctl 必须使用规范化绝对路径")
	}
	evalSymlinks := v.EvalSymlinks
	if evalSymlinks == nil {
		evalSymlinks = filepath.EvalSymlinks
	}

	resolvedBinary, err := resolvePath(evalSymlinks, "Nginx 二进制", profile.BinaryPath)
	if err != nil {
		return RuntimeReport{}, err
	}
	resolvedConfig, err := resolvePath(evalSymlinks, "Nginx 主配置", profile.ConfigPath)
	if err != nil {
		return RuntimeReport{}, err
	}
	resolvedInclude, err := resolvePath(evalSymlinks, "管理器全局入口", profile.HTTPIncludeFile)
	if err != nil {
		return RuntimeReport{}, err
	}
	resolvedRealIP, err := resolvePath(evalSymlinks, "real IP snippet", profile.RealIPSnippetPath)
	if err != nil {
		return RuntimeReport{}, err
	}
	resolvedPrefix := ""
	if profile.PrefixPath != "" {
		resolvedPrefix, err = resolvePath(evalSymlinks, "Nginx prefix", profile.PrefixPath)
		if err != nil {
			return RuntimeReport{}, err
		}
	}

	showOutput, err := v.Runner.Run(
		ctx,
		v.SystemctlPath,
		"show",
		profile.ServiceName,
		"--property=LoadState",
		"--property=ActiveState",
		"--property=FragmentPath",
		"--property=ExecStart",
		"--property=MainPID",
		"--no-pager",
	)
	if err != nil {
		return RuntimeReport{}, fmt.Errorf("读取 Nginx systemd 状态: %w", err)
	}
	properties, err := parseSystemctlProperties(showOutput.Stdout)
	if err != nil {
		return RuntimeReport{}, err
	}
	if properties["LoadState"] != "loaded" || properties["ActiveState"] != "active" {
		return RuntimeReport{}, errors.New("目标 Nginx service 未加载或未运行")
	}
	mainPID, err := strconv.Atoi(properties["MainPID"])
	if err != nil || mainPID <= 0 {
		return RuntimeReport{}, errors.New("目标 Nginx service 没有有效 MainPID")
	}

	execPath, execArgs, err := parseSystemdExecStart(properties["ExecStart"])
	if err != nil {
		return RuntimeReport{}, err
	}
	resolvedExec, err := resolvePath(evalSymlinks, "systemd ExecStart 二进制", execPath)
	if err != nil {
		return RuntimeReport{}, err
	}
	if resolvedExec != resolvedBinary {
		return RuntimeReport{}, errors.New("候选 Nginx 二进制与 systemd ExecStart 不一致")
	}

	serviceConfig, hasServiceConfig, err := optionValue(execArgs, "-c")
	if err != nil {
		return RuntimeReport{}, err
	}
	if hasServiceConfig {
		resolvedServiceConfig, err := resolvePath(evalSymlinks, "systemd Nginx 主配置", serviceConfig)
		if err != nil {
			return RuntimeReport{}, err
		}
		if resolvedServiceConfig != resolvedConfig {
			return RuntimeReport{}, errors.New("候选主配置与 systemd Nginx 的 -c 参数不一致")
		}
	} else {
		versionOutput, err := v.Runner.Run(ctx, resolvedBinary, "-V")
		if err != nil {
			return RuntimeReport{}, fmt.Errorf("读取 Nginx 编译参数: %w", err)
		}
		compiledConfig, err := compiledConfigPath(versionOutput.Stdout + "\n" + versionOutput.Stderr)
		if err != nil {
			return RuntimeReport{}, err
		}
		resolvedCompiledConfig, err := resolvePath(evalSymlinks, "Nginx 编译默认主配置", compiledConfig)
		if err != nil {
			return RuntimeReport{}, err
		}
		if resolvedCompiledConfig != resolvedConfig {
			return RuntimeReport{}, errors.New("候选主配置与 systemd Nginx 的编译默认配置不一致")
		}
	}

	servicePrefix, hasServicePrefix, err := optionValue(execArgs, "-p")
	if err != nil {
		return RuntimeReport{}, err
	}
	if hasServicePrefix {
		resolvedServicePrefix, err := resolvePath(evalSymlinks, "systemd Nginx prefix", servicePrefix)
		if err != nil {
			return RuntimeReport{}, err
		}
		if resolvedPrefix == "" || resolvedServicePrefix != resolvedPrefix {
			return RuntimeReport{}, errors.New("候选 prefix 与 systemd Nginx 的 -p 参数不一致")
		}
	} else if resolvedPrefix != "" {
		return RuntimeReport{}, errors.New("候选 Profile 设置了 prefix，但 systemd Nginx 未使用 -p")
	}

	command, args, err := NginxTestCommand(profile)
	if err != nil {
		return RuntimeReport{}, err
	}
	testOutput, err := v.Runner.Run(ctx, command, args...)
	if err != nil {
		return RuntimeReport{}, fmt.Errorf("Nginx 配置测试失败: %w", err)
	}
	expanded := testOutput.Stdout + "\n" + testOutput.Stderr
	if !hasConfigurationMarker(expanded, profile.ConfigPath, resolvedConfig) {
		return RuntimeReport{}, errors.New("nginx -T 输出的顶层配置与候选主配置不一致")
	}
	if !hasConfigurationMarker(expanded, profile.HTTPIncludeFile, resolvedInclude) {
		return RuntimeReport{}, errors.New("管理器全局入口未被实际 Nginx 配置树加载")
	}
	if !hasConfigurationMarker(expanded, profile.RealIPSnippetPath, resolvedRealIP) {
		return RuntimeReport{}, errors.New("real IP snippet 未被实际 Nginx 配置树加载")
	}
	if !hasDirective(expanded, "real_ip_header", "CF-Connecting-IP") || !hasDirectiveWithValue(expanded, "set_real_ip_from") {
		return RuntimeReport{}, errors.New("展开配置缺少 Cloudflare real IP 必要指令")
	}

	return RuntimeReport{
		BinaryPath:      resolvedBinary,
		ConfigPath:      resolvedConfig,
		PrefixPath:      resolvedPrefix,
		HTTPIncludeFile: resolvedInclude,
		RealIPSnippet:   resolvedRealIP,
		ServiceName:     profile.ServiceName,
		MainPID:         mainPID,
	}, nil
}

func resolvePath(evalSymlinks func(string) (string, error), label, path string) (string, error) {
	resolved, err := evalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("解析%s: %w", label, err)
	}
	return filepath.Clean(resolved), nil
}

func parseSystemctlProperties(output string) (map[string]string, error) {
	properties := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, errors.New("systemctl show 输出格式无效")
		}
		properties[key] = value
	}
	for _, key := range []string{"LoadState", "ActiveState", "FragmentPath", "ExecStart", "MainPID"} {
		if properties[key] == "" {
			return nil, fmt.Errorf("systemctl show 缺少 %s", key)
		}
	}
	return properties, nil
}

func parseSystemdExecStart(value string) (string, []string, error) {
	pathStart := strings.Index(value, "path=")
	argvStart := strings.Index(value, "argv[]=")
	if pathStart < 0 || argvStart < 0 {
		return "", nil, errors.New("无法解析 Nginx service 的 ExecStart")
	}
	pathValue := value[pathStart+len("path="):]
	if end := strings.IndexAny(pathValue, " ;"); end >= 0 {
		pathValue = pathValue[:end]
	}
	if pathValue == "" || !filepath.IsAbs(pathValue) {
		return "", nil, errors.New("Nginx service 的 ExecStart 不是绝对二进制路径")
	}

	argvValue := strings.TrimPrefix(value[argvStart+len("argv[]="):], " ")
	if marker := strings.Index(argvValue, " ; ignore_errors="); marker >= 0 {
		argvValue = argvValue[:marker]
	}
	if strings.ContainsAny(argvValue, "\"'\\") {
		return "", nil, errors.New("Nginx service 使用了第一版无法安全解析的复杂 ExecStart")
	}
	args := strings.Fields(argvValue)
	if len(args) == 0 {
		return "", nil, errors.New("Nginx service 的 ExecStart 参数为空")
	}
	return pathValue, args[1:], nil
}

func optionValue(args []string, option string) (string, bool, error) {
	found := ""
	for index, arg := range args {
		if arg != option {
			continue
		}
		if found != "" {
			return "", false, fmt.Errorf("Nginx ExecStart 重复使用 %s", option)
		}
		if index+1 >= len(args) || args[index+1] == "" || strings.HasPrefix(args[index+1], "-") {
			return "", false, fmt.Errorf("Nginx ExecStart 的 %s 缺少值", option)
		}
		found = args[index+1]
	}
	return found, found != "", nil
}

func compiledConfigPath(output string) (string, error) {
	const marker = "--conf-path="
	index := strings.Index(output, marker)
	if index < 0 {
		return "", errors.New("nginx -V 未提供 --conf-path，必须在 systemd ExecStart 中显式使用 -c")
	}
	value := output[index+len(marker):]
	if end := strings.IndexAny(value, " \t\r\n'"); end >= 0 {
		value = value[:end]
	}
	if value == "" || !filepath.IsAbs(value) {
		return "", errors.New("nginx -V 的 --conf-path 不是绝对路径")
	}
	return filepath.Clean(value), nil
}

func hasConfigurationMarker(output string, paths ...string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, path := range paths {
			if line == "# configuration file "+path+":" {
				return true
			}
		}
	}
	return false
}

func hasDirective(output, name, value string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == name && strings.TrimSuffix(fields[1], ";") == value && strings.HasSuffix(fields[1], ";") {
			return true
		}
	}
	return false
}

func hasDirectiveWithValue(output, name string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == name && fields[1] != ";" && strings.HasSuffix(fields[1], ";") {
			return true
		}
	}
	return false
}
