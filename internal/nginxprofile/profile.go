package nginxprofile

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	DefaultServiceName       = "nginx.service"
	DefaultHTTPIncludeFile   = "/etc/nginx/conf.d/50-nginx-acl-manager.conf"
	DefaultRealIPSnippetPath = "/etc/nginx/snippets/cloudflare-real-ip.conf"
)

// serviceNamePattern 限制页面只能提交结构化的 systemd service 名称。
var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]+\.service$`)

// Profile 描述需要被强校验并最终用于发布的本机 Nginx 运行对象。
type Profile struct {
	BinaryPath        string `json:"binaryPath"`
	ConfigPath        string `json:"configPath"`
	PrefixPath        string `json:"prefixPath,omitempty"`
	ServiceName       string `json:"serviceName"`
	HTTPIncludeFile   string `json:"httpIncludeFile"`
	RealIPSnippetPath string `json:"realIpSnippetPath"`
}

// FieldErrors 保存可直接映射到 Web 表单字段的基础校验错误。
type FieldErrors map[string]string

func (e FieldErrors) Error() string {
	return "Nginx Profile 字段校验失败"
}

// DefaultCandidate 返回 Notion 基线能够明确提供的候选值。
func DefaultCandidate(detectedBinaryPath string) Profile {
	return Profile{
		BinaryPath:        detectedBinaryPath,
		ServiceName:       DefaultServiceName,
		HTTPIncludeFile:   DefaultHTTPIncludeFile,
		RealIPSnippetPath: DefaultRealIPSnippetPath,
	}
}

// ValidateCandidate 校验 Web 层可以确定的结构和格式，不代替 root 强校验。
func ValidateCandidate(profile Profile) error {
	errs := FieldErrors{}
	validateAbsolutePath(errs, "binaryPath", profile.BinaryPath, true)
	validateAbsolutePath(errs, "configPath", profile.ConfigPath, true)
	validateAbsolutePath(errs, "prefixPath", profile.PrefixPath, false)
	validateAbsolutePath(errs, "httpIncludeFile", profile.HTTPIncludeFile, true)
	validateAbsolutePath(errs, "realIpSnippetPath", profile.RealIPSnippetPath, true)

	if profile.ServiceName == "" {
		errs["serviceName"] = "请输入 systemd service 名称"
	} else if !serviceNamePattern.MatchString(profile.ServiceName) {
		errs["serviceName"] = "service 名称必须是合法的 .service unit，不能包含路径或参数"
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// NginxTestCommand 返回强校验阶段使用的绝对命令和参数数组。
func NginxTestCommand(profile Profile) (string, []string, error) {
	if err := ValidateCandidate(profile); err != nil {
		return "", nil, err
	}

	args := make([]string, 0, 5)
	if profile.PrefixPath != "" {
		args = append(args, "-p", profile.PrefixPath)
	}
	args = append(args, "-T", "-c", profile.ConfigPath)
	return profile.BinaryPath, args, nil
}

func validateAbsolutePath(errs FieldErrors, field, value string, required bool) {
	if value == "" {
		if required {
			errs[field] = "请输入绝对路径"
		}
		return
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		errs[field] = "路径不能包含换行或空字符"
		return
	}
	if !filepath.IsAbs(value) {
		errs[field] = "必须填写绝对路径"
		return
	}
	if filepath.Clean(value) != value {
		errs[field] = fmt.Sprintf("请填写规范化路径：%s", filepath.Clean(value))
	}
}
