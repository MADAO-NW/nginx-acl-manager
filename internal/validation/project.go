package validation

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"nginx-acl-manager/internal/model"
)

const (
	PathExact          = "exact"
	PathNumericSegment = "numeric_segment"
)

// stableKeyPattern 约束会进入目录名和 Nginx 变量名的稳定标识。
var stableKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// hostLabelPattern 校验普通 DNS 标签，不接受通配符或下划线。
var hostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// allowedMethods 是第一版明确支持的 HTTP 方法集合。
var allowedMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {}, "OPTIONS": {},
}

// ValidateProject 对完整项目执行 Web 与 root 共用的纯业务校验。
func ValidateProject(project model.Project) error {
	if !stableKeyPattern.MatchString(project.Slug) {
		return errors.New("项目标识必须以小写字母开头，且只能包含小写字母、数字和连字符")
	}
	if strings.TrimSpace(project.DisplayName) == "" {
		return errors.New("项目名称不能为空")
	}
	instanceKeys := make(map[string]struct{}, len(project.Instances))
	for index := range project.Instances {
		instance := &project.Instances[index]
		if !stableKeyPattern.MatchString(instance.Key) {
			return fmt.Errorf("实例 %d 的标识格式无效", index+1)
		}
		if _, exists := instanceKeys[instance.Key]; exists {
			return fmt.Errorf("实例标识 %q 重复", instance.Key)
		}
		instanceKeys[instance.Key] = struct{}{}
		if err := ValidateInstance(*instance); err != nil {
			return fmt.Errorf("实例 %q: %w", instance.Key, err)
		}
	}
	return nil
}

// ValidateProjects 校验完整候选集及项目标识唯一性。
func ValidateProjects(projects []model.Project) error {
	seen := make(map[string]struct{}, len(projects))
	for index := range projects {
		if err := ValidateProject(projects[index]); err != nil {
			return err
		}
		if _, exists := seen[projects[index].Slug]; exists {
			return fmt.Errorf("项目标识 %q 重复", projects[index].Slug)
		}
		seen[projects[index].Slug] = struct{}{}
	}
	return nil
}

// ValidateInstance 校验实例字段、CIDR 和规则的唯一性。
func ValidateInstance(instance model.Instance) error {
	if strings.TrimSpace(instance.DisplayName) == "" {
		return errors.New("实例名称不能为空")
	}
	if instance.LocalPort < 1 || instance.LocalPort > 65535 {
		return errors.New("本地端口必须在 1 到 65535 之间")
	}
	if instance.ServerName != "" && !validServerName(instance.ServerName) {
		return errors.New("入口域名只能填写不带协议、端口和路径的主机名")
	}
	if instance.DenyStatus != 403 && instance.DenyStatus != 404 {
		return errors.New("拒绝状态只允许 403 或 404")
	}

	entryIDs := make(map[string]struct{}, len(instance.AllowedCIDRs))
	cidrs := make(map[string]struct{}, len(instance.AllowedCIDRs))
	for _, entry := range instance.AllowedCIDRs {
		if entry.ID == "" {
			return errors.New("白名单条目标识不能为空")
		}
		if _, exists := entryIDs[entry.ID]; exists {
			return errors.New("白名单条目标识重复")
		}
		entryIDs[entry.ID] = struct{}{}
		normalized, err := NormalizeCIDR(entry.CIDR)
		if err != nil || normalized != entry.CIDR {
			return fmt.Errorf("白名单 %q 必须保存为规范 CIDR", entry.ID)
		}
		if _, exists := cidrs[entry.CIDR]; exists {
			return fmt.Errorf("白名单 CIDR %q 重复", entry.CIDR)
		}
		cidrs[entry.CIDR] = struct{}{}
	}

	ruleIDs := make(map[string]struct{}, len(instance.Rules))
	matchKeys := make(map[string]struct{})
	for _, rule := range instance.Rules {
		if rule.ID == "" {
			return errors.New("规则标识不能为空")
		}
		if _, exists := ruleIDs[rule.ID]; exists {
			return errors.New("规则标识重复")
		}
		ruleIDs[rule.ID] = struct{}{}
		if err := ValidateRule(rule); err != nil {
			return fmt.Errorf("规则 %q: %w", rule.ID, err)
		}
		for _, method := range rule.Methods {
			key := method + "\x00" + rule.Path.Type + "\x00" + rule.Path.Value + fmt.Sprintf("\x00%t", rule.Path.OptionalTrailingSlash)
			if _, exists := matchKeys[key]; exists {
				return fmt.Errorf("规则 %q 与同实例其他规则重复", rule.ID)
			}
			matchKeys[key] = struct{}{}
		}
	}
	return nil
}

// ValidateRule 校验规则方法和受控路径模板。
func ValidateRule(rule model.Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("规则名称不能为空")
	}
	if len(rule.Methods) == 0 {
		return errors.New("至少选择一个 HTTP 方法")
	}
	seen := make(map[string]struct{}, len(rule.Methods))
	for _, method := range rule.Methods {
		if _, ok := allowedMethods[method]; !ok {
			return fmt.Errorf("不支持 HTTP 方法 %q", method)
		}
		if _, exists := seen[method]; exists {
			return fmt.Errorf("HTTP 方法 %q 重复", method)
		}
		seen[method] = struct{}{}
	}
	if rule.Path.Type != PathExact && rule.Path.Type != PathNumericSegment {
		return errors.New("路径类型只允许 exact 或 numeric_segment")
	}
	if err := validatePath(rule.Path); err != nil {
		return err
	}
	return nil
}

// NormalizeCIDR 将单 IP 和 CIDR 统一转换为掩码后的规范形式。
func NormalizeCIDR(value string) (string, error) {
	if value == "0.0.0.0" {
		return "0.0.0.0/0", nil
	}
	if strings.ContainsAny(value, " \t\r\n") || value == "" {
		return "", errors.New("IP/CIDR 格式无效")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", errors.New("IP/CIDR 格式无效")
		}
		return prefix.Masked().String(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", errors.New("IP/CIDR 格式无效")
	}
	return netip.PrefixFrom(address, address.BitLen()).String(), nil
}

// SortMethods 返回按固定业务顺序排列的方法副本。
func SortMethods(methods []string) []string {
	order := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	result := slices.Clone(methods)
	slices.SortFunc(result, func(a, b string) int {
		return slices.Index(order, a) - slices.Index(order, b)
	})
	return result
}

func validServerName(value string) bool {
	if strings.ContainsAny(value, ":/?#\x00\r\n") || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	value = strings.TrimSuffix(value, ".")
	for _, label := range strings.Split(value, ".") {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validatePath(path model.RulePath) error {
	if !utf8.ValidString(path.Value) || path.Value == "" || !strings.HasPrefix(path.Value, "/") {
		return errors.New("路径必须是以 / 开头的有效文本")
	}
	if strings.ContainsAny(path.Value, "?#;\x00\r\n") {
		return errors.New("路径不能包含查询串、fragment、分号或控制字符")
	}
	for _, character := range path.Value {
		if character < 0x20 || character == 0x7f {
			return errors.New("路径不能包含控制字符")
		}
	}
	if path.Value != "/" && strings.HasSuffix(path.Value, "/") {
		return errors.New("路径值不能以 / 结尾，请使用尾部斜杠选项")
	}
	if path.Type == PathExact {
		if strings.Contains(path.Value, "{id}") {
			return errors.New("exact 路径不能包含 {id}")
		}
		return nil
	}
	if strings.Count(path.Value, "{id}") != 1 {
		return errors.New("numeric_segment 路径必须且只能包含一个 {id}")
	}
	segments := strings.Split(path.Value, "/")
	if !slices.Contains(segments, "{id}") {
		return errors.New("{id} 必须是完整路径段")
	}
	return nil
}
