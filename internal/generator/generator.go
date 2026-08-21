package generator

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/validation"
)

const managedVersion = "1"

// FileSet 保存相对 release 根目录的确定性文件内容。
type FileSet map[string][]byte

// Generate 校验并生成完整项目集合对应的 Nginx 配置文件。
func Generate(projects []model.Project) (FileSet, error) {
	if err := validation.ValidateProjects(projects); err != nil {
		return nil, err
	}
	files := make(FileSet)
	orderedProjects := slices.Clone(projects)
	slices.SortFunc(orderedProjects, func(a, b model.Project) int { return strings.Compare(a.Slug, b.Slug) })
	for _, project := range orderedProjects {
		instances := slices.Clone(project.Instances)
		slices.SortFunc(instances, func(a, b model.Instance) int { return strings.Compare(a.Key, b.Key) })
		for _, instance := range instances {
			base := fmt.Sprintf("projects/%s/instances/%s", project.Slug, instance.Key)
			allowlist, routes, enforce := generateInstance(project.Slug, instance)
			files[base+"/http/10-allowlist.conf"] = []byte(allowlist)
			files[base+"/http/20-routes.conf"] = []byte(routes)
			files[base+"/location/10-enforce.conf"] = []byte(enforce)
		}
	}
	return files, nil
}

// HTTPIncludeContent 返回由 Profile apply 管理的固定 http 全局入口内容。
func HTTPIncludeContent(accessControlRoot string) []byte {
	return []byte(fmt.Sprintf(
		"# managed-by: nginx-acl-manager; scope=http; version=%s\ninclude %s/current/projects/*/instances/*/http/*.conf;\n",
		managedVersion,
		strings.TrimSuffix(accessControlRoot, "/"),
	))
}

// LocationIncludePath 返回运维需要放入业务 location 的稳定绝对路径。
func LocationIncludePath(accessControlRoot, projectSlug, instanceKey string) string {
	return fmt.Sprintf("%s/current/projects/%s/instances/%s/location/*.conf", strings.TrimSuffix(accessControlRoot, "/"), projectSlug, instanceKey)
}

func generateInstance(projectSlug string, instance model.Instance) (string, string, string) {
	variablePrefix := "acl_" + strings.ReplaceAll(projectSlug, "-", "_") + "_" + strings.ReplaceAll(instance.Key, "-", "_")
	header := fmt.Sprintf("# managed-by: nginx-acl-manager; project=%s; instance=%s; version=%s\n", projectSlug, instance.Key, managedVersion)

	enabledRules := make([]model.Rule, 0, len(instance.Rules))
	if instance.Enabled {
		for _, rule := range instance.Rules {
			if rule.Enabled {
				enabledRules = append(enabledRules, rule)
			}
		}
	}
	if len(enabledRules) == 0 {
		comment := header + "# 当前实例未启用任何访问控制规则。\n"
		return comment, comment, comment
	}

	allowed := slices.Clone(instance.AllowedCIDRs)
	slices.SortFunc(allowed, func(a, b model.AllowlistEntry) int {
		if comparison := strings.Compare(a.CIDR, b.CIDR); comparison != 0 {
			return comparison
		}
		return strings.Compare(a.ID, b.ID)
	})
	var allowlist strings.Builder
	allowlist.WriteString(header)
	fmt.Fprintf(&allowlist, "geo $%s_ip_allowed {\n    default  0;\n", variablePrefix)
	for _, entry := range allowed {
		fmt.Fprintf(&allowlist, "    %-18s  1;\n", entry.CIDR)
	}
	allowlist.WriteString("}\n")

	type routeMatch struct {
		method string
		regex  string
	}
	matches := make([]routeMatch, 0)
	for _, rule := range enabledRules {
		pathPattern := regexp.QuoteMeta(rule.Path.Value)
		if rule.Path.Type == validation.PathNumericSegment {
			pathPattern = strings.Replace(pathPattern, regexp.QuoteMeta("{id}"), "[0-9]+", 1)
		}
		if rule.Path.OptionalTrailingSlash && rule.Path.Value != "/" {
			pathPattern += "/?"
		}
		for _, method := range validation.SortMethods(rule.Methods) {
			matches = append(matches, routeMatch{method: method, regex: "~^" + method + ":" + pathPattern + "$"})
		}
	}
	slices.SortFunc(matches, func(a, b routeMatch) int {
		if comparison := strings.Compare(a.regex, b.regex); comparison != 0 {
			return comparison
		}
		return strings.Compare(a.method, b.method)
	})

	var routes strings.Builder
	routes.WriteString(header)
	fmt.Fprintf(&routes, "map \"$request_method:$uri\" $%s_route_protected {\n    default  0;\n", variablePrefix)
	for _, match := range matches {
		fmt.Fprintf(&routes, "    \"%s\"  1;\n", match.regex)
	}
	routes.WriteString("}\n\n")
	fmt.Fprintf(&routes, "map \"$%s_route_protected:$%s_ip_allowed\" $%s_blocked {\n    default  0;\n    \"1:0\"    1;\n}\n", variablePrefix, variablePrefix, variablePrefix)

	enforce := header + fmt.Sprintf("if ($%s_blocked) {\n    return %d;\n}\n", variablePrefix, instance.DenyStatus)
	return allowlist.String(), routes.String(), enforce
}
