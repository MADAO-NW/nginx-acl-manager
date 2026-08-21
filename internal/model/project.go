package model

// Project 是一个可独立发布和恢复的访问控制项目。
type Project struct {
	Slug        string     `json:"slug"`
	DisplayName string     `json:"displayName"`
	Instances   []Instance `json:"instances"`
}

// Instance 描述一个本机业务服务及其共享白名单和接口规则。
type Instance struct {
	Key          string           `json:"key"`
	DisplayName  string           `json:"displayName"`
	Enabled      bool             `json:"enabled"`
	LocalPort    int              `json:"localPort"`
	ServerName   string           `json:"serverName,omitempty"`
	DenyStatus   int              `json:"denyStatus"`
	AllowedCIDRs []AllowlistEntry `json:"allowedCidrs"`
	Rules        []Rule           `json:"rules"`
}

// AllowlistEntry 是实例内具有稳定标识的规范化 IP/CIDR。
type AllowlistEntry struct {
	ID    string `json:"id"`
	CIDR  string `json:"cidr"`
	Label string `json:"label"`
}

// Rule 描述精确 HTTP 方法和受控路径模板。
type Rule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	Methods []string `json:"methods"`
	Path    RulePath `json:"path"`
}

// RulePath 只允许 exact 或 numeric_segment 两类受控匹配。
type RulePath struct {
	Type                  string `json:"type"`
	Value                 string `json:"value"`
	OptionalTrailingSlash bool   `json:"optionalTrailingSlash"`
}

// Candidate 是 Web 交给 root 发布器重新校验的完整项目快照。
type Candidate struct {
	Action         string    `json:"action"`
	ChangedProject string    `json:"changedProject"`
	SourceRevision string    `json:"sourceRevision,omitempty"`
	Projects       []Project `json:"projects"`
}
