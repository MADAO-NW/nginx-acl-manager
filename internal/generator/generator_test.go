package generator

import (
	"bytes"
	"testing"

	"nginx-acl-manager/internal/model"
)

func TestGenerateDeterministicAndIsolated(t *testing.T) {
	t.Parallel()
	project := model.Project{Slug: "sub-2-api", DisplayName: "Sub2API", Instances: []model.Instance{{
		Key: "main-one", DisplayName: "主实例", Enabled: true, LocalPort: 7777, DenyStatus: 404,
		AllowedCIDRs: []model.AllowlistEntry{{ID: "b", CIDR: "2001:db8::/32"}, {ID: "a", CIDR: "203.0.113.10/32"}},
		Rules:        []model.Rule{{ID: "r1", Name: "账户", Enabled: true, Methods: []string{"HEAD", "GET"}, Path: model.RulePath{Type: "numeric_segment", Value: "/api/accounts/{id}", OptionalTrailingSlash: true}}},
	}}}
	first, err := Generate([]model.Project{project})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	second, err := Generate([]model.Project{project})
	if err != nil {
		t.Fatalf("Generate() second error = %v", err)
	}
	path := "projects/sub-2-api/instances/main-one/http/20-routes.conf"
	if !bytes.Equal(first[path], second[path]) {
		t.Fatal("相同输入生成结果不一致")
	}
	want := []byte(`$acl_sub_2_api_main_one_blocked`)
	if !bytes.Contains(first[path], want) || !bytes.Contains(first[path], []byte(`[0-9]+/?$`)) {
		t.Fatalf("routes = %s", first[path])
	}
}

func TestGenerateDisabledInstanceProducesComments(t *testing.T) {
	t.Parallel()
	files, err := Generate([]model.Project{{Slug: "demo", DisplayName: "Demo", Instances: []model.Instance{{
		Key: "main", DisplayName: "主实例", Enabled: false, LocalPort: 8080, DenyStatus: 403,
		Rules: []model.Rule{{ID: "r1", Name: "规则", Enabled: true, Methods: []string{"GET"}, Path: model.RulePath{Type: "exact", Value: "/admin"}}},
	}}}})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for path, content := range files {
		if bytes.Contains(content, []byte("map ")) || bytes.Contains(content, []byte("geo ")) || bytes.Contains(content, []byte("return ")) {
			t.Fatalf("disabled file %s has effect: %s", path, content)
		}
	}
}
