package validation

import (
	"testing"

	"nginx-acl-manager/internal/model"
)

func TestNormalizeCIDR(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"203.0.113.10":   "203.0.113.10/32",
		"203.0.113.7/24": "203.0.113.0/24",
		"2001:db8::1":    "2001:db8::1/128",
		"0.0.0.0":        "0.0.0.0/0",
	}
	for input, want := range tests {
		got, err := NormalizeCIDR(input)
		if err != nil || got != want {
			t.Errorf("NormalizeCIDR(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := NormalizeCIDR("203.0.113.1 trailing"); err == nil {
		t.Fatal("invalid CIDR error = nil")
	}
}

func TestValidateRuleRejectsUnsafeOrIncompleteTemplate(t *testing.T) {
	t.Parallel()
	rule := model.Rule{ID: "r1", Name: "账户", Methods: []string{"GET"}, Path: model.RulePath{Type: PathNumericSegment, Value: "/accounts/{id}"}}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("valid rule error = %v", err)
	}
	rule.Path.Value = "/accounts/{id}/x/{id}"
	if err := ValidateRule(rule); err == nil {
		t.Fatal("multiple {id} error = nil")
	}
	rule.Path = model.RulePath{Type: PathExact, Value: "/admin; return 200"}
	if err := ValidateRule(rule); err == nil {
		t.Fatal("unsafe exact path error = nil")
	}
}
