package nginxprofile

import (
	"reflect"
	"testing"
)

func TestValidateCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		profile   Profile
		wantField string
	}{
		{
			name:      "缺少必填路径",
			profile:   Profile{},
			wantField: "binaryPath",
		},
		{
			name: "拒绝相对路径",
			profile: func() Profile {
				profile := validProfile()
				profile.ConfigPath = "conf/nginx.conf"
				return profile
			}(),
			wantField: "configPath",
		},
		{
			name: "拒绝未规范化路径",
			profile: func() Profile {
				profile := validProfile()
				profile.HTTPIncludeFile = "/etc/nginx/conf.d/../conf.d/manager.conf"
				return profile
			}(),
			wantField: "httpIncludeFile",
		},
		{
			name: "拒绝 service 参数注入",
			profile: func() Profile {
				profile := validProfile()
				profile.ServiceName = "nginx.service --now"
				return profile
			}(),
			wantField: "serviceName",
		},
		{
			name: "拒绝路径换行",
			profile: func() Profile {
				profile := validProfile()
				profile.BinaryPath = "/usr/sbin/nginx\n--help"
				return profile
			}(),
			wantField: "binaryPath",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateCandidate(tt.profile)
			fieldErrors, ok := err.(FieldErrors)
			if !ok {
				t.Fatalf("ValidateCandidate() error = %T %v, want FieldErrors", err, err)
			}
			if _, exists := fieldErrors[tt.wantField]; !exists {
				t.Fatalf("ValidateCandidate() fields = %v, want %q", fieldErrors, tt.wantField)
			}
		})
	}

	if err := ValidateCandidate(validProfile()); err != nil {
		t.Fatalf("ValidateCandidate(valid) error = %v", err)
	}
}

func TestNginxTestCommand(t *testing.T) {
	t.Parallel()

	profile := validProfile()
	command, args, err := NginxTestCommand(profile)
	if err != nil {
		t.Fatalf("NginxTestCommand() error = %v", err)
	}
	if command != "/usr/sbin/nginx" {
		t.Fatalf("command = %q", command)
	}
	if want := []string{"-T", "-c", "/etc/nginx/nginx.conf"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}

	profile.PrefixPath = "/opt/nginx"
	_, args, err = NginxTestCommand(profile)
	if err != nil {
		t.Fatalf("NginxTestCommand(prefix) error = %v", err)
	}
	if want := []string{"-p", "/opt/nginx", "-T", "-c", "/etc/nginx/nginx.conf"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestDefaultCandidateDoesNotInventConfigPath(t *testing.T) {
	t.Parallel()

	profile := DefaultCandidate("/usr/sbin/nginx")
	if profile.ConfigPath != "" {
		t.Fatalf("ConfigPath = %q, want empty", profile.ConfigPath)
	}
	if profile.ServiceName != DefaultServiceName {
		t.Fatalf("ServiceName = %q", profile.ServiceName)
	}
}

func validProfile() Profile {
	return Profile{
		BinaryPath:        "/usr/sbin/nginx",
		ConfigPath:        "/etc/nginx/nginx.conf",
		ServiceName:       "nginx.service",
		HTTPIncludeFile:   "/etc/nginx/conf.d/50-nginx-acl-manager.conf",
		RealIPSnippetPath: "/etc/nginx/snippets/cloudflare-real-ip.conf",
	}
}
