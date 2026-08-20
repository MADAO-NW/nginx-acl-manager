package nginxprofile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type runnerStep struct {
	name   string
	args   []string
	output CommandOutput
	err    error
}

type scriptedRunner struct {
	t     *testing.T
	steps []runnerStep
	next  int
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) (CommandOutput, error) {
	r.t.Helper()
	if r.next >= len(r.steps) {
		r.t.Fatalf("unexpected command: %s %#v", name, args)
	}
	step := r.steps[r.next]
	r.next++
	if name != step.name || !reflect.DeepEqual(args, step.args) {
		r.t.Fatalf("command = %s %#v, want %s %#v", name, args, step.name, step.args)
	}
	return step.output, step.err
}

func (r *scriptedRunner) assertDone() {
	r.t.Helper()
	if r.next != len(r.steps) {
		r.t.Fatalf("executed %d commands, want %d", r.next, len(r.steps))
	}
}

func TestRuntimeValidatorDefaultSystemdProfile(t *testing.T) {
	t.Parallel()

	profile := runtimeProfile(t)
	systemctlOutput := defaultSystemctlOutput(profile, profile.BinaryPath)
	expanded := expandedConfig(profile, true)
	runner := &scriptedRunner{t: t, steps: []runnerStep{
		{
			name:   "/usr/bin/systemctl",
			args:   systemctlArgs(profile.ServiceName),
			output: CommandOutput{Stdout: systemctlOutput},
		},
		{
			name:   profile.BinaryPath,
			args:   []string{"-V"},
			output: CommandOutput{Stderr: "nginx version: nginx/1.26.0\nconfigure arguments: --conf-path=" + profile.ConfigPath},
		},
		{
			name:   profile.BinaryPath,
			args:   []string{"-T", "-c", profile.ConfigPath},
			output: CommandOutput{Stdout: expanded},
		},
	}}

	report, err := (RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner}).Validate(context.Background(), profile)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if report.BinaryPath != profile.BinaryPath || report.ConfigPath != profile.ConfigPath || report.MainPID != 321 {
		t.Fatalf("report = %#v", report)
	}
	runner.assertDone()
}

func TestRuntimeValidatorCustomPrefixAndConfig(t *testing.T) {
	t.Parallel()

	profile := runtimeProfile(t)
	profile.PrefixPath = filepath.Join(filepath.Dir(profile.BinaryPath), "prefix")
	if err := os.Mkdir(profile.PrefixPath, 0o755); err != nil {
		t.Fatalf("Mkdir(prefix) error = %v", err)
	}
	systemctlOutput := strings.Join([]string{
		"LoadState=loaded",
		"ActiveState=active",
		"FragmentPath=/etc/systemd/system/custom-nginx.service",
		"ExecStart={ path=" + profile.BinaryPath + " ; argv[]=" + profile.BinaryPath + " -p " + profile.PrefixPath + " -c " + profile.ConfigPath + " ; ignore_errors=no ; }",
		"MainPID=321",
	}, "\n")
	runner := &scriptedRunner{t: t, steps: []runnerStep{
		{
			name:   "/usr/bin/systemctl",
			args:   systemctlArgs(profile.ServiceName),
			output: CommandOutput{Stdout: systemctlOutput},
		},
		{
			name:   profile.BinaryPath,
			args:   []string{"-p", profile.PrefixPath, "-T", "-c", profile.ConfigPath},
			output: CommandOutput{Stdout: expandedConfig(profile, true)},
		},
	}}

	report, err := (RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner}).Validate(context.Background(), profile)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if report.PrefixPath != profile.PrefixPath {
		t.Fatalf("PrefixPath = %q", report.PrefixPath)
	}
	runner.assertDone()
}

func TestRuntimeValidatorRejectsDifferentSystemdBinary(t *testing.T) {
	t.Parallel()

	profile := runtimeProfile(t)
	otherBinary := filepath.Join(filepath.Dir(profile.BinaryPath), "other-nginx")
	if err := os.WriteFile(otherBinary, []byte("binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(other binary) error = %v", err)
	}
	runner := &scriptedRunner{t: t, steps: []runnerStep{
		{
			name:   "/usr/bin/systemctl",
			args:   systemctlArgs(profile.ServiceName),
			output: CommandOutput{Stdout: defaultSystemctlOutput(profile, otherBinary)},
		},
	}}

	_, err := (RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner}).Validate(context.Background(), profile)
	if err == nil || !strings.Contains(err.Error(), "ExecStart 不一致") {
		t.Fatalf("Validate() error = %v", err)
	}
	runner.assertDone()
}

func TestRuntimeValidatorRejectsMissingRealIPDirective(t *testing.T) {
	t.Parallel()

	profile := runtimeProfile(t)
	runner := &scriptedRunner{t: t, steps: []runnerStep{
		{
			name:   "/usr/bin/systemctl",
			args:   systemctlArgs(profile.ServiceName),
			output: CommandOutput{Stdout: defaultSystemctlOutput(profile, profile.BinaryPath)},
		},
		{
			name:   profile.BinaryPath,
			args:   []string{"-V"},
			output: CommandOutput{Stderr: "configure arguments: --conf-path=" + profile.ConfigPath},
		},
		{
			name:   profile.BinaryPath,
			args:   []string{"-T", "-c", profile.ConfigPath},
			output: CommandOutput{Stdout: expandedConfig(profile, false)},
		},
	}}

	_, err := (RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner}).Validate(context.Background(), profile)
	if err == nil || !strings.Contains(err.Error(), "real IP 必要指令") {
		t.Fatalf("Validate() error = %v", err)
	}
	runner.assertDone()
}

func TestRuntimeValidatorPropagatesControlledCommandFailure(t *testing.T) {
	t.Parallel()

	profile := runtimeProfile(t)
	runner := &scriptedRunner{t: t, steps: []runnerStep{
		{
			name: "/usr/bin/systemctl",
			args: systemctlArgs(profile.ServiceName),
			err:  errors.New("exit status 1"),
		},
	}}
	_, err := (RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner}).Validate(context.Background(), profile)
	if err == nil || !strings.Contains(err.Error(), "systemd 状态") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func runtimeProfile(t *testing.T) Profile {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(temp dir) error = %v", err)
	}
	profile := Profile{
		BinaryPath:        filepath.Join(dir, "nginx"),
		ConfigPath:        filepath.Join(dir, "nginx.conf"),
		ServiceName:       "nginx.service",
		HTTPIncludeFile:   filepath.Join(dir, "50-nginx-acl-manager.conf"),
		RealIPSnippetPath: filepath.Join(dir, "cloudflare-real-ip.conf"),
	}
	for _, path := range []string{profile.BinaryPath, profile.ConfigPath, profile.HTTPIncludeFile, profile.RealIPSnippetPath} {
		if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}
	return profile
}

func systemctlArgs(serviceName string) []string {
	return []string{
		"show",
		serviceName,
		"--property=LoadState",
		"--property=ActiveState",
		"--property=FragmentPath",
		"--property=ExecStart",
		"--property=MainPID",
		"--no-pager",
	}
}

func defaultSystemctlOutput(profile Profile, binaryPath string) string {
	return strings.Join([]string{
		"LoadState=loaded",
		"ActiveState=active",
		"FragmentPath=/lib/systemd/system/nginx.service",
		"ExecStart={ path=" + binaryPath + " ; argv[]=" + binaryPath + " -g daemon on; master_process on; ; ignore_errors=no ; }",
		"MainPID=321",
	}, "\n")
}

func expandedConfig(profile Profile, includeRealIPDirectives bool) string {
	lines := []string{
		"# configuration file " + profile.ConfigPath + ":",
		"http {",
		"# configuration file " + profile.HTTPIncludeFile + ":",
		"include /etc/nginx/access-control/current/projects/*/instances/*/http/*.conf;",
		"# configuration file " + profile.RealIPSnippetPath + ":",
	}
	if includeRealIPDirectives {
		lines = append(lines,
			"set_real_ip_from 203.0.113.0/24;",
			"real_ip_header CF-Connecting-IP;",
		)
	}
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}
