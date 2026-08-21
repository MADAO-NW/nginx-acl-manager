package nginxprofile_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/release"
)

type applyRunner struct {
	profile nginxprofile.Profile
}

func (r applyRunner) Run(_ context.Context, name string, args ...string) (nginxprofile.CommandOutput, error) {
	if strings.HasSuffix(name, "systemctl") && len(args) > 0 && args[0] == "show" {
		return nginxprofile.CommandOutput{Stdout: fmt.Sprintf("LoadState=loaded\nActiveState=active\nFragmentPath=/etc/systemd/system/nginx.service\nExecStart={ path=%s ; argv[]=%s -c %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\nMainPID=99\n", r.profile.BinaryPath, r.profile.BinaryPath, r.profile.ConfigPath)}, nil
	}
	if name == r.profile.BinaryPath {
		return nginxprofile.CommandOutput{Stdout: fmt.Sprintf("# configuration file %s:\n# configuration file %s:\n# configuration file %s:\nreal_ip_header CF-Connecting-IP;\nset_real_ip_from 173.245.48.0/20;\n", r.profile.ConfigPath, r.profile.HTTPIncludeFile, r.profile.RealIPSnippetPath)}, nil
	}
	return nginxprofile.CommandOutput{}, nil
}

func TestApplyCandidateCreatesManagedIncludeAndActiveProfile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "nginx")
	config := filepath.Join(dir, "nginx.conf")
	realIP := filepath.Join(dir, "real-ip.conf")
	include := filepath.Join(dir, "conf.d", "manager.conf")
	for path, mode := range map[string]os.FileMode{binary: 0o755, config: 0o644, realIP: 0o644} {
		if err := os.WriteFile(path, []byte("test\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	profile := nginxprofile.Profile{BinaryPath: binary, ConfigPath: config, ServiceName: "nginx.service", HTTPIncludeFile: include, RealIPSnippetPath: realIP}
	profiles := nginxprofile.Store{CandidatePath: filepath.Join(dir, "candidate.json"), ActivePath: filepath.Join(dir, "active.json")}
	if err := profiles.SaveCandidate(profile); err != nil {
		t.Fatal(err)
	}
	releases := release.Store{AccessControlRoot: filepath.Join(dir, "access-control")}
	runner := applyRunner{profile: profile}
	err := nginxprofile.ApplyCandidate(context.Background(), nginxprofile.ApplyOptions{
		Profiles: profiles, Releases: releases, AccessControlRoot: releases.AccessControlRoot,
		Validator: nginxprofile.RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner}, Runner: runner,
		SystemctlPath: "/usr/bin/systemctl", ApplicationUID: -1, ApplicationGID: -1,
		ResultPath: filepath.Join(dir, "result.json"), RecoverUnitPath: filepath.Join(dir, "systemd", "recover.service"), SystemdRoot: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/nginx-acl-manager",
	})
	if err != nil {
		t.Fatalf("ApplyCandidate() error = %v", err)
	}
	if _, err := profiles.LoadActive(); err != nil {
		t.Fatalf("LoadActive() error = %v", err)
	}
	content, err := os.ReadFile(include)
	if err != nil || !strings.Contains(string(content), "managed-by: nginx-acl-manager") || strings.Contains(string(content), "profile_probe") {
		t.Fatalf("managed include = %q, %v", content, err)
	}
}

func TestApplyCandidateRefusesUnmanagedInclude(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "nginx")
	config := filepath.Join(dir, "nginx.conf")
	realIP := filepath.Join(dir, "real.conf")
	include := filepath.Join(dir, "existing.conf")
	for path, mode := range map[string]os.FileMode{binary: 0o755, config: 0o644, realIP: 0o644, include: 0o644} {
		if err := os.WriteFile(path, []byte("user-owned\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	profile := nginxprofile.Profile{BinaryPath: binary, ConfigPath: config, ServiceName: "nginx.service", HTTPIncludeFile: include, RealIPSnippetPath: realIP}
	profiles := nginxprofile.Store{CandidatePath: filepath.Join(dir, "candidate.json"), ActivePath: filepath.Join(dir, "active.json")}
	if err := profiles.SaveCandidate(profile); err != nil {
		t.Fatal(err)
	}
	err := nginxprofile.ApplyCandidate(context.Background(), nginxprofile.ApplyOptions{Profiles: profiles, Releases: release.Store{AccessControlRoot: filepath.Join(dir, "acl")}, AccessControlRoot: filepath.Join(dir, "acl"), Runner: applyRunner{profile: profile}, ApplicationUID: -1, ApplicationGID: -1})
	if err == nil {
		t.Fatal("ApplyCandidate() error = nil")
	}
	content, readErr := os.ReadFile(include)
	if readErr != nil || string(content) != "user-owned\n" {
		t.Fatalf("unmanaged include changed: %q, %v", content, readErr)
	}
}
