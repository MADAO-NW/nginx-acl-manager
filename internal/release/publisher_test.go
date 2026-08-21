package release

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"nginx-acl-manager/internal/model"
	"nginx-acl-manager/internal/nginxprofile"
)

type publishRunner struct {
	profile nginxprofile.Profile
}

func (r publishRunner) Run(_ context.Context, name string, args ...string) (nginxprofile.CommandOutput, error) {
	if strings.HasSuffix(name, "systemctl") && len(args) > 0 && args[0] == "show" {
		return nginxprofile.CommandOutput{Stdout: fmt.Sprintf("LoadState=loaded\nActiveState=active\nFragmentPath=/etc/systemd/system/nginx.service\nExecStart={ path=%s ; argv[]=%s -c %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\nMainPID=123\n", r.profile.BinaryPath, r.profile.BinaryPath, r.profile.ConfigPath)}, nil
	}
	if name == r.profile.BinaryPath {
		return nginxprofile.CommandOutput{Stdout: fmt.Sprintf("# configuration file %s:\n# configuration file %s:\n# configuration file %s:\nreal_ip_header CF-Connecting-IP;\nset_real_ip_from 173.245.48.0/20;\n", r.profile.ConfigPath, r.profile.HTTPIncludeFile, r.profile.RealIPSnippetPath)}, nil
	}
	return nginxprofile.CommandOutput{}, nil
}

func TestPublishSuccessAndStaleCandidate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := Store{
		AccessControlRoot: filepath.Join(dir, "acl"), CandidatePath: filepath.Join(dir, "staging", "candidate.json"),
		TransactionPath: filepath.Join(dir, "acl", ".transaction.json"), ResultPath: filepath.Join(dir, "result.json"),
	}
	oldRevision, err := store.EnsureInitialRelease()
	if err != nil {
		t.Fatalf("EnsureInitialRelease() error = %v", err)
	}
	project := model.Project{Slug: "demo", DisplayName: "Demo", Instances: []model.Instance{}}
	if err := store.SaveCandidate(model.Candidate{Action: "publish", ChangedProject: "demo", SourceRevision: oldRevision, Projects: []model.Project{project}}); err != nil {
		t.Fatalf("SaveCandidate() error = %v", err)
	}
	profile := nginxprofile.Profile{BinaryPath: "/usr/sbin/nginx", ConfigPath: "/etc/nginx/nginx.conf", ServiceName: "nginx.service", HTTPIncludeFile: "/etc/nginx/conf.d/50-nginx-acl-manager.conf", RealIPSnippetPath: "/etc/nginx/snippets/cloudflare-real-ip.conf"}
	profiles := nginxprofile.Store{ActivePath: filepath.Join(dir, "profile.json")}
	if err := profiles.SaveActive(profile); err != nil {
		t.Fatalf("SaveActive() error = %v", err)
	}
	runner := publishRunner{profile: profile}
	publisher := Publisher{
		Store: store, Profiles: profiles, Runner: runner, Systemctl: "/usr/bin/systemctl", LockPath: filepath.Join(dir, "publish.lock"),
		Validator: nginxprofile.RuntimeValidator{SystemctlPath: "/usr/bin/systemctl", Runner: runner, EvalSymlinks: func(path string) (string, error) { return path, nil }},
	}
	result, err := publisher.Publish(context.Background())
	if err != nil || !result.Success || result.Revision == oldRevision {
		t.Fatalf("Publish() = %#v, %v", result, err)
	}
	if current, _ := store.CurrentRevision(); current != result.Revision {
		t.Fatalf("current = %q", current)
	}
	if _, err := publisher.Publish(context.Background()); err == nil {
		t.Fatal("stale candidate publish error = nil")
	}
}

func TestPublishRollsBackCurrentAfterSwitchFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := Store{AccessControlRoot: filepath.Join(dir, "acl"), CandidatePath: filepath.Join(dir, "candidate.json"), TransactionPath: filepath.Join(dir, "transaction.json")}
	oldRevision, err := store.EnsureInitialRelease()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCandidate(model.Candidate{Action: "publish", ChangedProject: "demo", SourceRevision: oldRevision, Projects: []model.Project{{Slug: "demo", DisplayName: "Demo", Instances: []model.Instance{}}}}); err != nil {
		t.Fatal(err)
	}
	profile := nginxprofile.Profile{BinaryPath: "/usr/sbin/nginx", ConfigPath: "/etc/nginx/nginx.conf", ServiceName: "nginx.service", HTTPIncludeFile: "/etc/nginx/conf.d/manager.conf", RealIPSnippetPath: "/etc/nginx/snippets/real.conf"}
	profiles := nginxprofile.Store{ActivePath: filepath.Join(dir, "profile.json")}
	if err := profiles.SaveActive(profile); err != nil {
		t.Fatal(err)
	}
	publisher := Publisher{Store: store, Profiles: profiles, Runner: publishRunner{profile: profile}, Systemctl: "/usr/bin/systemctl", LockPath: filepath.Join(dir, "lock"), AfterSwitch: func() error { return errors.New("injected") }}
	if _, err := publisher.Publish(context.Background()); err == nil {
		t.Fatal("Publish() error = nil")
	}
	if current, _ := store.CurrentRevision(); current != oldRevision {
		t.Fatalf("rollback current = %q, want %q", current, oldRevision)
	}
}

func TestBuildReleaseKeepsWebReadablePermissionsWithRestrictiveUmask(t *testing.T) {
	oldUmask := syscall.Umask(0o027)
	defer syscall.Umask(oldUmask)

	dir := t.TempDir()
	store := Store{AccessControlRoot: filepath.Join(dir, "acl")}
	project := model.Project{
		Slug:        "demo",
		DisplayName: "Demo",
		Instances: []model.Instance{{
			Key:          "local",
			DisplayName:  "Local",
			Enabled:      true,
			LocalPort:    8317,
			DenyStatus:   403,
			AllowedCIDRs: []model.AllowlistEntry{},
			Rules:        []model.Rule{},
		}},
	}
	const revision = "revision-umask"
	if err := store.buildRelease(revision, "", model.Candidate{Action: "publish", ChangedProject: project.Slug, Projects: []model.Project{project}}); err != nil {
		t.Fatalf("buildRelease() error = %v", err)
	}

	releaseDirectory := filepath.Join(store.AccessControlRoot, "releases", revision)
	checks := []struct {
		path string
		mode os.FileMode
	}{
		{path: releaseDirectory, mode: 0o755},
		{path: filepath.Join(releaseDirectory, "projects", "demo", "instances", "local", "http"), mode: 0o755},
		{path: filepath.Join(releaseDirectory, "projects", "demo", "instances", "local", "http", "10-allowlist.conf"), mode: 0o644},
		{path: filepath.Join(releaseDirectory, "projects", "demo", "source.json"), mode: 0o644},
		{path: filepath.Join(releaseDirectory, "manifest.json"), mode: 0o644},
	}
	for _, check := range checks {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatalf("stat %s: %v", check.path, err)
		}
		if mode := info.Mode().Perm(); mode != check.mode {
			t.Errorf("mode %s = %04o, want %04o", check.path, mode, check.mode)
		}
	}
}

func TestPrepareRestoreCandidateKeepsOtherCurrentProjects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := Store{AccessControlRoot: filepath.Join(dir, "acl")}
	oldA := model.Project{Slug: "alpha", DisplayName: "Alpha old", Instances: []model.Instance{}}
	oldB := model.Project{Slug: "beta", DisplayName: "Beta old", Instances: []model.Instance{}}
	if err := store.buildRelease("revision-old", "", model.Candidate{Action: "publish", ChangedProject: "alpha", Projects: []model.Project{oldA, oldB}}); err != nil {
		t.Fatal(err)
	}
	newA := model.Project{Slug: "alpha", DisplayName: "Alpha new", Instances: []model.Instance{}}
	newB := model.Project{Slug: "beta", DisplayName: "Beta new", Instances: []model.Instance{}}
	if err := store.buildRelease("revision-current", "revision-old", model.Candidate{Action: "publish", ChangedProject: "beta", Projects: []model.Project{newA, newB}}); err != nil {
		t.Fatal(err)
	}
	if err := store.switchCurrent("revision-current"); err != nil {
		t.Fatal(err)
	}
	candidate, err := store.PrepareRestoreCandidate("alpha", "revision-old")
	if err != nil {
		t.Fatalf("PrepareRestoreCandidate() error = %v", err)
	}
	if candidate.Action != "restore" || candidate.SourceRevision != "revision-current" || len(candidate.Projects) != 2 {
		t.Fatalf("candidate = %#v", candidate)
	}
	if candidate.Projects[0].DisplayName != "Alpha old" || candidate.Projects[1].DisplayName != "Beta new" {
		t.Fatalf("restore projects = %#v", candidate.Projects)
	}
}
