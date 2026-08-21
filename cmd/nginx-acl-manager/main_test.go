package main

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/serverconfig"
)

func TestConfigInitCommand(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	var port int
	var err error
	for range 10 {
		var listener net.Listener
		listener, err = net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}
		port = listener.Addr().(*net.TCPAddr).Port
		if err = listener.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		err = run([]string{"config", "init", "--output", path, "--port", strconv.Itoa(port)})
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), "管理端口不可用") {
			t.Fatalf("run(config init) error = %v", err)
		}
	}
	if err != nil {
		t.Fatalf("run(config init) exhausted port retries: %v", err)
	}
	config, err := serverconfig.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenPort != port {
		t.Fatalf("ListenPort = %d", config.ListenPort)
	}
	if err := run([]string{"config", "init", "--output", path}); err == nil {
		t.Fatal("second config init error = nil")
	}
	if err := run([]string{"config", "set-port", "--output", path}); err == nil {
		t.Fatal("config set-port without --port error = nil")
	}
}

func TestConfigInitRejectsOccupiedPort(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	path := filepath.Join(t.TempDir(), "config.json")
	if err := run([]string{"config", "init", "--output", path, "--port", strconv.Itoa(port)}); err == nil {
		t.Fatal("run(config init occupied port) error = nil")
	}
}

func TestResolveServePaths(t *testing.T) {
	t.Parallel()

	production, err := resolveServePaths("")
	if err != nil {
		t.Fatalf("resolveServePaths(production) error = %v", err)
	}
	if production.configPath != defaultConfigPath || production.accessControlRoot != defaultAccessControlRoot {
		t.Fatalf("production paths = %#v", production)
	}

	localDirectory := filepath.Join(t.TempDir(), "local-dev")
	local, err := resolveServePaths(localDirectory)
	if err != nil {
		t.Fatalf("resolveServePaths(local) error = %v", err)
	}
	wants := map[string]string{
		"config":           filepath.Join(localDirectory, "config.json"),
		"credentials":      filepath.Join(localDirectory, "auth.json"),
		"candidateProfile": filepath.Join(localDirectory, "staging", "nginx-profile-candidate.json"),
		"activeProfile":    filepath.Join(localDirectory, "nginx-profile.json"),
		"drafts":           filepath.Join(localDirectory, "drafts", "projects"),
		"publishCandidate": filepath.Join(localDirectory, "staging", "candidate.json"),
		"accessControl":    filepath.Join(localDirectory, "access-control"),
		"transaction":      filepath.Join(localDirectory, "access-control", ".publish-transaction.json"),
		"publishResult":    filepath.Join(localDirectory, "results", "publish.json"),
		"profileResult":    filepath.Join(localDirectory, "results", "profile-apply.json"),
		"authCandidate":    filepath.Join(localDirectory, "staging", "auth-candidate.json"),
		"totpState":        filepath.Join(localDirectory, "auth", "totp-state.json"),
	}
	got := map[string]string{
		"config":           local.configPath,
		"credentials":      local.credentialsPath,
		"candidateProfile": local.candidateProfilePath,
		"activeProfile":    local.activeProfilePath,
		"drafts":           local.draftDirectory,
		"publishCandidate": local.publishCandidatePath,
		"accessControl":    local.accessControlRoot,
		"transaction":      local.transactionPath,
		"publishResult":    local.publishResultPath,
		"profileResult":    local.profileResultPath,
		"authCandidate":    local.authCandidatePath,
		"totpState":        local.totpStatePath,
	}
	for name, want := range wants {
		if got[name] != want {
			t.Errorf("%s path = %q; want %q", name, got[name], want)
		}
	}

	if _, err := resolveServePaths(".local-dev"); err == nil {
		t.Fatal("relative local directory error = nil")
	}
}

func TestProfileSeedCandidateCommand(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "candidate.json")
	err := run([]string{
		"profile", "seed-candidate",
		"--output", path,
		"--nginx-bin", "/usr/sbin/nginx",
		"--nginx-conf", "/etc/nginx/nginx.conf",
	})
	if err != nil {
		t.Fatalf("run(profile seed-candidate) error = %v", err)
	}
	profile, err := (nginxprofile.Store{CandidatePath: path}).LoadCandidate()
	if err != nil {
		t.Fatalf("LoadCandidate() error = %v", err)
	}
	if profile.ServiceName != nginxprofile.DefaultServiceName {
		t.Fatalf("ServiceName = %q", profile.ServiceName)
	}
}
