package main

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"nginx-acl-manager/internal/nginxprofile"
	"nginx-acl-manager/internal/serverconfig"
)

func TestConfigInitCommand(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := run([]string{"config", "init", "--output", path, "--port", strconv.Itoa(port)}); err != nil {
		t.Fatalf("run(config init) error = %v", err)
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
