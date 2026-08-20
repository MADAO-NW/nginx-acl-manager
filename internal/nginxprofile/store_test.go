package nginxprofile

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStoreSaveAndLoadCandidate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := Store{
		CandidatePath: filepath.Join(dir, "staging", "nginx-profile-candidate.json"),
		ActivePath:    filepath.Join(dir, "nginx-profile.json"),
	}
	profile := validProfile()
	if err := store.SaveCandidate(profile); err != nil {
		t.Fatalf("SaveCandidate() error = %v", err)
	}

	loaded, err := store.LoadCandidate()
	if err != nil {
		t.Fatalf("LoadCandidate() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, profile) {
		t.Fatalf("LoadCandidate() = %#v, want %#v", loaded, profile)
	}

	info, err := os.Stat(store.CandidatePath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("candidate mode = %o, want 600", got)
	}
}

func TestStoreInvalidCandidateKeepsPreviousValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := Store{CandidatePath: filepath.Join(dir, "candidate.json")}
	original := validProfile()
	if err := store.SaveCandidate(original); err != nil {
		t.Fatalf("SaveCandidate(original) error = %v", err)
	}

	invalid := original
	invalid.ServiceName = "nginx.service;reboot"
	if err := store.SaveCandidate(invalid); err == nil {
		t.Fatal("SaveCandidate(invalid) error = nil")
	}
	loaded, err := store.LoadCandidate()
	if err != nil {
		t.Fatalf("LoadCandidate() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, original) {
		t.Fatalf("candidate changed to %#v", loaded)
	}
}

func TestStoreStrictJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	data := []byte(`{
  "binaryPath": "/usr/sbin/nginx",
  "configPath": "/etc/nginx/nginx.conf",
  "serviceName": "nginx.service",
  "httpIncludeFile": "/etc/nginx/conf.d/50-nginx-acl-manager.conf",
  "realIpSnippetPath": "/etc/nginx/snippets/cloudflare-real-ip.conf",
  "command": "reboot"
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	store := Store{CandidatePath: path}
	if _, err := store.LoadCandidate(); err == nil {
		t.Fatal("LoadCandidate() error = nil, want unknown field error")
	}
}

func TestStoreNotFound(t *testing.T) {
	t.Parallel()

	store := Store{
		CandidatePath: filepath.Join(t.TempDir(), "candidate.json"),
		ActivePath:    filepath.Join(t.TempDir(), "active.json"),
	}
	if _, err := store.LoadCandidate(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadCandidate() error = %v, want ErrNotFound", err)
	}
	if _, err := store.LoadActive(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadActive() error = %v, want ErrNotFound", err)
	}
}
