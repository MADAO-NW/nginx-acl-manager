package serverconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAndListenAddress(t *testing.T) {
	t.Parallel()

	config := Default()
	if config.ListenPort != 7582 {
		t.Fatalf("ListenPort = %d", config.ListenPort)
	}
	address, err := config.ListenAddressWithPort()
	if err != nil {
		t.Fatalf("ListenAddressWithPort() error = %v", err)
	}
	if address != "127.0.0.1:7582" {
		t.Fatalf("address = %q", address)
	}
}

func TestLoadStrictConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listenPort":17582}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenPort != 17582 {
		t.Fatalf("ListenPort = %d", config.ListenPort)
	}

	if err := os.WriteFile(path, []byte(`{"listenPort":7582,"listenAddress":"0.0.0.0"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(unknown) error = %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(unknown field) error = nil")
	}
}

func TestValidatePort(t *testing.T) {
	t.Parallel()

	for _, port := range []int{-1, 0, 65536} {
		if err := (Config{ListenPort: port}).Validate(); err == nil {
			t.Fatalf("Validate(%d) error = nil", port)
		}
	}
}

func TestSaveConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{ListenPort: 17582}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenPort != 17582 {
		t.Fatalf("ListenPort = %d", config.ListenPort)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := Save(path, Config{ListenPort: 7582}); err != nil {
		t.Fatalf("Save(existing) error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := Save(path, Config{ListenPort: 0}); err == nil {
		t.Fatal("Save(invalid) error = nil")
	}
}
