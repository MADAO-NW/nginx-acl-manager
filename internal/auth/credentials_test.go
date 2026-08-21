package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashPasswordAndVerifier(t *testing.T) {
	t.Parallel()

	password := "correct horse battery staple"
	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("HashPassword() = %q", encoded)
	}

	verifier, err := NewVerifier(Credentials{Username: "admin", PasswordHash: encoded})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if !verifier.Verify("admin", password) {
		t.Fatal("Verify(correct) = false")
	}
	if verifier.Verify("unknown", password) {
		t.Fatal("Verify(wrong username) = true")
	}
	if verifier.Verify("admin", "incorrect password") {
		t.Fatal("Verify(wrong password) = true")
	}
}

func TestHashPasswordUsesIndependentSalt(t *testing.T) {
	t.Parallel()

	first, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword(first) error = %v", err)
	}
	second, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword(second) error = %v", err)
	}
	if first == second {
		t.Fatal("HashPassword() reused salt")
	}
}

func TestHashPasswordRejectsShortPassword(t *testing.T) {
	t.Parallel()

	if _, err := HashPassword("12345"); err == nil {
		t.Fatal("HashPassword(short) error = nil")
	}
	if _, err := HashPassword("123456"); err != nil {
		t.Fatalf("HashPassword(minimum) error = %v", err)
	}
}

func TestNewVerifierRejectsUnsupportedHash(t *testing.T) {
	t.Parallel()

	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	tests := []string{
		strings.Replace(encoded, "argon2id", "argon2i", 1),
		strings.Replace(encoded, "m=19456", "m=999999", 1),
		encoded + "extra",
	}
	for _, candidate := range tests {
		if _, err := NewVerifier(Credentials{Username: "admin", PasswordHash: candidate}); err == nil {
			t.Fatalf("NewVerifier(%q) error = nil", candidate)
		}
	}
}

func TestLoadCredentialsStrictJSON(t *testing.T) {
	t.Parallel()

	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	content := `{"username":"admin","passwordHash":"` + encoded + `"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	credentials, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}
	if credentials.Username != "admin" || credentials.PasswordHash != encoded {
		t.Fatalf("LoadCredentials() = %#v", credentials)
	}

	content = `{"username":"admin","passwordHash":"` + encoded + `","role":"root"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(unknown) error = %v", err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("LoadCredentials(unknown field) error = nil")
	}
}

func TestSaveCredentials(t *testing.T) {
	t.Parallel()

	encoded, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := SaveCredentials(path, Credentials{Username: "admin", PasswordHash: encoded}); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}
	credentials, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials() error = %v", err)
	}
	if credentials.Username != "admin" {
		t.Fatalf("Username = %q", credentials.Username)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := SaveCredentials(path, credentials); err != nil {
		t.Fatalf("SaveCredentials(existing) error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if err := SaveCredentials(path, Credentials{Username: "", PasswordHash: encoded}); err == nil {
		t.Fatal("SaveCredentials(invalid) error = nil")
	}
}
