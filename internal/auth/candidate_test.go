package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyCredentialCandidates(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialsPath := filepath.Join(directory, "auth.json")
	candidatePath := filepath.Join(directory, "staging", "auth-candidate.json")
	statePath := filepath.Join(directory, "auth", "totp-state.json")
	passwordHash, err := HashPassword("initial-password")
	if err != nil {
		t.Fatalf("HashPassword(initial) error = %v", err)
	}
	credentials := Credentials{Username: "admin", PasswordHash: passwordHash}
	if err := SaveCredentials(credentialsPath, credentials); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}
	fingerprint, err := CredentialsFingerprint(credentials)
	if err != nil {
		t.Fatalf("CredentialsFingerprint() error = %v", err)
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}
	if err := SaveCandidate(candidatePath, Candidate{Action: CandidateEnableTOTP, ExpectedFingerprint: fingerprint, TOTPSecret: secret, TOTPInitialStep: 123}); err != nil {
		t.Fatalf("SaveCandidate(enable) error = %v", err)
	}
	if _, err := ApplyCandidate(credentialsPath, candidatePath, statePath); err != nil {
		t.Fatalf("ApplyCandidate(enable) error = %v", err)
	}
	enabled, err := LoadCredentials(credentialsPath)
	if err != nil {
		t.Fatalf("LoadCredentials(enabled) error = %v", err)
	}
	if enabled.TOTP == nil || enabled.TOTP.Secret != secret {
		t.Fatalf("enabled credentials = %#v", enabled)
	}

	newPasswordHash, err := HashPassword("changed-password")
	if err != nil {
		t.Fatalf("HashPassword(changed) error = %v", err)
	}
	fingerprint, _ = CredentialsFingerprint(enabled)
	if err := SaveCandidate(candidatePath, Candidate{Action: CandidateChangePassword, ExpectedFingerprint: fingerprint, PasswordHash: newPasswordHash}); err != nil {
		t.Fatalf("SaveCandidate(password) error = %v", err)
	}
	if _, err := ApplyCandidate(credentialsPath, candidatePath, statePath); err != nil {
		t.Fatalf("ApplyCandidate(password) error = %v", err)
	}
	changed, err := LoadCredentials(credentialsPath)
	if err != nil {
		t.Fatalf("LoadCredentials(changed) error = %v", err)
	}
	if changed.PasswordHash != newPasswordHash || changed.TOTP == nil {
		t.Fatalf("changed credentials = %#v", changed)
	}

	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		t.Fatalf("MkdirAll(state) error = %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile(state) error = %v", err)
	}
	fingerprint, _ = CredentialsFingerprint(changed)
	if err := SaveCandidate(candidatePath, Candidate{Action: CandidateDisableTOTP, ExpectedFingerprint: fingerprint}); err != nil {
		t.Fatalf("SaveCandidate(disable) error = %v", err)
	}
	if _, err := ApplyCandidate(credentialsPath, candidatePath, statePath); err != nil {
		t.Fatalf("ApplyCandidate(disable) error = %v", err)
	}
	disabled, err := LoadCredentials(credentialsPath)
	if err != nil {
		t.Fatalf("LoadCredentials(disabled) error = %v", err)
	}
	if disabled.TOTP != nil {
		t.Fatalf("disabled credentials = %#v", disabled)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("TOTP state still exists: %v", err)
	}
}

func TestApplyCandidateRejectsStaleFingerprint(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	credentialsPath := filepath.Join(directory, "auth.json")
	candidatePath := filepath.Join(directory, "candidate.json")
	passwordHash, _ := HashPassword("initial-password")
	if err := SaveCredentials(credentialsPath, Credentials{Username: "admin", PasswordHash: passwordHash}); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}
	staleFingerprint := "0000000000000000000000000000000000000000000000000000000000000000"
	newPasswordHash, _ := HashPassword("changed-password")
	if err := SaveCandidate(candidatePath, Candidate{Action: CandidateChangePassword, ExpectedFingerprint: staleFingerprint, PasswordHash: newPasswordHash}); err != nil {
		t.Fatalf("SaveCandidate() error = %v", err)
	}
	if _, err := ApplyCandidate(credentialsPath, candidatePath, filepath.Join(directory, "state.json")); err == nil {
		t.Fatal("ApplyCandidate(stale) error = nil")
	}
}
