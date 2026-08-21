package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238Vector(t *testing.T) {
	t.Parallel()

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	code, err := generateTOTPCode(secret, 59/totpPeriodSeconds, 8)
	if err != nil {
		t.Fatalf("generateTOTPCode() error = %v", err)
	}
	if code != "94287082" {
		t.Fatalf("generateTOTPCode() = %q", code)
	}
}

func TestTOTPWindowAndReplay(t *testing.T) {
	t.Parallel()

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1_700_000_000, 0)
	step := now.Unix() / totpPeriodSeconds
	code, err := generateTOTPCode(secret, step, totpDigits)
	if err != nil {
		t.Fatalf("generateTOTPCode() error = %v", err)
	}
	acceptedStep, ok := VerifyTOTP(secret, code, now, -1)
	if !ok || acceptedStep != step {
		t.Fatalf("VerifyTOTP() = %d, %v", acceptedStep, ok)
	}
	if _, ok := VerifyTOTP(secret, code, now, acceptedStep); ok {
		t.Fatal("VerifyTOTP() accepted replay")
	}
	previousCode, err := generateTOTPCode(secret, step-1, totpDigits)
	if err != nil {
		t.Fatalf("generateTOTPCode(previous) error = %v", err)
	}
	if _, ok := VerifyTOTP(secret, previousCode, now, -1); !ok {
		t.Fatal("VerifyTOTP() rejected adjacent step")
	}
}

func TestGenerateTOTPSecretAndProvisioningURI(t *testing.T) {
	t.Parallel()

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret() error = %v", err)
	}
	if _, err := decodeTOTPSecret(secret); err != nil {
		t.Fatalf("decodeTOTPSecret() error = %v", err)
	}
	uri, err := ProvisioningURI("Nginx ACL Manager", "admin", secret)
	if err != nil {
		t.Fatalf("ProvisioningURI() error = %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("ProvisioningURI() = %q", uri)
	}
}

func TestTOTPStateStorePersistsReplayBoundary(t *testing.T) {
	t.Parallel()

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1_700_000_000, 0)
	code, err := generateTOTPCode(secret, now.Unix()/totpPeriodSeconds, totpDigits)
	if err != nil {
		t.Fatalf("generateTOTPCode() error = %v", err)
	}
	path := t.TempDir() + "/totp-state.json"
	first := &TOTPStateStore{Path: path, Now: func() time.Time { return now }}
	if !first.VerifyAndConsume(secret, code) {
		t.Fatal("first VerifyAndConsume() = false")
	}
	second := &TOTPStateStore{Path: path, Now: func() time.Time { return now }}
	if second.VerifyAndConsume(secret, code) {
		t.Fatal("restarted store accepted replay")
	}
}
