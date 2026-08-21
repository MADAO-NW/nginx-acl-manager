package auth

import (
	"testing"
	"time"
)

func TestLoginLimiterProgressionAndReset(t *testing.T) {
	t.Parallel()

	limiter := NewLoginLimiter()
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	wants := []time.Duration{0, 0, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for index, want := range wants {
		if got := limiter.Failure("source"); got != want {
			t.Fatalf("Failure(%d) = %s; want %s", index+1, got, want)
		}
	}
	limiter.Success("source")
	if got := limiter.Failure("source"); got != 0 {
		t.Fatalf("Failure(after success) = %s", got)
	}
	now = now.Add(loginFailureResetAfter)
	if got := limiter.Failure("source"); got != 0 {
		t.Fatalf("Failure(after timeout) = %s", got)
	}
}
