package auth

import (
	"testing"
	"time"
)

func TestSessionLifecycleAndExpiry(t *testing.T) {
	t.Parallel()

	store, err := NewSessionStore(10*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionStore() error = %v", err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	sessionID, csrfToken, err := store.Create()
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if sessionID == "" || csrfToken == "" {
		t.Fatal("Create() returned empty token")
	}
	if got, ok := store.Get(sessionID); !ok || got != csrfToken {
		t.Fatalf("Get() = %q, %v", got, ok)
	}

	now = now.Add(9 * time.Minute)
	if _, ok := store.Get(sessionID); !ok {
		t.Fatal("session expired before idle timeout")
	}
	now = now.Add(11 * time.Minute)
	if _, ok := store.Get(sessionID); ok {
		t.Fatal("session did not expire after idle timeout")
	}
}

func TestSessionAbsoluteExpiryAndDelete(t *testing.T) {
	t.Parallel()

	store, err := NewSessionStore(30*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionStore() error = %v", err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	sessionID, _, err := store.Create()
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	for range 3 {
		now = now.Add(20 * time.Minute)
		if now.Sub(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)) < time.Hour {
			if _, ok := store.Get(sessionID); !ok {
				t.Fatal("session expired before absolute timeout")
			}
		}
	}
	if _, ok := store.Get(sessionID); ok {
		t.Fatal("session did not expire at absolute timeout")
	}

	sessionID, _, err = store.Create()
	if err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}
	store.Delete(sessionID)
	if _, ok := store.Get(sessionID); ok {
		t.Fatal("Delete() left session active")
	}
}

func TestNewSessionStoreRejectsInvalidTimeouts(t *testing.T) {
	t.Parallel()

	if _, err := NewSessionStore(0, time.Hour); err == nil {
		t.Fatal("NewSessionStore(0, ...) error = nil")
	}
	if _, err := NewSessionStore(2*time.Hour, time.Hour); err == nil {
		t.Fatal("NewSessionStore(idle > absolute) error = nil")
	}
}

func TestPendingSessionPromotionAndDeleteAll(t *testing.T) {
	t.Parallel()

	store, err := NewSessionStore(30*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionStore() error = %v", err)
	}
	pendingID, pendingCSRF, err := store.CreatePending()
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if _, ok := store.Get(pendingID); ok {
		t.Fatal("pending session became authenticated")
	}
	if got, ok := store.GetPending(pendingID); !ok || got != pendingCSRF {
		t.Fatalf("GetPending() = %q, %v", got, ok)
	}
	sessionID, _, ok, err := store.PromotePending(pendingID)
	if err != nil || !ok {
		t.Fatalf("PromotePending() = %q, %v, %v", sessionID, ok, err)
	}
	if _, ok := store.GetPending(pendingID); ok {
		t.Fatal("PromotePending() kept pending session")
	}
	if _, ok := store.Get(sessionID); !ok {
		t.Fatal("promoted session is not authenticated")
	}
	store.DeleteAll()
	if _, ok := store.Get(sessionID); ok {
		t.Fatal("DeleteAll() left session active")
	}
}
