package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func configuredStore(t *testing.T, now *time.Time) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "auth.json"), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssueSetupCode(15 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeSetup(code, "admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSessionLifecycleAndCSRF(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := configuredStore(t, &now)
	first, err := store.NewSession("admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.NewSession("admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token || first.CSRFToken == second.CSRFToken || first.Token == "" || first.CSRFToken == "" {
		t.Fatal("session and CSRF tokens must be independent random values")
	}
	resolved, ok := store.Session(first.Token)
	if !ok || resolved.Username != "admin" {
		t.Fatal("valid session not resolved")
	}
	if !store.ValidateCSRF(first.Token, first.CSRFToken) {
		t.Fatal("valid CSRF rejected")
	}
	if store.ValidateCSRF(first.Token, second.CSRFToken) {
		t.Fatal("foreign CSRF accepted")
	}
	now = now.Add(time.Hour + time.Second)
	if _, ok := store.Session(first.Token); ok {
		t.Fatal("expired session accepted")
	}
	if store.ValidateCSRF(first.Token, first.CSRFToken) {
		t.Fatal("expired session CSRF accepted")
	}
	if err := store.DeleteSession(second.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Session(second.Token); ok {
		t.Fatal("deleted session accepted")
	}
}

func TestLoginThrottleAndRecovery(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := configuredStore(t, &now)
	for attempt := 1; attempt <= 4; attempt++ {
		if err := store.Authenticate("admin", "wrong", "198.51.100.10"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d error=%v", attempt, err)
		}
	}
	if err := store.Authenticate("admin", "wrong", "198.51.100.10"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fifth attempt error=%v", err)
	}
	if err := store.Authenticate("admin", "correct horse battery staple", "198.51.100.10"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("throttled correct login error=%v", err)
	}
	if err := store.Authenticate("admin", "correct horse battery staple", "203.0.113.20"); err != nil {
		t.Fatalf("independent remote key was throttled: %v", err)
	}
	now = now.Add(5*time.Minute + time.Second)
	if err := store.Authenticate("admin", "correct horse battery staple", "198.51.100.10"); err != nil {
		t.Fatalf("login did not recover after throttle: %v", err)
	}
}

func TestSuccessfulLoginClearsFailureBucket(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := configuredStore(t, &now)
	for attempt := 0; attempt < 3; attempt++ {
		if err := store.Authenticate("admin", "wrong", "198.51.100.11"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	if err := store.Authenticate("admin", "correct horse battery staple", "198.51.100.11"); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if err := store.Authenticate("admin", "wrong", "198.51.100.11"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("post-success attempt %d error=%v", attempt+1, err)
		}
	}
}
