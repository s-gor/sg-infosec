package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupCodeSingleUseExpiryAndPersistence(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if store.AdminConfigured() {
		t.Fatal("fresh store unexpectedly has an administrator")
	}
	code, err := store.IssueSetupCode(15 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !store.SetupPending() {
		t.Fatal("setup must be pending after code issue")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), code) {
		t.Fatal("raw setup code persisted")
	}
	if err := store.ConsumeSetup(code, "admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if store.SetupPending() {
		t.Fatal("setup remained pending after consumption")
	}
	if !store.AdminConfigured() || store.AdminUsername() != "admin" {
		t.Fatal("administrator was not created")
	}
	bytes, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "correct horse battery staple") {
		t.Fatal("plaintext password persisted")
	}
	if err := store.ConsumeSetup(code, "admin2", "another correct password"); !errors.Is(err, ErrSetupUnavailable) {
		t.Fatalf("reused setup code error=%v", err)
	}
	reopened, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.AdminConfigured() || reopened.AdminUsername() != "admin" {
		t.Fatal("administrator state did not survive reopen")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("auth state mode=%#o", info.Mode().Perm())
	}
}

func TestSetupCodeExpires(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store, err := Open(filepath.Join(t.TempDir(), "auth.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssueSetupCode(15 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(15*time.Minute + time.Second)
	if err := store.ConsumeSetup(code, "admin", "correct horse battery staple"); !errors.Is(err, ErrSetupUnavailable) {
		t.Fatalf("expired setup code error=%v", err)
	}
}

func TestResetAdminRevokesSessions(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store, err := Open(filepath.Join(t.TempDir(), "auth.json"), func() time.Time { return now })
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
	session, err := store.NewSession("admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Session(session.Token); !ok {
		t.Fatal("session missing before reset")
	}
	if err := store.ResetAdmin("root-admin", "new correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Session(session.Token); ok {
		t.Fatal("admin reset did not revoke sessions")
	}
	if store.AdminUsername() != "root-admin" {
		t.Fatalf("username=%q", store.AdminUsername())
	}
}
