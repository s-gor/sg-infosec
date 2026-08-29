//go:build cgo

package store

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

func TestOpenCreatesSchemaAndEnablesSQLiteSafetyPragmas(t *testing.T) {
	store := openTestStore(t)

	foreignKeys, err := store.pragmaInt(context.Background(), "foreign_keys")
	if err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}
	journalMode, err := store.pragmaText(context.Background(), "journal_mode")
	if err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	busyTimeout, err := store.pragmaInt(context.Background(), "busy_timeout")
	if err != nil {
		t.Fatal(err)
	}
	if busyTimeout <= 0 {
		t.Fatalf("busy_timeout = %d, want > 0", busyTimeout)
	}
	if count := tableCount(t, store, "schema_migrations"); count != 1 {
		t.Fatalf("schema_migrations count = %d, want 1", count)
	}
}

func TestInsertEventIsIdempotentPerSourceAndEventID(t *testing.T) {
	store := openTestStore(t)
	event := testEvent("panel-a", "event-1", "192.0.2.10")

	if err := store.WithTx(context.Background(), func(tx *Tx) error {
		inserted, err := tx.InsertEvent(context.Background(), event)
		if err != nil {
			return err
		}
		if !inserted {
			t.Fatal("first insert reported duplicate")
		}
		inserted, err = tx.InsertEvent(context.Background(), event)
		if err != nil {
			return err
		}
		if inserted {
			t.Fatal("second insert reported new row")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if count := tableCount(t, store, "events"); count != 1 {
		t.Fatalf("events count = %d, want 1", count)
	}
}

func TestWithTxRollsBackEventAndDecisionTogether(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	rollback := errors.New("force rollback")

	err := store.WithTx(context.Background(), func(tx *Tx) error {
		if _, err := tx.InsertEvent(context.Background(), testEvent("panel-a", "event-1", "192.0.2.20")); err != nil {
			return err
		}
		if err := tx.InsertDecision(context.Background(), testDecision("decision-1", "panel-a", "192.0.2.20", now)); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("WithTx error = %v, want rollback sentinel", err)
	}
	if count := tableCount(t, store, "events"); count != 0 {
		t.Fatalf("events count = %d, want 0", count)
	}
	if count := tableCount(t, store, "decisions"); count != 0 {
		t.Fatalf("decisions count = %d, want 0", count)
	}
}

func TestActiveDecisionLookupMatchesIPv6CanonicalForm(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	decision := testDecision("decision-v6", "panel-a", "2001:0db8:0:0:0:0:0:10", now)
	if err := store.WithTx(context.Background(), func(tx *Tx) error {
		return tx.InsertDecision(context.Background(), decision)
	}); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("2001:db8::10")
	got, err := store.GetActiveDecision(context.Background(), "panel-a", model.ScopeAdminLogin, addr, now)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != decision.ID {
		t.Fatalf("decision = %#v, want %q", got, decision.ID)
	}
}

func TestExpiredAllowlistEntryDoesNotMatch(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Minute)
	active := now.Add(time.Hour)
	entries := []model.AllowlistEntry{
		{ID: "expired", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Description: "expired", ExpiresAt: &expired, CreatedAt: now, CreatedBy: "test"},
		{ID: "active", Prefix: netip.MustParsePrefix("2001:db8::/32"), Description: "active", ExpiresAt: &active, CreatedAt: now, CreatedBy: "test"},
	}
	for _, entry := range entries {
		if err := store.PutAllowlistEntry(context.Background(), entry, "test", "request-1"); err != nil {
			t.Fatal(err)
		}
	}

	if matched, err := store.IsAllowlisted(context.Background(), model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.10"), now); err != nil {
		t.Fatal(err)
	} else if matched {
		t.Fatal("expired allowlist entry matched")
	}
	if matched, err := store.IsAllowlisted(context.Background(), model.ScopeAdminLogin, netip.MustParseAddr("2001:db8::10"), now); err != nil {
		t.Fatal(err)
	} else if !matched {
		t.Fatal("active IPv6 allowlist entry did not match")
	}
}

func TestCountEventsUsesSourceTypeScopeIPAndReceivedWindow(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	old := testEvent("panel-a", "old", "192.0.2.40")
	old.ReceivedAt = now.Add(-11 * time.Minute)
	recent := testEvent("panel-a", "recent", "192.0.2.40")
	recent.ReceivedAt = now.Add(-time.Minute)
	otherSource := testEvent("panel-b", "other", "192.0.2.40")
	otherSource.ReceivedAt = now.Add(-time.Minute)

	if err := store.WithTx(context.Background(), func(tx *Tx) error {
		for _, event := range []model.Event{old, recent, otherSource} {
			if _, err := tx.InsertEvent(context.Background(), event); err != nil {
				return err
			}
		}
		count, err := tx.CountEvents(context.Background(), "panel-a", model.EventAuthFailed, model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.40"), now.Add(-10*time.Minute))
		if err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("CountEvents = %d, want 1", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFindLastPolicyDecisionIsSourceIsolated(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, source := range []string{"panel-a", "panel-b"} {
		decision := testDecision("decision-"+source, source, "192.0.2.50", now)
		if err := store.WithTx(context.Background(), func(tx *Tx) error {
			return tx.InsertDecision(context.Background(), decision)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WithTx(context.Background(), func(tx *Tx) error {
		got, err := tx.FindLastPolicyDecision(context.Background(), "panel-a", "policy-1", netip.MustParseAddr("192.0.2.50"), now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if got == nil || got.SourceID != "panel-a" {
			t.Fatalf("decision = %#v, want panel-a", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPutAllowlistEntryRejectsInvalidPrefix(t *testing.T) {
	store := openTestStore(t)
	entry := model.AllowlistEntry{ID: "invalid", Description: "invalid", CreatedAt: time.Now().UTC(), CreatedBy: "test"}
	if err := store.PutAllowlistEntry(context.Background(), entry, "test", "request-invalid"); err == nil {
		t.Fatal("PutAllowlistEntry succeeded with invalid prefix")
	}
	if count := tableCount(t, store, "allowlist_entries"); count != 0 {
		t.Fatalf("allowlist count = %d, want 0", count)
	}
}

func TestOpenRejectsDatabaseWithNewerSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	db, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.exec("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL); INSERT INTO schema_migrations VALUES (99, 'future')"); err != nil {
		t.Fatal(err)
	}
	if err := db.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("Open accepted a newer schema version")
	}
}

func TestListDecisionsUsesStableCreatedAtIDPagination(t *testing.T) {
	store := openTestStore(t)
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"decision-a", "decision-c", "decision-b"} {
		decision := testDecision(id, "panel-a", "192.0.2.30", now)
		if err := store.WithTx(context.Background(), func(tx *Tx) error {
			return tx.InsertDecision(context.Background(), decision)
		}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := store.ListDecisions(context.Background(), DecisionFilter{SourceID: "panel-a", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.Items[0].ID != "decision-c" || first.Items[1].ID != "decision-b" {
		t.Fatalf("first page = %#v", first.Items)
	}
	if first.Next == nil {
		t.Fatal("first page has no cursor")
	}
	second, err := store.ListDecisions(context.Background(), DecisionFilter{SourceID: "panel-a", Limit: 2, Cursor: first.Next})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].ID != "decision-a" {
		t.Fatalf("second page = %#v", second.Items)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sg-infosec.db")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return store
}

func testEvent(sourceID, eventID, ip string) model.Event {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	return model.Event{
		SourceID: sourceID, EventID: eventID, EventType: model.EventAuthFailed,
		Scope: model.ScopeAdminLogin, IP: netip.MustParseAddr(ip), Subject: "admin",
		OccurredAt: now, ReceivedAt: now, Metadata: map[string]any{"reason": "invalid_password"},
	}
}

func testDecision(id, sourceID, ip string, now time.Time) model.Decision {
	return model.Decision{
		ID: id, SourceID: sourceID, PolicyID: "policy-1", Scope: model.ScopeAdminLogin,
		IP: netip.MustParseAddr(ip), Backend: model.BackendApplication, State: model.DecisionActive,
		ReasonCode: "threshold_exceeded", Strike: 1, StartsAt: now, ExpiresAt: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
}

func tableCount(t *testing.T, store *Store, table string) int64 {
	t.Helper()
	count, err := store.tableCount(context.Background(), table)
	if err != nil {
		t.Fatal(err)
	}
	return count
}
