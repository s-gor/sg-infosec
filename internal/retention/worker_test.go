//go:build cgo

package retention

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
)

func TestRetentionDeletesInBoundedBatches(t *testing.T) {
	database, fake := retentionFixture(t)
	old := fake.Now().Add(-48 * time.Hour)
	for i := 0; i < 25; i++ {
		event := model.Event{SourceID: "panel", EventID: eventID(i), EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin, IP: netip.MustParseAddr("192.0.2.10"), OccurredAt: old, ReceivedAt: old}
		err := database.WithTx(context.Background(), func(tx *store.Tx) error {
			if _, err := tx.InsertEvent(context.Background(), event); err != nil {
				return err
			}
			return tx.AppendAudit(context.Background(), model.AuditEntry{OccurredAt: old, Actor: "test", Action: "old", TargetType: "event", TargetID: event.EventID, RequestID: event.EventID, Result: "success"})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	worker := New(database, fake, Config{EventRetention: 24 * time.Hour, AuditRetention: 24 * time.Hour, BatchSize: 7, MaxBatches: 2})
	result, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.EventsDeleted != 14 || result.AuditDeleted != 14 {
		t.Fatalf("result=%+v", result)
	}
	remainingEvents := countEvents(t, database, old.Add(-time.Second))
	if remainingEvents != 11 {
		t.Fatalf("remaining events=%d", remainingEvents)
	}
	page, err := database.ListAudit(context.Background(), store.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 11 {
		t.Fatalf("remaining audit=%d", len(page.Items))
	}
}

func TestRetentionNeverDeletesDecisionsOrAllowlist(t *testing.T) {
	database, fake := retentionFixture(t)
	old := fake.Now().Add(-48 * time.Hour)
	decision := model.Decision{ID: "active", SourceID: "panel", PolicyID: "p", Scope: model.ScopeAdminLogin, IP: netip.MustParseAddr("192.0.2.20"), Backend: model.BackendApplication, State: model.DecisionActive, ReasonCode: "test", Strike: 1, StartsAt: old, ExpiresAt: fake.Now().Add(time.Hour), CreatedAt: old, UpdatedAt: old}
	if err := database.WithTx(context.Background(), func(tx *store.Tx) error { return tx.InsertDecision(context.Background(), decision) }); err != nil {
		t.Fatal(err)
	}
	if err := database.PutAllowlistEntry(context.Background(), model.AllowlistEntry{ID: "allow", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Description: "trusted", CreatedAt: old, CreatedBy: "test"}, "test", "seed"); err != nil {
		t.Fatal(err)
	}
	worker := New(database, fake, Config{EventRetention: time.Hour, AuditRetention: time.Hour, BatchSize: 100, MaxBatches: 10})
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := database.ListDecisions(context.Background(), store.DecisionFilter{Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("decisions=%+v err=%v", page, err)
	}
	allow, err := database.ListAllowlist(context.Background(), store.AllowlistFilter{Limit: 10})
	if err != nil || len(allow.Items) != 1 {
		t.Fatalf("allowlist=%+v err=%v", allow, err)
	}
}

func retentionFixture(t *testing.T) (*store.Store, *clock.Fake) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, &clock.Fake{Current: time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)}
}

func countEvents(t *testing.T, db *store.Store, since time.Time) int {
	t.Helper()
	var count int
	err := db.WithTx(context.Background(), func(tx *store.Tx) error {
		var err error
		count, err = tx.CountEvents(context.Background(), "panel", model.EventAuthFailed, model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.10"), since)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func eventID(index int) string {
	return time.Unix(int64(index), 0).UTC().Format("150405.000000000")
}
