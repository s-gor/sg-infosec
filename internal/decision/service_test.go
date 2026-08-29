//go:build cgo

package decision

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

func TestCheckReturnsActiveDecision(t *testing.T) {
	database, sourceClock := newServiceFixture(t)
	insertDecision(t, database, model.Decision{
		ID: "active", SourceID: "panel-a", PolicyID: "p", Scope: model.ScopeAdminLogin,
		IP: netip.MustParseAddr("192.0.2.30"), Backend: model.BackendApplication,
		State: model.DecisionActive, ReasonCode: "threshold_exceeded", Strike: 1,
		StartsAt: sourceClock.Now(), ExpiresAt: sourceClock.Now().Add(time.Hour),
		CreatedAt: sourceClock.Now(), UpdatedAt: sourceClock.Now(),
	})
	result, err := NewService(database, sourceClock).Check(context.Background(), "panel-a", model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.30"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Blocked || result.DecisionID != "active" {
		t.Fatalf("result=%+v", result)
	}
}

func TestCheckExpiresElapsedDecision(t *testing.T) {
	database, sourceClock := newServiceFixture(t)
	insertDecision(t, database, model.Decision{
		ID: "expired", SourceID: "panel-a", PolicyID: "p", Scope: model.ScopeAdminLogin,
		IP: netip.MustParseAddr("192.0.2.31"), Backend: model.BackendApplication,
		State: model.DecisionActive, ReasonCode: "threshold_exceeded", Strike: 1,
		StartsAt: sourceClock.Now().Add(-time.Hour), ExpiresAt: sourceClock.Now().Add(-time.Minute),
		CreatedAt: sourceClock.Now().Add(-time.Hour), UpdatedAt: sourceClock.Now().Add(-time.Hour),
	})
	result, err := NewService(database, sourceClock).Check(context.Background(), "panel-a", model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.31"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked {
		t.Fatalf("result=%+v", result)
	}
	page, err := database.ListDecisions(context.Background(), store.DecisionFilter{State: model.DecisionExpired, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "expired" {
		t.Fatalf("page=%+v", page)
	}
}

func TestCheckDoesNotCrossSourceBoundary(t *testing.T) {
	database, sourceClock := newServiceFixture(t)
	insertDecision(t, database, model.Decision{
		ID: "other", SourceID: "panel-a", PolicyID: "p", Scope: model.ScopeAdminLogin,
		IP: netip.MustParseAddr("192.0.2.32"), Backend: model.BackendApplication,
		State: model.DecisionActive, ReasonCode: "threshold_exceeded", Strike: 1,
		StartsAt: sourceClock.Now(), ExpiresAt: sourceClock.Now().Add(time.Hour),
		CreatedAt: sourceClock.Now(), UpdatedAt: sourceClock.Now(),
	})
	result, err := NewService(database, sourceClock).Check(context.Background(), "panel-b", model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.32"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked {
		t.Fatalf("result=%+v", result)
	}
}

func newServiceFixture(t *testing.T) (*store.Store, *clock.Fake) {
	t.Helper()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, &clock.Fake{Current: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
}

func insertDecision(t *testing.T, database *store.Store, decision model.Decision) {
	t.Helper()
	if err := database.WithTx(context.Background(), func(tx *store.Tx) error {
		return tx.InsertDecision(context.Background(), decision)
	}); err != nil {
		t.Fatal(err)
	}
}
