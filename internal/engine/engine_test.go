//go:build cgo

package engine

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
)

func TestEngineCreatesDecisionAtExactThreshold(t *testing.T) {
	fixture := newFixture(t, 5)
	for i := 0; i < 4; i++ {
		result, err := fixture.process(i, "panel-a", "192.0.2.10")
		if err != nil {
			t.Fatal(err)
		}
		if result.DecisionID != "" {
			t.Fatalf("decision created at event %d", i+1)
		}
	}
	result, err := fixture.process(4, "panel-a", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if result.DecisionID == "" {
		t.Fatal("fifth event did not create decision")
	}
	if got := countDecisions(t, fixture.store); got != 1 {
		t.Fatalf("decisions=%d", got)
	}
}

func TestEngineDoesNotCountEventsOutsideWindow(t *testing.T) {
	fixture := newFixture(t, 3)
	fixture.policy.Window = 10 * time.Minute
	fixture.engine = New(fixture.store, fixture.clock, []model.Policy{fixture.policy})
	_, _ = fixture.process(0, "panel-a", "192.0.2.11")
	_, _ = fixture.process(1, "panel-a", "192.0.2.11")
	fixture.clock.Advance(11 * time.Minute)
	result, err := fixture.process(2, "panel-a", "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	if result.DecisionID != "" {
		t.Fatal("old events were counted")
	}
}

func TestEngineDoesNotCreateSecondDecisionWhileOneIsActive(t *testing.T) {
	fixture := newFixture(t, 2)
	_, _ = fixture.process(0, "panel-a", "192.0.2.12")
	first, err := fixture.process(1, "panel-a", "192.0.2.12")
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i < 8; i++ {
		_, _ = fixture.process(i, "panel-a", "192.0.2.12")
	}
	if got := countDecisions(t, fixture.store); got != 1 {
		t.Fatalf("decisions=%d, first=%s", got, first.DecisionID)
	}
}

func TestEngineEscalatesAndCapsDuration(t *testing.T) {
	fixture := newFixture(t, 1)
	fixture.policy.BaseDuration = 30 * time.Minute
	fixture.policy.EscalationFactor = 4
	fixture.policy.MaxDuration = 2 * time.Hour
	fixture.engine = New(fixture.store, fixture.clock, []model.Policy{fixture.policy})
	first, err := fixture.process(0, "panel-a", "192.0.2.13")
	if err != nil {
		t.Fatal(err)
	}
	d1, _ := fixture.store.GetActiveDecision(context.Background(), "panel-a", model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.13"), fixture.clock.Now())
	if d1 == nil || d1.ExpiresAt.Sub(d1.StartsAt) != 30*time.Minute {
		t.Fatalf("first duration=%v", d1)
	}
	fixture.clock.Advance(31 * time.Minute)
	second, err := fixture.process(1, "panel-a", "192.0.2.13")
	if err != nil {
		t.Fatal(err)
	}
	if second.DecisionID == first.DecisionID {
		t.Fatal("decision ID reused")
	}
	d2, _ := fixture.store.GetActiveDecision(context.Background(), "panel-a", model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.13"), fixture.clock.Now())
	if d2 == nil || d2.Strike != 2 || d2.ExpiresAt.Sub(d2.StartsAt) != 2*time.Hour {
		t.Fatalf("second=%+v", d2)
	}
}

func TestEngineResetsStrikeAfterResetInterval(t *testing.T) {
	fixture := newFixture(t, 1)
	fixture.policy.ResetInterval = time.Hour
	fixture.engine = New(fixture.store, fixture.clock, []model.Policy{fixture.policy})
	_, _ = fixture.process(0, "panel-a", "192.0.2.14")
	fixture.clock.Advance(fixture.policy.BaseDuration + time.Hour + time.Second)
	_, err := fixture.process(1, "panel-a", "192.0.2.14")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := fixture.store.GetActiveDecision(context.Background(), "panel-a", model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.14"), fixture.clock.Now())
	if d == nil || d.Strike != 1 {
		t.Fatalf("strike=%+v", d)
	}
}

func TestEngineSkipsAutomaticDecisionForAllowlistedPrefix(t *testing.T) {
	fixture := newFixture(t, 1)
	now := fixture.clock.Now()
	if err := fixture.store.PutAllowlistEntry(context.Background(), model.AllowlistEntry{ID: "allow-1", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Description: "office", CreatedAt: now, CreatedBy: "test"}, "test", "req"); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.process(0, "panel-a", "192.0.2.15")
	if err != nil {
		t.Fatal(err)
	}
	if result.DecisionID != "" {
		t.Fatal("allowlisted IP was blocked")
	}
}

func TestEngineProcessesConcurrentEventsIntoOneDecision(t *testing.T) {
	fixture := newFixture(t, 5)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, err := fixture.process(i, "panel-a", "192.0.2.16"); errs <- err }(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if events := countEvents(t, fixture.store, "panel-a", "192.0.2.16", time.Time{}); events != 20 {
		t.Fatalf("events=%d", events)
	}
	if decisions := countDecisions(t, fixture.store); decisions != 1 {
		t.Fatalf("decisions=%d", decisions)
	}
}

func TestEngineRollsBackEventWhenDecisionInsertFails(t *testing.T) {
	fixture := newFixture(t, 1)
	fixture.engine.idGenerator = func() (string, error) { return "fixed-id", nil }
	existing := model.Decision{ID: "fixed-id", SourceID: "other", PolicyID: "other", Scope: model.ScopeAdminLogin, IP: netip.MustParseAddr("198.51.100.1"), Backend: model.BackendApplication, State: model.DecisionActive, ReasonCode: "test", Strike: 1, StartsAt: fixture.clock.Now(), ExpiresAt: fixture.clock.Now().Add(time.Hour), CreatedAt: fixture.clock.Now(), UpdatedAt: fixture.clock.Now()}
	if err := fixture.store.WithTx(context.Background(), func(tx *store.Tx) error { return tx.InsertDecision(context.Background(), existing) }); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.process(0, "panel-a", "192.0.2.17")
	if err == nil {
		t.Fatal("expected decision insert error")
	}
	if events := countEvents(t, fixture.store, "panel-a", "192.0.2.17", time.Time{}); events != 0 {
		t.Fatalf("event was not rolled back: %d", events)
	}
}

func TestEngineIsolatesSameIPAcrossSources(t *testing.T) {
	fixture := newFixture(t, 1)
	first, err := fixture.process(0, "panel-a", "192.0.2.18")
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.process(1, "panel-b", "192.0.2.18")
	if err != nil {
		t.Fatal(err)
	}
	if first.DecisionID == "" || second.DecisionID == "" || first.DecisionID == second.DecisionID {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	if decisions := countDecisions(t, fixture.store); decisions != 2 {
		t.Fatalf("decisions=%d", decisions)
	}
}

type fixture struct {
	store  *store.Store
	clock  *clock.Fake
	policy model.Policy
	engine *Engine
}

func newFixture(t *testing.T, threshold uint32) *fixture {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	fake := &clock.Fake{Current: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
	policy := model.Policy{ID: "admin-login", Enabled: true, EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin, Threshold: threshold, Window: 10 * time.Minute, BaseDuration: 30 * time.Minute, EscalationFactor: 4, MaxDuration: 24 * time.Hour, ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication}
	return &fixture{store: db, clock: fake, policy: policy, engine: New(db, fake, []model.Policy{policy})}
}
func (f *fixture) process(index int, sourceID, ip string) (Result, error) {
	identity := sourceauth.Identity{SourceID: sourceID}
	event := model.Event{SourceID: sourceID, EventID: sourceID + "-event-" + time.Unix(int64(index), 0).UTC().Format("150405.000000000"), EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin, IP: netip.MustParseAddr(ip), OccurredAt: f.clock.Now(), ReceivedAt: f.clock.Now()}
	return f.engine.Process(context.Background(), identity, event)
}

func countDecisions(t *testing.T, database *store.Store) int {
	t.Helper()
	page, err := database.ListDecisions(context.Background(), store.DecisionFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Items)
}

func countEvents(t *testing.T, database *store.Store, sourceID, ip string, since time.Time) int {
	t.Helper()
	var count int
	err := database.WithTx(context.Background(), func(tx *store.Tx) error {
		var err error
		count, err = tx.CountEvents(context.Background(), sourceID, model.EventAuthFailed, model.ScopeAdminLogin, netip.MustParseAddr(ip), since)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
}
