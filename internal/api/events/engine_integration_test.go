//go:build cgo

package events

import (
	"context"
	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessorReturnsDecisionIDAtThresholdAndDuplicateDoesNotReevaluate(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fake := &clock.Fake{Current: now}
	policy := model.Policy{ID: "p", Enabled: true, EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin, Threshold: 2, Window: 10 * time.Minute, BaseDuration: 30 * time.Minute, EscalationFactor: 4, MaxDuration: 24 * time.Hour, ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication}
	notifier := &testNotifier{}
	processor := NewProcessor(db, fake, policy).WithDecisionNotifier(notifier)
	identity := sourceauth.Identity{SourceID: "panel", AllowedEvents: map[model.EventType]struct{}{model.EventAuthFailed: {}}, AllowedScopes: map[model.Scope]struct{}{model.ScopeAdminLogin: {}}}
	request := func(id string) protocol.EventRequest {
		return protocol.EventRequest{EventID: id, EventType: "auth.failed", Scope: "admin-login", IP: "192.0.2.90", OccurredAt: now}
	}
	first, err := processor.Process(context.Background(), identity, request("one"))
	if err != nil {
		t.Fatal(err)
	}
	if first.DecisionID != "" || first.Duplicate {
		t.Fatalf("first=%+v", first)
	}
	second, err := processor.Process(context.Background(), identity, request("two"))
	if err != nil {
		t.Fatal(err)
	}
	if second.DecisionID == "" || second.Duplicate {
		t.Fatalf("second=%+v", second)
	}
	if notifier.triggers != 1 {
		t.Fatalf("triggers=%d", notifier.triggers)
	}
	duplicate, err := processor.Process(context.Background(), identity, request("two"))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.DecisionID != "" {
		t.Fatalf("duplicate=%+v", duplicate)
	}
	if notifier.triggers != 1 {
		t.Fatalf("duplicate retriggered notifier: %d", notifier.triggers)
	}
	page, err := db.ListDecisions(context.Background(), store.DecisionFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("decisions=%d", len(page.Items))
	}
}

type testNotifier struct{ triggers int }

func (n *testNotifier) Trigger() { n.triggers++ }
