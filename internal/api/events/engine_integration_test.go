//go:build cgo

package events

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestProcessorReturnsDecisionIDAtThresholdAndDuplicateDoesNotReevaluate(t *testing.T) {
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fakeClock := &clock.Fake{Current: now}
	policy := model.Policy{
		ID: "p", Enabled: true, EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin,
		Threshold: 2, Window: 10 * time.Minute, BaseDuration: 30 * time.Minute,
		EscalationFactor: 4, MaxDuration: 24 * time.Hour,
		ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication,
	}
	processor := NewProcessor(database, fakeClock, policy)
	identity := sourceauth.Identity{
		SourceID:      "panel",
		AllowedEvents: map[model.EventType]struct{}{model.EventAuthFailed: {}},
		AllowedScopes: map[model.Scope]struct{}{model.ScopeAdminLogin: {}},
	}
	request := func(id string) protocol.EventRequest {
		return protocol.EventRequest{
			EventID: id, EventType: "auth.failed", Scope: "admin-login",
			IP: "192.0.2.90", OccurredAt: now,
		}
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
	duplicate, err := processor.Process(context.Background(), identity, request("two"))
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate.Duplicate || duplicate.DecisionID != "" {
		t.Fatalf("duplicate=%+v", duplicate)
	}
	page, err := database.ListDecisions(context.Background(), store.DecisionFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("decisions=%d", len(page.Items))
	}
}
