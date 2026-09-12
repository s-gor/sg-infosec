//go:build cgo

package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

func TestListEventsFiltersAndOrdersNewestFirst(t *testing.T) {
	database := openTestStore(t)
	now := time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)
	events := []model.Event{
		socEvent("ssh", "ssh-old", model.EventAuthFailed, model.ScopeSSH, "198.51.100.10", now.Add(-90*time.Minute)),
		socEvent("ssh", "ssh-new", model.EventAuthFailed, model.ScopeSSH, "198.51.100.11", now.Add(-5*time.Minute)),
		socEvent("nginx", "panel-new", model.EventAuthFailed, model.ScopeAdminLogin, "203.0.113.20", now.Add(-2*time.Minute)),
		socEvent("gateway", "api-new", model.EventAPIAuthFailed, model.ScopeAdminAPI, "203.0.113.21", now.Add(-time.Minute)),
	}
	if err := database.WithTx(context.Background(), func(tx *Tx) error {
		for _, event := range events {
			if _, err := tx.InsertEvent(context.Background(), event); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	since := now.Add(-time.Hour)
	page, err := database.ListEvents(context.Background(), EventFilter{
		Limit:     20,
		Scope:     model.ScopeSSH,
		EventType: model.EventAuthFailed,
		Since:     &since,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].EventID != "ssh-new" {
		t.Fatalf("filtered events = %#v", page.Items)
	}

	all, err := database.ListEvents(context.Background(), EventFilter{Limit: 20, Since: &since})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Items) != 3 {
		t.Fatalf("items=%d, want 3", len(all.Items))
	}
	if all.Items[0].EventID != "api-new" || all.Items[1].EventID != "panel-new" || all.Items[2].EventID != "ssh-new" {
		t.Fatalf("newest-first order = %#v", all.Items)
	}
}

func TestOverviewReturnsExactSOCCounts(t *testing.T) {
	database := openTestStore(t)
	now := time.Date(2026, 9, 12, 20, 30, 0, 0, time.UTC)
	events := []model.Event{
		socEvent("ssh", "ssh-1", model.EventAuthFailed, model.ScopeSSH, "198.51.100.10", now.Add(-50*time.Minute)),
		socEvent("ssh", "ssh-2", model.EventAuthFailed, model.ScopeSSH, "198.51.100.10", now.Add(-40*time.Minute)),
		socEvent("nginx", "panel-1", model.EventAuthFailed, model.ScopeAdminLogin, "203.0.113.20", now.Add(-20*time.Minute)),
		socEvent("gateway", "api-1", model.EventAPIAuthFailed, model.ScopeAdminAPI, "203.0.113.21", now.Add(-10*time.Minute)),
		socEvent("gateway", "ok-1", model.EventAuthSucceeded, model.ScopeAdminLogin, "203.0.113.21", now.Add(-5*time.Minute)),
		socEvent("ssh", "old", model.EventAuthFailed, model.ScopeSSH, "192.0.2.99", now.Add(-25*time.Hour)),
	}
	if err := database.WithTx(context.Background(), func(tx *Tx) error {
		for _, event := range events {
			if _, err := tx.InsertEvent(context.Background(), event); err != nil {
				return err
			}
		}
		return tx.InsertDecision(context.Background(), model.Decision{
			ID: "active-auto", SourceID: "ssh", PolicyID: "ssh-bruteforce", Scope: model.ScopeSSH,
			IP: netip.MustParseAddr("198.51.100.10"), Backend: model.BackendNFTables, State: model.DecisionActive,
			ReasonCode: "threshold_exceeded", Strike: 1, StartsAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(time.Hour),
			CreatedAt: now.Add(-10 * time.Minute), UpdatedAt: now.Add(-10 * time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := database.Overview(context.Background(), now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventsTotal != 5 {
		t.Fatalf("events_total=%d, want 5", summary.EventsTotal)
	}
	if summary.FailedEvents != 4 {
		t.Fatalf("failed_events=%d, want 4", summary.FailedEvents)
	}
	if summary.UniqueIPs != 3 {
		t.Fatalf("unique_ips=%d, want 3", summary.UniqueIPs)
	}
	if summary.ActiveDecisions != 1 || summary.AutomaticDecisions != 1 {
		t.Fatalf("decision counts=%d/%d, want 1/1", summary.ActiveDecisions, summary.AutomaticDecisions)
	}
	if countForKey(summary.ByScope, "ssh") != 2 || countForKey(summary.ByScope, "admin-login") != 2 || countForKey(summary.ByScope, "admin-api") != 1 {
		t.Fatalf("by_scope=%#v", summary.ByScope)
	}
	if countForKey(summary.ByEventType, "auth.failed") != 3 || countForKey(summary.ByEventType, "api.auth_failed") != 1 || countForKey(summary.ByEventType, "auth.succeeded") != 1 {
		t.Fatalf("by_event_type=%#v", summary.ByEventType)
	}
	if len(summary.Sources) != 3 {
		t.Fatalf("sources=%#v", summary.Sources)
	}
	if len(summary.Hourly) != 25 {
		t.Fatalf("hourly buckets=%d, want 25", len(summary.Hourly))
	}
}

func countForKey(values []OverviewBreakdown, key string) int64 {
	for _, value := range values {
		if value.Key == key {
			return value.Count
		}
	}
	return 0
}

func socEvent(sourceID, eventID string, eventType model.EventType, scope model.Scope, ip string, receivedAt time.Time) model.Event {
	return model.Event{
		SourceID: sourceID,
		EventID: eventID,
		EventType: eventType,
		Scope: scope,
		IP: netip.MustParseAddr(ip),
		Subject: "subject",
		OccurredAt: receivedAt,
		ReceivedAt: receivedAt,
		Metadata: map[string]any{"test": true},
	}
}
