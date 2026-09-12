//go:build cgo

package control

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestEventListRequiresReadAdminAndAppliesFilters(t *testing.T) {
	fixture := newControlFixture(t)
	seedSOCEvent(t, fixture, "ssh", "ssh-old", model.EventAuthFailed, model.ScopeSSH, "198.51.100.10", fixture.now.Add(-2*time.Hour))
	seedSOCEvent(t, fixture, "ssh", "ssh-new", model.EventAuthFailed, model.ScopeSSH, "198.51.100.11", fixture.now.Add(-10*time.Minute))
	seedSOCEvent(t, fixture, "panel-a", "panel-new", model.EventAuthFailed, model.ScopeAdminLogin, "203.0.113.20", fixture.now.Add(-5*time.Minute))

	denied := fixture.request(t, http.MethodGet, "/v1/events", nil, fixture.checker)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}
	since := fixture.now.Add(-time.Hour).Format(time.RFC3339)
	path := "/v1/events?limit=20&scope=ssh&event_type=auth.failed&since=" + url.QueryEscape(since)
	response := fixture.request(t, http.MethodGet, path, nil, fixture.reader)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body protocol.EventListResponse
	decodeJSON(t, response, &body)
	if len(body.Items) != 1 || body.Items[0].EventID != "ssh-new" || body.Items[0].IP != "198.51.100.11" {
		t.Fatalf("items=%#v", body.Items)
	}
}

func TestEventListRejectsInvalidEventType(t *testing.T) {
	fixture := newControlFixture(t)
	response := fixture.request(t, http.MethodGet, "/v1/events?event_type=unknown", nil, fixture.reader)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestOverviewReturnsExactWindowSummary(t *testing.T) {
	fixture := newControlFixture(t)
	seedSOCEvent(t, fixture, "ssh", "ssh-1", model.EventAuthFailed, model.ScopeSSH, "198.51.100.10", fixture.now.Add(-50*time.Minute))
	seedSOCEvent(t, fixture, "ssh", "ssh-2", model.EventAuthFailed, model.ScopeSSH, "198.51.100.10", fixture.now.Add(-40*time.Minute))
	seedSOCEvent(t, fixture, "panel-a", "panel-1", model.EventAuthFailed, model.ScopeAdminLogin, "203.0.113.20", fixture.now.Add(-20*time.Minute))
	seedSOCEvent(t, fixture, "panel-a", "ok-1", model.EventAuthSucceeded, model.ScopeAdminLogin, "203.0.113.20", fixture.now.Add(-10*time.Minute))
	fixture.insertDecision(t, "active", "panel-a", "203.0.113.20", fixture.now.Add(time.Hour))
	response := fixture.request(t, http.MethodGet, "/v1/overview?window=1h", nil, fixture.reader)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body protocol.OverviewResponse
	decodeJSON(t, response, &body)
	if body.Window != "1h" || body.EventsTotal != 4 || body.FailedEvents != 3 || body.UniqueIPs != 2 || body.ActiveDecisions != 1 || body.AutomaticDecisions != 1 {
		t.Fatalf("overview=%+v", body)
	}
	if len(body.Hourly) != 2 {
		t.Fatalf("hourly=%d, want 2", len(body.Hourly))
	}
}

func TestOverviewRejectsInvalidWindowAndRequiresReadAdmin(t *testing.T) {
	fixture := newControlFixture(t)
	invalid := fixture.request(t, http.MethodGet, "/v1/overview?window=7d", nil, fixture.reader)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	denied := fixture.request(t, http.MethodGet, "/v1/overview?window=24h", nil, fixture.checker)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func seedSOCEvent(t *testing.T, fixture *controlFixture, sourceID, eventID string, eventType model.EventType, scope model.Scope, ip string, receivedAt time.Time) {
	t.Helper()
	event := model.Event{
		SourceID:   sourceID,
		EventID:    eventID,
		EventType:  eventType,
		Scope:      scope,
		IP:         netip.MustParseAddr(ip),
		Subject:    "subject",
		OccurredAt: receivedAt,
		ReceivedAt: receivedAt,
		Metadata:   map[string]any{"seed": true},
	}
	if err := fixture.database.WithTx(context.Background(), func(tx *store.Tx) error { _, err := tx.InsertEvent(context.Background(), event); return err }); err != nil {
		t.Fatal(err)
	}
}
