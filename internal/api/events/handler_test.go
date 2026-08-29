//go:build cgo

package events

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestPostEventAcceptsAuthorizedIPv4Event(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := fixture.post(t, validRequest("event-v4", "192.0.2.10"), fixture.identity)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	var body protocol.EventResponse
	decodeBody(t, response, &body)
	if !body.Accepted || body.Duplicate || body.RequestID == "" {
		t.Fatalf("response = %#v", body)
	}
}

func TestPostEventAcceptsAuthorizedIPv6Event(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := fixture.post(t, validRequest("event-v6", "2001:0db8:0:0:0:0:0:10"), fixture.identity)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", response.Code, response.Body.String())
	}
	var body protocol.EventResponse
	decodeBody(t, response, &body)
	if !body.Accepted || body.Duplicate {
		t.Fatalf("response = %#v", body)
	}
}

func TestPostEventReturnsSameResultForDuplicateEventID(t *testing.T) {
	fixture := newHandlerFixture(t)
	request := validRequest("duplicate-event", "192.0.2.20")
	first := fixture.post(t, request, fixture.identity)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status = %d; body=%s", first.Code, first.Body.String())
	}
	second := fixture.post(t, request, fixture.identity)
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200; body=%s", second.Code, second.Body.String())
	}
	var body protocol.EventResponse
	decodeBody(t, second, &body)
	if !body.Accepted || !body.Duplicate {
		t.Fatalf("response = %#v", body)
	}
}

func TestPostEventRejectsUnknownJSONField(t *testing.T) {
	fixture := newHandlerFixture(t)
	raw := []byte(`{"event_id":"unknown-field","event_type":"auth.failed","scope":"admin-login","ip":"192.0.2.30","occurred_at":"2026-08-29T12:00:00Z","unexpected":true}`)
	response := fixture.postRaw(t, raw, fixture.identity)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestPostEventRejectsOversizedBody(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.handler = NewHandler(fixture.processor, 128)
	request := validRequest("oversized", "192.0.2.40")
	request.Metadata = map[string]any{"note": strings.Repeat("x", 512)}
	response := fixture.post(t, request, fixture.identity)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", response.Code, response.Body.String())
	}
}

func TestPostEventRejectsDisallowedEventTypeBeforeWritingDatabase(t *testing.T) {
	fixture := newHandlerFixture(t)
	request := validRequest("not-written", "192.0.2.50")
	request.EventType = "auth.succeeded"
	denied := fixture.post(t, request, fixture.identity)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403; body=%s", denied.Code, denied.Body.String())
	}

	request.EventType = "auth.failed"
	allowed := fixture.post(t, request, fixture.identity)
	if allowed.Code != http.StatusAccepted {
		t.Fatalf("allowed status = %d, want 202; body=%s", allowed.Code, allowed.Body.String())
	}
	var body protocol.EventResponse
	decodeBody(t, allowed, &body)
	if body.Duplicate {
		t.Fatal("disallowed event was written before authorization")
	}
}

func TestPostEventRejectsMetadataContainingSensitiveKeys(t *testing.T) {
	fixture := newHandlerFixture(t)
	for _, key := range []string{"password", "PassWd", "token", "authorization", "cookie", "private_key", "subscription_url", "config"} {
		request := validRequest("secret-"+strings.ReplaceAll(key, "_", "-"), "192.0.2.60")
		request.Metadata = map[string]any{"nested": map[string]any{key: "secret"}}
		response := fixture.post(t, request, fixture.identity)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("key %q status = %d, want 400; body=%s", key, response.Code, response.Body.String())
		}
	}
}

func TestPostEventUsesServerReceivedAtForPolicyTime(t *testing.T) {
	fixture := newHandlerFixture(t)
	request := validRequest("server-time", "192.0.2.70")
	request.OccurredAt = fixture.now.Add(-24 * time.Hour)
	response := fixture.post(t, request, fixture.identity)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}

	err := fixture.store.WithTx(context.Background(), func(tx *store.Tx) error {
		count, err := tx.CountEvents(context.Background(), fixture.identity.SourceID, model.EventAuthFailed, model.ScopeAdminLogin, netip.MustParseAddr("192.0.2.70"), fixture.now.Add(-time.Second))
		if err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("recent event count = %d, want 1", count)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostEventRejectsMissingPeerIdentity(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := fixture.post(t, validRequest("missing-identity", "192.0.2.80"), sourceauth.Identity{})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", response.Code, response.Body.String())
	}
}

func TestPostEventRejectsSecondJSONValue(t *testing.T) {
	fixture := newHandlerFixture(t)
	first, err := json.Marshal(validRequest("two-values", "192.0.2.90"))
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.postRaw(t, append(first, []byte(` {}`)...), fixture.identity)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

type handlerFixture struct {
	handler   http.Handler
	processor *Processor
	store     *store.Store
	identity  sourceauth.Identity
	now       time.Time
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fakeClock := &clock.Fake{Current: now}
	processor := NewProcessor(database, fakeClock)
	identity := sourceauth.Identity{
		SourceID: "sg-gateway", UID: 1001,
		AllowedEvents: map[model.EventType]struct{}{model.EventAuthFailed: {}},
		AllowedScopes: map[model.Scope]struct{}{model.ScopeAdminLogin: {}},
		Permissions:   map[config.Permission]struct{}{config.PermissionCheckDecisions: {}},
	}
	return &handlerFixture{
		handler: NewHandler(processor, 16*1024), processor: processor, store: database,
		identity: identity, now: now,
	}
}

func (f *handlerFixture) post(t *testing.T, body protocol.EventRequest, identity sourceauth.Identity) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return f.postRaw(t, data, identity)
}

func (f *handlerFixture) postRaw(t *testing.T, data []byte, identity sourceauth.Identity) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if identity.SourceID != "" {
		request = request.WithContext(sourceauth.WithIdentity(request.Context(), identity))
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func validRequest(eventID, ip string) protocol.EventRequest {
	return protocol.EventRequest{
		EventID: eventID, EventType: "auth.failed", Scope: "admin-login", IP: ip,
		Subject: "admin", OccurredAt: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
		Metadata: map[string]any{"reason": "invalid_password"},
	}
}

func decodeBody(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode body: %v; body=%s", err, response.Body.String())
	}
}

func TestPostEventRejectsOccurredAtMoreThanFiveMinutesInFuture(t *testing.T) {
	fixture := newHandlerFixture(t)
	request := validRequest("future-event", "192.0.2.100")
	request.OccurredAt = fixture.now.Add(5*time.Minute + time.Nanosecond)
	response := fixture.post(t, request, fixture.identity)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestPostEventRejectsMetadataLargerThanEightKiBWithinBodyLimit(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.handler = NewHandler(fixture.processor, 32*1024)
	request := validRequest("large-metadata", "192.0.2.101")
	request.Metadata = map[string]any{"note": strings.Repeat("x", 9*1024)}
	response := fixture.post(t, request, fixture.identity)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	var body protocol.ErrorResponse
	decodeBody(t, response, &body)
	if body.Code != "metadata_too_large" {
		t.Fatalf("error code = %q, want metadata_too_large", body.Code)
	}
}

func TestPostEventPreservesValidRequestID(t *testing.T) {
	fixture := newHandlerFixture(t)
	data, err := json.Marshal(validRequest("request-id", "192.0.2.102"))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "gateway.request-123")
	request = request.WithContext(sourceauth.WithIdentity(request.Context(), fixture.identity))
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	var body protocol.EventResponse
	decodeBody(t, response, &body)
	if body.RequestID != "gateway.request-123" {
		t.Fatalf("request_id = %q", body.RequestID)
	}
}
