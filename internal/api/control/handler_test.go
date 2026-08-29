//go:build cgo

package control

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/s-gor/sg-infosec/internal/decision"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestDecisionCheckAllowsConfiguredMiddlewareSource(t *testing.T) {
	fixture := newControlFixture(t)
	fixture.insertDecision(t, "active", "panel-a", "192.0.2.10", fixture.now.Add(time.Hour))
	response := fixture.request(t, http.MethodPost, "/v1/decisions/check", map[string]any{
		"scope": "admin-login", "ip": "192.0.2.10", "route_id": "admin.login",
	}, fixture.checker)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Blocked    bool   `json:"blocked"`
		DecisionID string `json:"decision_id"`
	}
	decodeJSON(t, response, &body)
	if !body.Blocked || body.DecisionID != "active" {
		t.Fatalf("body=%+v", body)
	}
}

func TestDecisionCheckRejectsSourceWithoutPermission(t *testing.T) {
	fixture := newControlFixture(t)
	response := fixture.request(t, http.MethodPost, "/v1/decisions/check", map[string]any{
		"scope": "admin-login", "ip": "192.0.2.11", "route_id": "admin.login",
	}, sourceauth.Identity{SourceID: "panel-a"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDecisionCheckDoesNotCrossSourceBoundaryAndOmitsExpiryWhenAllowed(t *testing.T) {
	fixture := newControlFixture(t)
	fixture.insertDecision(t, "panel-a-only", "panel-a", "192.0.2.14", fixture.now.Add(time.Hour))
	panelB := identity("panel-b", config.PermissionCheckDecisions)
	response := fixture.request(t, http.MethodPost, "/v1/decisions/check", map[string]any{
		"scope": "admin-login", "ip": "192.0.2.14", "route_id": "admin.login",
	}, panelB)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	decodeJSON(t, response, &body)
	if blocked, _ := body["blocked"].(bool); blocked {
		t.Fatalf("body=%+v", body)
	}
	if _, exists := body["expires_at"]; exists {
		t.Fatalf("allowed response contains expires_at: %+v", body)
	}
}

func TestRevokeDecisionIsIdempotentAndAuditedOnce(t *testing.T) {
	fixture := newControlFixture(t)
	fixture.insertDecision(t, "revoke-once", "panel-a", "192.0.2.15", fixture.now.Add(time.Hour))
	first := fixture.requestWithID(t, http.MethodPost, "/v1/decisions/revoke-once/revoke", map[string]any{}, fixture.writer, "admin.req-first")
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var firstBody protocol.ActionResponse
	decodeJSON(t, first, &firstBody)
	if !firstBody.Changed {
		t.Fatalf("first body=%+v", firstBody)
	}
	second := fixture.requestWithID(t, http.MethodPost, "/v1/decisions/revoke-once/revoke", map[string]any{}, fixture.writer, "admin.req-second")
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	var secondBody protocol.ActionResponse
	decodeJSON(t, second, &secondBody)
	if secondBody.Changed {
		t.Fatalf("second body=%+v", secondBody)
	}
	page, err := fixture.database.ListAudit(context.Background(), store.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range page.Items {
		if entry.Action == "decision.revoked" && entry.TargetID == "revoke-once" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("revoke audit entries=%d, want 1", count)
	}
}

func TestManualDecisionRejectsDurationOverSevenDays(t *testing.T) {
	fixture := newControlFixture(t)
	response := fixture.request(t, http.MethodPost, "/v1/decisions/manual", map[string]any{
		"source_id": "panel-a", "scope": "admin-login", "ip": "192.0.2.16",
		"duration": "169h", "reason": "too long", "override_allowlist": false,
	}, fixture.writer)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestListDecisionsRequiresAdministrativePeer(t *testing.T) {
	fixture := newControlFixture(t)
	response := fixture.request(t, http.MethodGet, "/v1/decisions", nil, fixture.checker)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	response = fixture.request(t, http.MethodGet, "/v1/decisions", nil, fixture.reader)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestManualDecisionRequiresExplicitAllowlistOverride(t *testing.T) {
	fixture := newControlFixture(t)
	if err := fixture.database.PutAllowlistEntry(context.Background(), model.AllowlistEntry{
		ID: "office", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Description: "office",
		CreatedAt: fixture.now, CreatedBy: "test",
	}, "test", "seed"); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"source_id": "panel-a", "scope": "admin-login", "ip": "192.0.2.12",
		"duration": "30m", "reason": "incident response", "override_allowlist": false,
	}
	response := fixture.request(t, http.MethodPost, "/v1/decisions/manual", request, fixture.writer)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	request["override_allowlist"] = true
	response = fixture.request(t, http.MethodPost, "/v1/decisions/manual", request, fixture.writer)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRevokeDecisionWritesActorAndRequestIDToAudit(t *testing.T) {
	fixture := newControlFixture(t)
	fixture.insertDecision(t, "revoke-me", "panel-a", "192.0.2.13", fixture.now.Add(time.Hour))
	response := fixture.requestWithID(t, http.MethodPost, "/v1/decisions/revoke-me/revoke", map[string]any{}, fixture.writer, "admin.req-1")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	response = fixture.request(t, http.MethodGet, "/v1/audit", nil, fixture.reader)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"actor":"security-admin"`) || !strings.Contains(response.Body.String(), `"request_id":"admin.req-1"`) {
		t.Fatalf("audit=%s", response.Body.String())
	}
}

func TestAllowlistCreateNormalizesIPv4AndAcceptsIPv6CIDR(t *testing.T) {
	fixture := newControlFixture(t)
	for _, item := range []struct{ prefix, want string }{{"192.0.2.20", "192.0.2.20/32"}, {"2001:db8::/64", "2001:db8::/64"}} {
		response := fixture.request(t, http.MethodPost, "/v1/allowlist", map[string]any{
			"prefix": item.prefix, "scope": "admin-login", "description": "trusted admin",
		}, fixture.writer)
		if response.Code != http.StatusCreated {
			t.Fatalf("prefix=%s status=%d body=%s", item.prefix, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"prefix":"`+item.want+`"`) {
			t.Fatalf("body=%s", response.Body.String())
		}
	}
}

func TestAuditResponseNeverContainsInternalDetails(t *testing.T) {
	fixture := newControlFixture(t)
	err := fixture.database.WithTx(context.Background(), func(tx *store.Tx) error {
		return tx.AppendAudit(context.Background(), model.AuditEntry{
			OccurredAt: fixture.now, Actor: "test", Action: "test.action", TargetType: "test",
			TargetID: "1", RequestID: "req", Result: "success",
			Details: map[string]any{"token": "must-not-leak", "event_metadata": map[string]any{"password": "secret"}},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.request(t, http.MethodGet, "/v1/audit", nil, fixture.reader)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "must-not-leak") || strings.Contains(body, "password") || strings.Contains(body, "details") {
		t.Fatalf("audit leaked details: %s", body)
	}
}

type controlFixture struct {
	database *store.Store
	clock    *clock.Fake
	handler  http.Handler
	now      time.Time
	checker  sourceauth.Identity
	reader   sourceauth.Identity
	writer   sourceauth.Identity
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	database, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	fakeClock := &clock.Fake{Current: now}
	service := decision.NewService(database, fakeClock)
	fixture := &controlFixture{database: database, clock: fakeClock, now: now}
	fixture.handler = NewHandler(service, database, fakeClock, []string{"panel-a", "panel-b"}, 16*1024)
	fixture.checker = identity("panel-a", config.PermissionCheckDecisions)
	fixture.reader = identity("security-reader", config.PermissionReadAdmin)
	fixture.writer = identity("security-admin", config.PermissionWriteAdmin, config.PermissionReadAdmin)
	return fixture
}

func identity(sourceID string, permissions ...config.Permission) sourceauth.Identity {
	values := make(map[config.Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		values[permission] = struct{}{}
	}
	return sourceauth.Identity{SourceID: sourceID, Permissions: values}
}

func (f *controlFixture) insertDecision(t *testing.T, id, sourceID, ip string, expires time.Time) {
	t.Helper()
	err := f.database.WithTx(context.Background(), func(tx *store.Tx) error {
		return tx.InsertDecision(context.Background(), model.Decision{
			ID: id, SourceID: sourceID, PolicyID: "seed", Scope: model.ScopeAdminLogin,
			IP: netip.MustParseAddr(ip), Backend: model.BackendApplication, State: model.DecisionActive,
			ReasonCode: "threshold_exceeded", Strike: 1, StartsAt: f.now, ExpiresAt: expires,
			CreatedAt: f.now, UpdatedAt: f.now,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *controlFixture) request(t *testing.T, method, path string, body any, identity sourceauth.Identity) *httptest.ResponseRecorder {
	return f.requestWithID(t, method, path, body, identity, "")
}

func (f *controlFixture) requestWithID(t *testing.T, method, path string, body any, identity sourceauth.Identity, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if requestID != "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	request = request.WithContext(sourceauth.WithIdentity(request.Context(), identity))
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func decodeJSON(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode: %v body=%s", err, response.Body.String())
	}
}

func TestDecodeCursorRejectsTrailingJSONValue(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"at":"2026-08-29T13:00:00Z","id":"one"} {"id":"two"}`))
	var cursor decisionCursor
	if err := decodeCursor(encoded, &cursor); err == nil {
		t.Fatal("cursor with a second JSON value was accepted")
	}
}

func TestNFTReconcileRequiresWritePermissionAndInvokesWorker(t *testing.T) {
	fixture := newControlFixture(t)
	reconciler := &fakeNFTReconciler{}
	handler := NewHandler(decision.NewService(fixture.database, fixture.clock), fixture.database, fixture.clock, []string{"panel-a"}, 4096, reconciler)
	request := httptest.NewRequest(http.MethodPost, "/v1/nft/reconcile", nil)
	identity := sourceauth.Identity{SourceID: "admin", Permissions: map[config.Permission]struct{}{config.PermissionWriteAdmin: {}}}
	request = request.WithContext(sourceauth.WithIdentity(request.Context(), identity))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || reconciler.calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, reconciler.calls, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/nft/reconcile", nil)
	request = request.WithContext(sourceauth.WithIdentity(request.Context(), sourceauth.Identity{SourceID: "reader", Permissions: map[config.Permission]struct{}{config.PermissionReadAdmin: {}}}))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || reconciler.calls != 1 {
		t.Fatalf("status=%d calls=%d", response.Code, reconciler.calls)
	}
}

type fakeNFTReconciler struct {
	calls    int
	triggers int
	err      error
}

func (f *fakeNFTReconciler) SyncOnce(context.Context) error { f.calls++; return f.err }
func (f *fakeNFTReconciler) Trigger()                       { f.triggers++ }
