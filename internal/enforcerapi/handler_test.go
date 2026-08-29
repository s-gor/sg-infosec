package enforcerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

func TestEnsureRequiresStrictJSONAndSchemaVersion(t *testing.T) {
	service := &fakeService{}
	handler := New(service, 1024)

	response := request(t, handler, http.MethodPost, "/v1/ensure", `{"request_id":"req.1","schema_version":1}`, "application/json")
	if response.Code != http.StatusOK || service.ensureID != "req.1" {
		t.Fatalf("code=%d body=%s ensureID=%q", response.Code, response.Body.String(), service.ensureID)
	}

	for _, body := range []string{
		`{"request_id":"req.2","schema_version":2}`,
		`{"request_id":"req.2","schema_version":1,"extra":true}`,
		`{"request_id":"req.2","schema_version":1}{}`,
	} {
		response = request(t, handler, http.MethodPost, "/v1/ensure", body, "application/json")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s code=%d response=%s", body, response.Code, response.Body.String())
		}
	}
}

func TestHandlerMapsAllTypedCommands(t *testing.T) {
	now := time.Date(2026, 8, 29, 17, 0, 0, 0, time.UTC)
	service := &fakeService{
		listEntries: []enforcer.Entry{{
			Key:       enforcer.Key{Scope: "ssh", Protocol: "tcp", Port: 22, IP: mustAddr(t, "203.0.113.7")},
			ExpiresAt: now.Add(time.Hour),
		}},
		report: enforcer.ReconcileReport{Created: 1, Removed: 2},
	}
	handler := New(service, 64*1024)

	entryJSON := `{"scope":"ssh","protocol":"tcp","port":22,"ip":"203.0.113.7","expires_at":"2026-08-29T18:00:00Z"}`
	response := request(t, handler, http.MethodPost, "/v1/add", `{"request_id":"req.add","entry":`+entryJSON+`}`, "application/json")
	if response.Code != http.StatusOK || service.addID != "req.add" || service.addEntry.IP != "203.0.113.7" {
		t.Fatalf("add code=%d body=%s service=%+v", response.Code, response.Body.String(), service)
	}

	response = request(t, handler, http.MethodPost, "/v1/remove", `{"request_id":"req.remove","key":{"scope":"ssh","protocol":"tcp","port":22,"ip":"203.0.113.7"}}`, "application/json")
	if response.Code != http.StatusOK || service.removeID != "req.remove" || service.removeKey.IP != "203.0.113.7" {
		t.Fatalf("remove code=%d body=%s service=%+v", response.Code, response.Body.String(), service)
	}

	response = request(t, handler, http.MethodGet, "/v1/list", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("list code=%d body=%s", response.Code, response.Body.String())
	}
	var listed enforcerprotocol.ListResponse
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Entries) != 1 || listed.Entries[0].IP != "203.0.113.7" {
		t.Fatalf("list=%+v", listed)
	}

	response = request(t, handler, http.MethodPost, "/v1/reconcile", `{"request_id":"req.reconcile","entries":[`+entryJSON+`]}`, "application/json")
	if response.Code != http.StatusOK || service.reconcileID != "req.reconcile" || len(service.reconcileEntries) != 1 {
		t.Fatalf("reconcile code=%d body=%s service=%+v", response.Code, response.Body.String(), service)
	}
	var report enforcerprotocol.ReconcileResponse
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Created != 1 || report.Removed != 2 {
		t.Fatalf("report=%+v", report)
	}
}

func TestHandlerRejectsWrongMethodMediaTypeBodyAndRoute(t *testing.T) {
	handler := New(&fakeService{}, 32)
	cases := []struct {
		method, path, body, media string
		status                    int
	}{
		{http.MethodGet, "/v1/add", "", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/add", `{}`, "text/plain", http.StatusUnsupportedMediaType},
		{http.MethodPost, "/v1/add", `{"request_id":"` + string(bytes.Repeat([]byte("a"), 64)) + `"}`, "application/json", http.StatusRequestEntityTooLarge},
		{http.MethodPost, "/unknown", `{}`, "application/json", http.StatusNotFound},
	}
	for _, item := range cases {
		response := request(t, handler, item.method, item.path, item.body, item.media)
		if response.Code != item.status {
			t.Fatalf("%s %s code=%d want=%d body=%s", item.method, item.path, response.Code, item.status, response.Body.String())
		}
	}
}

func TestHandlerDoesNotExposeBackendErrors(t *testing.T) {
	handler := New(&fakeService{err: errors.New("nft secret detail")}, 1024)
	response := request(t, handler, http.MethodPost, "/v1/ensure", `{"request_id":"req.1","schema_version":1}`, "application/json")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("secret")) {
		t.Fatalf("backend error leaked: %s", response.Body.String())
	}
}

func TestHandlerMapsValidationErrorsWithoutCallingBackendDetails(t *testing.T) {
	handler := New(&fakeService{err: enforcer.ErrUnsupportedTarget}, 1024)
	response := request(t, handler, http.MethodPost, "/v1/add", `{"request_id":"req.1","entry":{"scope":"admin-login","protocol":"tcp","port":443,"ip":"203.0.113.7","expires_at":"2026-08-29T18:00:00Z"}}`, "application/json")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	var failure enforcerprotocol.ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Code != "unsupported_target" {
		t.Fatalf("failure=%+v", failure)
	}
}

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func request(t *testing.T, handler http.Handler, method, path, body, media string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if media != "" {
		req.Header.Set("Content-Type", media)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

type fakeService struct {
	ensureID         string
	addID            string
	addEntry         enforcerprotocol.Entry
	removeID         string
	removeKey        enforcerprotocol.Key
	reconcileID      string
	reconcileEntries []enforcerprotocol.Entry
	listEntries      []enforcer.Entry
	report           enforcer.ReconcileReport
	err              error
}

func (f *fakeService) Ensure(_ context.Context, requestID string) error {
	f.ensureID = requestID
	return f.err
}
func (f *fakeService) Add(_ context.Context, requestID string, entry enforcerprotocol.Entry) error {
	f.addID, f.addEntry = requestID, entry
	return f.err
}
func (f *fakeService) Remove(_ context.Context, requestID string, key enforcerprotocol.Key) error {
	f.removeID, f.removeKey = requestID, key
	return f.err
}
func (f *fakeService) List(context.Context) ([]enforcer.Entry, error) { return f.listEntries, f.err }
func (f *fakeService) Reconcile(_ context.Context, requestID string, entries []enforcerprotocol.Entry) (enforcer.ReconcileReport, error) {
	f.reconcileID, f.reconcileEntries = requestID, entries
	return f.report, f.err
}
