package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/web/auth"
	"github.com/s-gor/sg-infosec/internal/web/coreclient"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type fakeCore struct{}

func (fakeCore) Health(context.Context) (coreclient.HealthResponse, error) {
	return coreclient.HealthResponse{Status: "ok", Database: "ok", ActiveDecisions: 2}, nil
}
func (fakeCore) ListDecisions(context.Context, coreclient.ListOptions) (protocol.DecisionListResponse, error) {
	return protocol.DecisionListResponse{}, nil
}
func (fakeCore) AddDecision(context.Context, protocol.ManualDecisionRequest) (protocol.DecisionView, error) {
	return protocol.DecisionView{}, nil
}
func (fakeCore) RevokeDecision(context.Context, string) (protocol.ActionResponse, error) {
	return protocol.ActionResponse{Changed: true}, nil
}
func (fakeCore) ListAllowlist(context.Context, coreclient.ListOptions) (protocol.AllowlistListResponse, error) {
	return protocol.AllowlistListResponse{}, nil
}
func (fakeCore) AddAllowlist(context.Context, protocol.AllowlistCreateRequest) (protocol.AllowlistView, error) {
	return protocol.AllowlistView{}, nil
}
func (fakeCore) RemoveAllowlist(context.Context, string) (protocol.ActionResponse, error) {
	return protocol.ActionResponse{Changed: true}, nil
}
func (fakeCore) ListAudit(context.Context, coreclient.ListOptions) (protocol.AuditListResponse, error) {
	return protocol.AuditListResponse{}, nil
}

func TestStandaloneWebSetupLoginAndDashboard(t *testing.T) {
	store, err := auth.Open(t.TempDir()+"/auth.json", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssueSetupCode(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{BasePath: "/infosec/", SessionTTL: time.Hour}, store, fakeCore{})
	if err != nil {
		t.Fatal(err)
	}

	setup := formRequest(t, handler, "/infosec/setup", url.Values{
		"setup_code": {code},
		"username":   {"admin"},
		"password":   {"correct horse battery staple"},
	})
	if setup.Code != http.StatusSeeOther {
		t.Fatalf("setup status=%d body=%s", setup.Code, setup.Body.String())
	}

	login := formRequest(t, handler, "/infosec/login", url.Values{
		"username": {"admin"},
		"password": {"correct horse battery staple"},
	})
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie: %#v", cookies)
	}

	req := httptest.NewRequest(http.MethodGet, "/infosec/", nil)
	req.AddCookie(cookies[0])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d body=%s", response.Code, response.Body.String())
	}
	body, _ := io.ReadAll(response.Result().Body)
	for _, text := range []string{"SG InfoSec", "Состояние защиты", "Активные блокировки", "2"} {
		if !strings.Contains(string(body), text) {
			t.Fatalf("dashboard missing %q: %s", text, body)
		}
	}
}

func TestProtectedRoutesRequireSession(t *testing.T) {
	store, err := auth.Open(t.TempDir()+"/auth.json", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ResetAdmin("admin", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{BasePath: "/infosec/", SessionTTL: time.Hour}, store, fakeCore{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/infosec/", "/infosec/decisions", "/infosec/allowlist", "/infosec/audit"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/infosec/login" {
			t.Fatalf("%s status=%d location=%q", path, response.Code, response.Header().Get("Location"))
		}
	}
}

func formRequest(t *testing.T, handler http.Handler, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
