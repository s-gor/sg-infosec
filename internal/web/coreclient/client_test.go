package coreclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	baseclient "github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type expectedRequest struct {
	method string
	path   string
	body   any
	reply  any
}

func TestServiceUsesExistingControlContract(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	expected := []expectedRequest{
		{method: http.MethodGet, path: "/v1/health", reply: map[string]any{"status": "ok"}},
		{method: http.MethodGet, path: "/v1/decisions?limit=5&scope=ssh&source_id=sg-infosec-web&state=active", reply: protocol.DecisionListResponse{}},
		{method: http.MethodPost, path: "/v1/decisions/manual", body: &protocol.ManualDecisionRequest{}, reply: protocol.DecisionView{ID: "decision-1"}},
		{method: http.MethodPost, path: "/v1/decisions/decision-1/revoke", reply: protocol.ActionResponse{Changed: true}},
		{method: http.MethodGet, path: "/v1/allowlist?limit=5", reply: protocol.AllowlistListResponse{}},
		{method: http.MethodPost, path: "/v1/allowlist", body: &protocol.AllowlistCreateRequest{}, reply: protocol.AllowlistView{ID: "allow-1"}},
		{method: http.MethodDelete, path: "/v1/allowlist/allow-1", reply: protocol.ActionResponse{Changed: true}},
		{method: http.MethodGet, path: "/v1/audit?limit=5", reply: protocol.AuditListResponse{}},
	}
	var mu sync.Mutex
	index := 0
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if index >= len(expected) {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		want := expected[index]
		index++
		if r.Method != want.method || r.URL.RequestURI() != want.path {
			t.Errorf("request=%s %s want=%s %s", r.Method, r.URL.RequestURI(), want.method, want.path)
		}
		if want.body != nil {
			if err := json.NewDecoder(r.Body).Decode(want.body); err != nil {
				t.Errorf("decode request: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(want.reply); err != nil {
			t.Errorf("encode reply: %v", err)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())

	service := New(socket)
	ctx := context.Background()
	if health, err := service.Health(ctx); err != nil || health.Status != "ok" {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	if _, err := service.ListDecisions(ctx, baseclient.ListOptions{Limit: 5, SourceID: "sg-infosec-web", Scope: "ssh", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddDecision(ctx, protocol.ManualDecisionRequest{SourceID: "sg-infosec-web", Scope: "ssh", IP: "192.0.2.1", Duration: "1h", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeDecision(ctx, "decision-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListAllowlist(ctx, baseclient.ListOptions{Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AddAllowlist(ctx, protocol.AllowlistCreateRequest{Prefix: "192.0.2.0/24", Description: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RemoveAllowlist(ctx, "allow-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListAudit(ctx, baseclient.ListOptions{Limit: 5}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if index != len(expected) {
		t.Fatalf("received %d requests, want %d", index, len(expected))
	}
}

func TestNewWithMissingSocketReturnsUnavailable(t *testing.T) {
	service := New(filepath.Join(t.TempDir(), "missing.sock"))
	_, err := service.Health(context.Background())
	if !baseclient.IsUnavailable(err) {
		t.Fatalf("error=%v", err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
