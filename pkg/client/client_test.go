package client

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestClientUsesUnixSocketAndNeverFallsBackToTCP(t *testing.T) {
	var proxyHits atomic.Int32
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	proxyServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy must not be used", http.StatusBadGateway)
	})}
	go proxyServer.Serve(proxyListener)
	defer proxyServer.Close()
	t.Setenv("HTTP_PROXY", "http://"+proxyListener.Addr().String())
	t.Setenv("HTTPS_PROXY", "http://"+proxyListener.Addr().String())

	socketPath := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/check" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"blocked":false}`))
	})}
	go server.Serve(listener)
	defer server.Close()

	got, err := New(socketPath).CheckDecision(context.Background(), protocol.DecisionCheckRequest{
		Scope: "admin-login", IP: "192.0.2.10", RouteID: "admin.login",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Blocked {
		t.Fatalf("response = %+v", got)
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("proxy hits = %d, want 0", proxyHits.Load())
	}
}

func TestClientEnforcesTwoSecondDefaultTimeout(t *testing.T) {
	got := New(filepath.Join(t.TempDir(), "control.sock"))
	if got.httpClient.Timeout != 2*time.Second {
		t.Fatalf("timeout = %v, want 2s", got.httpClient.Timeout)
	}
}

func TestClientClassifiesMissingSocketAsUnavailable(t *testing.T) {
	_, err := New(filepath.Join(t.TempDir(), "missing.sock")).Health(context.Background())
	if err == nil || !IsUnavailable(err) {
		t.Fatalf("error = %v, want unavailable", err)
	}
}

func TestClientErrorNeverIncludesSensitiveRequestBody(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"invalid_manual_decision","message":"manual decision is invalid","request_id":"test"}`))
	})}
	go server.Serve(listener)
	defer server.Close()

	const secret = "DO-NOT-LEAK-THIS-REASON"
	_, err = New(socketPath).AddDecision(context.Background(), protocol.ManualDecisionRequest{
		SourceID: "panel", Scope: "admin-login", IP: "192.0.2.1", Duration: "30m", Reason: secret,
	})
	if err == nil {
		t.Fatal("expected API error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked request body: %v", err)
	}
}

func TestClientRejectsPathLikeResourceIDsBeforeDialing(t *testing.T) {
	client := New(filepath.Join(t.TempDir(), "missing.sock"))
	if _, err := client.RevokeDecision(context.Background(), "../decision"); err == nil || IsUnavailable(err) {
		t.Fatalf("revoke error = %v, want local validation error", err)
	}
	if _, err := client.RemoveAllowlist(context.Background(), "folder/entry"); err == nil || IsUnavailable(err) {
		t.Fatalf("remove error = %v, want local validation error", err)
	}
}

func TestClientReconcileNFTUsesCoreControlRoute(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/nft/reconcile" {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"changed":true,"request_id":"server-request"}`))
	})}
	go server.Serve(listener)
	defer server.Close()

	response, err := New(socketPath).ReconcileNFT(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !response.Changed || response.RequestID != "server-request" {
		t.Fatalf("response=%+v", response)
	}
}
