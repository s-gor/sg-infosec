package enforcerclient

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

func unixServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enforcer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close(); listener.Close(); os.Remove(path) })
	return path
}

func TestActionResponseOKFalseIsErrorAndOptionalFieldsAreAccepted(t *testing.T) {
	socket := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "future_optional": "value"})
	}))
	client := New(socket)
	if err := client.Ensure(context.Background(), "test-1"); err == nil || !strings.Contains(err.Error(), "ok=false") {
		t.Fatalf("err=%v", err)
	}
}

func TestListAcceptsAdditiveOptionalFields(t *testing.T) {
	socket := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"entries": []any{}, "future_optional": true})
	}))
	client := New(socket)
	if _, err := client.List(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsDoNotExposeSocketPathOrRequestBody(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "secret-token.sock")
	client := New(socket)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := client.Add(ctx, "request", enforcerprotocol.Entry{IP: "203.0.113.7"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), socket) || strings.Contains(err.Error(), "203.0.113.7") {
		t.Fatalf("secret leaked: %v", err)
	}
}
