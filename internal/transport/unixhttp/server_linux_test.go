//go:build linux

package unixhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
)

func TestUnixServerPlacesPeerIdentityInRequestContext(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	uid := uint32(os.Getuid())
	resolver, err := sourceauth.NewResolver([]config.Source{{
		ID: "test-source", UID: uid,
		AllowedEvents: map[model.EventType]struct{}{model.EventAuthFailed: {}},
		AllowedScopes: map[model.Scope]struct{}{model.ScopeAdminLogin: {}},
	}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	seen := make(chan sourceauth.Identity, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := sourceauth.IdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "missing identity", http.StatusUnauthorized)
			return
		}
		seen <- identity
		w.WriteHeader(http.StatusNoContent)
	})

	server, err := New(Config{SocketPath: socketPath, Mode: 0o660, ExpectedOwnerUID: uid}, handler, resolver)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-serveDone; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}}
	request, err := http.NewRequest(http.MethodGet, "http://unix/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}

	select {
	case identity := <-seen:
		if identity.UID != uid || identity.SourceID != "test-source" {
			t.Fatalf("identity = %#v", identity)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not observe peer identity")
	}
}

func TestUnixServerRemovesStaleSocketOnlyWhenItIsASocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	address, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	resolver, err := sourceauth.NewResolver([]config.Source{{ID: "test", UID: uint32(os.Getuid())}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{SocketPath: socketPath, Mode: 0o660, ExpectedOwnerUID: uint32(os.Getuid())}, http.NotFoundHandler(), resolver)
	if err != nil {
		t.Fatalf("New with stale socket: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket remains after Close: %v", err)
	}
}

func TestUnixServerRefusesToReplaceRegularFile(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	if err := os.WriteFile(socketPath, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := sourceauth.NewResolver([]config.Source{{ID: "test", UID: uint32(os.Getuid())}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(Config{SocketPath: socketPath, Mode: 0o660, ExpectedOwnerUID: uint32(os.Getuid())}, http.NotFoundHandler(), resolver)
	if err == nil || !strings.Contains(err.Error(), "not a Unix socket") {
		t.Fatalf("New error = %v, want regular-file refusal", err)
	}
	data, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "do not replace" {
		t.Fatalf("regular file content changed: %q", data)
	}
}

func TestUnixServerRefusesSymlinkSocketPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	socketPath := filepath.Join(dir, "events.sock")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, socketPath); err != nil {
		t.Fatal(err)
	}
	resolver, err := sourceauth.NewResolver([]config.Source{{ID: "test", UID: uint32(os.Getuid())}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(Config{SocketPath: socketPath, Mode: 0o660, ExpectedOwnerUID: uint32(os.Getuid())}, http.NotFoundHandler(), resolver)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("New error = %v, want symlink refusal", err)
	}
}

func TestUnixServerRejectsSocketOwnerMismatchAfterBind(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	actualUID := uint32(os.Getuid())
	resolver, err := sourceauth.NewResolver([]config.Source{{ID: "test", UID: actualUID}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = New(Config{SocketPath: socketPath, Mode: 0o660, ExpectedOwnerUID: actualUID + 1}, http.NotFoundHandler(), resolver)
	if err == nil || !strings.Contains(err.Error(), "owned by UID") {
		t.Fatalf("New error = %v, want owner mismatch", err)
	}
	if _, statErr := os.Lstat(socketPath); !os.IsNotExist(statErr) {
		t.Fatalf("socket remains after owner mismatch: %v", statErr)
	}
}
