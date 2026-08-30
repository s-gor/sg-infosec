//go:build linux && cgo

package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
)

func TestAppStartsBothSocketsAndServesHealth(t *testing.T) {
	cfg := testConfig(t)
	application, err := New(cfg, Dependencies{UID: uint32(os.Getuid()), RetentionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	waitSocket(t, cfg.EventsSocket)
	waitSocket(t, cfg.ControlSocket)
	response := unixGet(t, cfg.ControlSocket, "/v1/health")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if body["protocol_version"] != "v1" {
		t.Fatalf("body=%+v", body)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAppRefusesSecondInstanceUsingSameState(t *testing.T) {
	cfg := testConfig(t)
	first, err := New(cfg, Dependencies{UID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(cfg, Dependencies{UID: uint32(os.Getuid())})
	if err == nil {
		second.Close()
		t.Fatal("second instance was accepted")
	}
}

func TestAppShutdownClosesSocketsAndDatabase(t *testing.T) {
	cfg := testConfig(t)
	application, err := New(cfg, Dependencies{UID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	waitSocket(t, cfg.EventsSocket)
	waitSocket(t, cfg.ControlSocket)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{cfg.EventsSocket, cfg.ControlSocket} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("socket remains %s err=%v", path, err)
		}
	}
	if err := application.store.Ping(context.Background()); err == nil {
		t.Fatal("database remains open")
	}
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	uid := uint32(os.Getuid())
	return config.Config{
		DatabasePath:   filepath.Join(dir, "state.db"),
		EventsSocket:   filepath.Join(dir, "events.sock"),
		ControlSocket:  filepath.Join(dir, "control.sock"),
		EventBodyLimit: 16 * 1024,
		Retention:      config.EventRetention{Events: 24 * time.Hour, Audit: 30 * 24 * time.Hour},
		Sources: []config.Source{{
			ID: "test-source", UID: uid,
			AllowedEvents: map[model.EventType]struct{}{model.EventAuthFailed: {}},
			AllowedScopes: map[model.Scope]struct{}{model.ScopeAdminLogin: {}},
			Permissions: map[config.Permission]struct{}{
				config.PermissionCheckDecisions: {}, config.PermissionReadAdmin: {}, config.PermissionWriteAdmin: {},
			},
		}},
		Policies: []model.Policy{{
			ID: "p", Enabled: true, EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin,
			Threshold: 5, Window: 10 * time.Minute, BaseDuration: 30 * time.Minute,
			EscalationFactor: 4, MaxDuration: 24 * time.Hour,
			ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication,
		}},
	}
}

func waitSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket did not appear: %s", path)
}

func unixGet(t *testing.T, socket, path string) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	response, err := client.Get("http://unix" + path)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
