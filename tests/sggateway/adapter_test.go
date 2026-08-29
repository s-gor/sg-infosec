//go:build linux && cgo

package sggateway

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/app"
	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
)

type smokeResult struct {
	InitiallyBlocked bool `json:"initially_blocked"`
	BlockedAfterFive bool `json:"blocked_after_five"`
	APIBlocked       bool `json:"api_blocked"`
	IPv6Blocked      bool `json:"ipv6_blocked"`
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test path")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(current)))
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Unix socket did not appear: %s", path)
}

func TestSGGatewayAdapterAgainstRealDaemon(t *testing.T) {
	adapterPath := os.Getenv("SG_GATEWAY_ADAPTER_PATH")
	if adapterPath == "" {
		t.Skip("set SG_GATEWAY_ADAPTER_PATH to app/security/sg_infosec.py")
	}
	if _, err := os.Stat(adapterPath); err != nil {
		t.Fatalf("adapter path: %v", err)
	}

	dir := t.TempDir()
	uid := uint32(os.Getuid())
	cfg := config.Config{
		DatabasePath:   filepath.Join(dir, "sg-infosec.db"),
		EventsSocket:   filepath.Join(dir, "events.sock"),
		ControlSocket:  filepath.Join(dir, "control.sock"),
		EventBodyLimit: 16 * 1024,
		Retention: config.EventRetention{
			Events: 7 * 24 * time.Hour,
			Audit:  90 * 24 * time.Hour,
		},
		Sources: []config.Source{{
			ID:  "sg-gateway",
			UID: uid,
			AllowedEvents: map[model.EventType]struct{}{
				model.EventAuthFailed:    {},
				model.EventAPIAuthFailed: {},
			},
			AllowedScopes: map[model.Scope]struct{}{
				model.ScopeAdminLogin: {},
				model.ScopeAdminAPI:   {},
			},
			Permissions: map[config.Permission]struct{}{
				config.PermissionCheckDecisions: {},
			},
		}},
		Policies: []model.Policy{
			{
				ID: "sg-gateway-admin-login", Enabled: true, SourceID: "sg-gateway",
				EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin,
				Threshold: 5, Window: 10 * time.Minute, BaseDuration: 30 * time.Minute,
				EscalationFactor: 4, MaxDuration: 24 * time.Hour,
				ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication,
			},
			{
				ID: "sg-gateway-admin-api", Enabled: true, SourceID: "sg-gateway",
				EventType: model.EventAPIAuthFailed, Scope: model.ScopeAdminAPI,
				Threshold: 10, Window: 10 * time.Minute, BaseDuration: 15 * time.Minute,
				EscalationFactor: 4, MaxDuration: 24 * time.Hour,
				ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication,
			},
		},
	}

	application, err := app.New(cfg, app.Dependencies{UID: uid, RetentionInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("application did not stop")
			}
		}
	})

	waitForSocket(t, cfg.EventsSocket)
	waitForSocket(t, cfg.ControlSocket)

	helper := filepath.Join(repositoryRoot(t), "tests/sggateway/adapter_smoke.py")
	command := exec.Command(
		"python3", helper,
		"--adapter", adapterPath,
		"--control", cfg.ControlSocket,
		"--events", cfg.EventsSocket,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Python adapter smoke failed: %v\n%s", err, output)
	}
	var result smokeResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode smoke result: %v\n%s", err, output)
	}
	if result.InitiallyBlocked || !result.BlockedAfterFive || result.APIBlocked || !result.IPv6Blocked {
		t.Fatalf("unexpected adapter result: %+v", result)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("application did not stop")
	}
	stopped = true

	for _, socketPath := range []string{cfg.EventsSocket, cfg.ControlSocket} {
		if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
			t.Fatalf("socket remains after shutdown: %s err=%v", socketPath, err)
		}
	}

	failOpen := exec.Command(
		"python3", helper,
		"--adapter", adapterPath,
		"--control", cfg.ControlSocket,
		"--events", cfg.EventsSocket,
		"--fail-open-only",
	)
	if output, err := failOpen.CombinedOutput(); err != nil {
		t.Fatalf("fail-open smoke failed: %v\n%s", err, output)
	}
}
