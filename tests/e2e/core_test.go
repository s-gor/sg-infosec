//go:build linux && cgo

package e2e

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/app"
	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestCoreDecisionLifecycleOverUnixSockets(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)
	fakeClock := &clock.Fake{Current: now}
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
			ID:  "e2e-panel",
			UID: uid,
			AllowedEvents: map[model.EventType]struct{}{
				model.EventAuthFailed: {},
			},
			AllowedScopes: map[model.Scope]struct{}{
				model.ScopeAdminLogin: {},
				model.ScopeAdminAPI:   {},
			},
			Permissions: map[config.Permission]struct{}{
				config.PermissionCheckDecisions: {},
				config.PermissionReadAdmin:      {},
				config.PermissionWriteAdmin:     {},
			},
		}},
		Policies: []model.Policy{{
			ID: "e2e-admin-login", Enabled: true, SourceID: "e2e-panel",
			EventType: model.EventAuthFailed, Scope: model.ScopeAdminLogin,
			Threshold: 5, Window: 10 * time.Minute, BaseDuration: 30 * time.Minute,
			EscalationFactor: 4, MaxDuration: 24 * time.Hour,
			ResetInterval: 30 * 24 * time.Hour, Backend: model.BackendApplication,
		}},
	}

	application, err := app.New(cfg, app.Dependencies{
		Clock: fakeClock, UID: uid, RetentionInterval: time.Hour,
	})
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
			_ = awaitRunResult(t, done)
		}
	})

	waitForSocket(t, cfg.EventsSocket)
	waitForSocket(t, cfg.ControlSocket)
	controlClient := client.New(cfg.ControlSocket, client.WithTimeout(3*time.Second))
	defer controlClient.CloseIdleConnections()
	waitForHealth(t, controlClient)

	ipv4 := "203.0.113.10"
	var ipv4Decision string
	for index := 1; index <= 5; index++ {
		response, status := postEvent(t, cfg.EventsSocket, protocol.EventRequest{
			EventID: "ipv4-" + time.Duration(index).String(), EventType: "auth.failed",
			Scope: "admin-login", IP: ipv4, Subject: "admin", OccurredAt: now,
			Metadata: map[string]any{"reason": "invalid_password"},
		})
		if status != http.StatusAccepted {
			t.Fatalf("IPv4 event %d status = %d", index, status)
		}
		if index < 5 && response.DecisionID != "" {
			t.Fatalf("IPv4 event %d created early decision %q", index, response.DecisionID)
		}
		if index == 5 {
			ipv4Decision = response.DecisionID
		}
	}
	if ipv4Decision == "" {
		t.Fatal("fifth IPv4 event did not create a decision")
	}

	blocked, err := controlClient.CheckDecision(context.Background(), protocol.DecisionCheckRequest{
		Scope: "admin-login", IP: ipv4, RouteID: "admin.login",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !blocked.Blocked || blocked.DecisionID != ipv4Decision {
		t.Fatalf("admin-login check = %+v", blocked)
	}
	allowedAPI, err := controlClient.CheckDecision(context.Background(), protocol.DecisionCheckRequest{
		Scope: "admin-api", IP: ipv4, RouteID: "admin.api",
	})
	if err != nil {
		t.Fatal(err)
	}
	if allowedAPI.Blocked {
		t.Fatalf("admin-api was blocked by admin-login decision: %+v", allowedAPI)
	}

	ipv6 := "2001:db8::10"
	var ipv6Decision string
	for index := 1; index <= 5; index++ {
		response, status := postEvent(t, cfg.EventsSocket, protocol.EventRequest{
			EventID: "ipv6-" + time.Duration(index).String(), EventType: "auth.failed",
			Scope: "admin-login", IP: ipv6, Subject: "admin", OccurredAt: now,
		})
		if status != http.StatusAccepted {
			t.Fatalf("IPv6 event %d status = %d", index, status)
		}
		if index == 5 {
			ipv6Decision = response.DecisionID
		}
	}
	if ipv6Decision == "" || ipv6Decision == ipv4Decision {
		t.Fatalf("IPv6 decision = %q, IPv4 decision = %q", ipv6Decision, ipv4Decision)
	}
	blocked6, err := controlClient.CheckDecision(context.Background(), protocol.DecisionCheckRequest{
		Scope: "admin-login", IP: ipv6, RouteID: "admin.login",
	})
	if err != nil || !blocked6.Blocked || blocked6.DecisionID != ipv6Decision {
		t.Fatalf("IPv6 check = %+v err=%v", blocked6, err)
	}

	revoked, err := controlClient.RevokeDecision(context.Background(), ipv4Decision)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked.Changed {
		t.Fatalf("revoke response = %+v", revoked)
	}
	afterRevoke, err := controlClient.CheckDecision(context.Background(), protocol.DecisionCheckRequest{
		Scope: "admin-login", IP: ipv4, RouteID: "admin.login",
	})
	if err != nil {
		t.Fatal(err)
	}
	if afterRevoke.Blocked {
		t.Fatalf("IPv4 remains blocked after revoke: %+v", afterRevoke)
	}
	stillBlocked6, err := controlClient.CheckDecision(context.Background(), protocol.DecisionCheckRequest{
		Scope: "admin-login", IP: ipv6, RouteID: "admin.login",
	})
	if err != nil || !stillBlocked6.Blocked {
		t.Fatalf("IPv6 decision was affected by IPv4 revoke: %+v err=%v", stillBlocked6, err)
	}

	cancel()
	if err := awaitRunResult(t, done); err != nil {
		t.Fatal(err)
	}
	stopped = true
	for _, socketPath := range []string{cfg.EventsSocket, cfg.ControlSocket} {
		if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
			t.Fatalf("socket remains after shutdown: %s err=%v", socketPath, err)
		}
	}
}
