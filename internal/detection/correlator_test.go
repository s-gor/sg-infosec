package detection

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func finding(ip string, category Category, service Service, at time.Time, subject string) Finding {
	return Finding{IP: netip.MustParseAddr(ip), Category: category, Service: service, OccurredAt: at, SubjectHash: subject}
}

func TestCorrelatorSSHThresholds(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	c := NewCorrelator(DefaultCorrelatorConfig())
	var signals []Signal
	for i := 0; i < 5; i++ {
		signals = append(signals, c.Observe(finding("203.0.113.10", CategorySSHAuthFailed, ServiceSSH, base.Add(time.Duration(i)*time.Minute), ""))...)
	}
	assertSignal(t, signals, "auth.failed", "ssh")

	c = NewCorrelator(DefaultCorrelatorConfig())
	signals = nil
	for i := 0; i < 12; i++ {
		signals = append(signals, c.Observe(finding("203.0.113.11", CategorySSHAuthFailed, ServiceSSH, base.Add(time.Duration(i)*5*time.Minute), ""))...)
	}
	assertSignal(t, signals, "auth.failed", "ssh")
}

func TestCorrelatorInvalidUserEnumeration(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	c := NewCorrelator(DefaultCorrelatorConfig())
	var signals []Signal
	for i := 0; i < 6; i++ {
		signals = append(signals, c.Observe(finding("198.51.100.7", CategorySSHInvalidUser, ServiceSSH, base.Add(time.Duration(i)*time.Minute), fmt.Sprintf("u%d", i)))...)
	}
	assertSignal(t, signals, "auth.failed", "ssh")
}

func TestCorrelatorApplicationThresholds(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		category  Category
		service   Service
		count     int
		eventType string
		scope     string
	}{
		{name: "http scan", category: CategoryHTTPAdminProbe, service: ServiceHTTP, count: 6, eventType: "api.auth_failed", scope: "admin-api"},
		{name: "panel failures", category: CategoryGatewayAuthFailed, service: ServiceGateway, count: 5, eventType: "auth.failed", scope: "admin-login"},
		{name: "api failures", category: CategoryGatewayAPIAuthFailed, service: ServiceGateway, count: 10, eventType: "api.auth_failed", scope: "admin-api"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCorrelator(DefaultCorrelatorConfig())
			var signals []Signal
			for i := 0; i < test.count; i++ {
				signals = append(signals, c.Observe(finding("192.0.2.20", test.category, test.service, base.Add(time.Duration(i)*time.Second), ""))...)
			}
			assertSignal(t, signals, test.eventType, test.scope)
		})
	}
}

func TestCorrelatorCrossServiceRequiresTwoServices(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	c := NewCorrelator(DefaultCorrelatorConfig())
	var signals []Signal
	for i := 0; i < 4; i++ {
		signals = append(signals, c.Observe(finding("203.0.113.55", CategorySSHInvalidUser, ServiceSSH, base.Add(time.Duration(i)*time.Second), fmt.Sprintf("u%d", i)))...)
	}
	if hasReason(signals, "cross-service") {
		t.Fatalf("cross-service signal emitted from one service: %#v", signals)
	}
	signals = append(signals, c.Observe(finding("203.0.113.55", CategoryHTTPAdminProbe, ServiceHTTP, base.Add(5*time.Second), ""))...)
	if !hasReason(signals, "cross-service") {
		t.Fatalf("missing cross-service signal: %#v", signals)
	}
	assertSignal(t, signals, "auth.failed", "ssh")
	assertSignal(t, signals, "api.auth_failed", "admin-api")
}

func TestCorrelatorBoundsAndExpiry(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	cfg := DefaultCorrelatorConfig()
	cfg.MaxStates = 4
	c := NewCorrelator(cfg)
	for i := 1; i <= 5; i++ {
		c.Observe(finding(fmt.Sprintf("192.0.2.%d", i), CategorySSHAuthFailed, ServiceSSH, base, ""))
	}
	if got := c.StateCount(); got != 4 {
		t.Fatalf("state count = %d, want 4", got)
	}
	c.Observe(finding("198.51.100.9", CategorySSHAuthFailed, ServiceSSH, base.Add(61*time.Minute), ""))
	if got := c.StateCount(); got > 2 {
		t.Fatalf("expired states retained: %d", got)
	}
}

func assertSignal(t *testing.T, signals []Signal, eventType, scope string) {
	t.Helper()
	for _, signal := range signals {
		if signal.EventType == eventType && signal.Scope == scope {
			return
		}
	}
	t.Fatalf("missing signal %s/%s in %#v", eventType, scope, signals)
}

func hasReason(signals []Signal, reason string) bool {
	for _, signal := range signals {
		if signal.Reason == reason {
			return true
		}
	}
	return false
}
