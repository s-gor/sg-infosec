package console

import (
	"context"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type fakeCore struct {
	health    client.HealthResponse
	decisions protocol.DecisionListResponse
	allowlist protocol.AllowlistListResponse
	audit     protocol.AuditListResponse
	added     []protocol.ManualDecisionRequest
	revoked   []string
}

func (f *fakeCore) Health(context.Context) (client.HealthResponse, error) { return f.health, nil }
func (f *fakeCore) ListDecisions(context.Context, client.ListOptions) (protocol.DecisionListResponse, error) {
	return f.decisions, nil
}
func (f *fakeCore) ListAllowlist(context.Context, client.ListOptions) (protocol.AllowlistListResponse, error) {
	return f.allowlist, nil
}
func (f *fakeCore) ListAudit(context.Context, client.ListOptions) (protocol.AuditListResponse, error) {
	return f.audit, nil
}
func (f *fakeCore) AddDecision(_ context.Context, request protocol.ManualDecisionRequest) (protocol.DecisionView, error) {
	f.added = append(f.added, request)
	return protocol.DecisionView{ID: "decision-1", Scope: request.Scope, IP: request.IP}, nil
}
func (f *fakeCore) RevokeDecision(_ context.Context, id string) (protocol.ActionResponse, error) {
	f.revoked = append(f.revoked, id)
	return protocol.ActionResponse{Changed: true}, nil
}

type fakeEnforcer struct{ ready bool }
func (f *fakeEnforcer) Ready(context.Context) error { return nil }

type fakeProbe map[string]bool
func (f fakeProbe) Hostname() string { return "sg-test" }
func (f fakeProbe) Exists(path string) bool { return f[path] }

func TestCollectAndRenderOverviewShowsConnectionsAndCounts(t *testing.T) {
	core := &fakeCore{
		health: client.HealthResponse{Status: "healthy", Database: "ok", ProtocolVersion: "v1", ActiveDecisions: 2, DatabaseBytes: 98696},
		decisions: protocol.DecisionListResponse{Items: []protocol.DecisionView{{ID: "one"}, {ID: "two"}}},
		allowlist: protocol.AllowlistListResponse{Items: []protocol.AllowlistView{{ID: "allow-1"}}},
		audit: protocol.AuditListResponse{Items: []protocol.AuditView{{ID: 1}, {ID: 2}, {ID: 3}}},
	}
	probe := fakeProbe{
		"/run/sg-infosec/control.sock": true,
		"/run/sg-infosec/events.sock": true,
		"/run/sg-infosec/enforcer.sock": true,
		"/etc/systemd/system/sg-infosec-ssh-agent.service": true,
		"/opt/sg-gateway": true,
		"/opt/sg-gateway/app/security/sg_infosec.py": true,
	}

	snapshot, err := Collect(context.Background(), core, &fakeEnforcer{}, probe, DefaultPaths())
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	RenderOverview(&output, snapshot, false)
	text := output.String()
	for _, want := range []string{
		"SG InfoSec Console", "sg-test", "HEALTHY", "98696", "2", "1", "3",
		"/run/sg-infosec/control.sock", "CONNECTED",
		"SSH journal", "CONNECTED", "SG-Gateway", "ADAPTER READY",
		"VPN ports 585/586/587", "excluded",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("plain output contains ANSI: %q", text)
	}
}

func TestOverviewJSONIsStable(t *testing.T) {
	snapshot := Snapshot{Hostname: "sg-test", CoreStatus: "healthy", Database: "ok", Protocol: "v1", EnforcerReady: true}
	var output strings.Builder
	if err := RenderJSON(&output, snapshot); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, `"hostname":"sg-test"`) || !strings.Contains(got, `"enforcer_ready":true`) {
		t.Fatalf("json=%q", got)
	}
}
