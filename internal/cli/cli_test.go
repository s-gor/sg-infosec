package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type fakeService struct {
	health            client.HealthResponse
	healthErr         error
	addCalls          int
	allowCalls        int
	nftReconcileCalls int
}

func (f *fakeService) Health(context.Context) (client.HealthResponse, error) {
	return f.health, f.healthErr
}
func (f *fakeService) CheckDecision(context.Context, protocol.DecisionCheckRequest) (protocol.DecisionCheckResponse, error) {
	return protocol.DecisionCheckResponse{}, nil
}
func (f *fakeService) ListDecisions(context.Context, client.ListOptions) (protocol.DecisionListResponse, error) {
	return protocol.DecisionListResponse{}, nil
}
func (f *fakeService) AddDecision(context.Context, protocol.ManualDecisionRequest) (protocol.DecisionView, error) {
	f.addCalls++
	return protocol.DecisionView{}, nil
}
func (f *fakeService) RevokeDecision(context.Context, string) (protocol.ActionResponse, error) {
	return protocol.ActionResponse{}, nil
}
func (f *fakeService) ListAllowlist(context.Context, client.ListOptions) (protocol.AllowlistListResponse, error) {
	return protocol.AllowlistListResponse{}, nil
}
func (f *fakeService) AddAllowlist(context.Context, protocol.AllowlistCreateRequest) (protocol.AllowlistView, error) {
	f.allowCalls++
	return protocol.AllowlistView{}, nil
}
func (f *fakeService) RemoveAllowlist(context.Context, string) (protocol.ActionResponse, error) {
	return protocol.ActionResponse{}, nil
}
func (f *fakeService) ListAudit(context.Context, client.ListOptions) (protocol.AuditListResponse, error) {
	return protocol.AuditListResponse{}, nil
}
func (f *fakeService) ReconcileNFT(context.Context) (protocol.ActionResponse, error) {
	f.nftReconcileCalls++
	return protocol.ActionResponse{Changed: true, RequestID: "core-request"}, nil
}

func testDependencies(service Service) Dependencies {
	return Dependencies{
		NewClient:      func(string) Service { return service },
		ValidateConfig: func(string) error { return nil },
	}
}

func TestCLIHealthPrintsStableJSON(t *testing.T) {
	service := &fakeService{health: client.HealthResponse{
		Status: "healthy", Database: "ok", ProtocolVersion: "v1",
		ActiveDecisions: 2, DatabaseBytes: 4096,
		Build: client.BuildMetadata{Version: "dev", Commit: "abc", BuildTime: "unknown", ProtocolVersion: "v1"},
	}}
	var stdout, stderr strings.Builder
	code := Run([]string{"--json", "health"}, &stdout, &stderr, testDependencies(service))
	if code != ExitSuccess {
		t.Fatalf("code = %d, stderr=%q", code, stderr.String())
	}
	want := "{\"status\":\"healthy\",\"database\":\"ok\",\"protocol_version\":\"v1\",\"build\":{\"version\":\"dev\",\"commit\":\"abc\",\"build_time\":\"unknown\",\"protocol_version\":\"v1\"},\"active_decisions\":2,\"database_bytes\":4096}\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestCLIDecisionAddRequiresReasonAndDuration(t *testing.T) {
	service := &fakeService{}
	for _, args := range [][]string{
		{"decisions", "add", "--source", "panel", "--scope", "admin-login", "--ip", "192.0.2.1", "--duration", "30m"},
		{"decisions", "add", "--source", "panel", "--scope", "admin-login", "--ip", "192.0.2.1", "--reason", "manual"},
	} {
		code := Run(args, io.Discard, io.Discard, testDependencies(service))
		if code != ExitUsage {
			t.Fatalf("args=%v code=%d, want %d", args, code, ExitUsage)
		}
	}
	if service.addCalls != 0 {
		t.Fatalf("add calls = %d, want 0", service.addCalls)
	}
}

func TestCLIAllowlistAddRequiresDescription(t *testing.T) {
	service := &fakeService{}
	code := Run([]string{"allowlist", "add", "--prefix", "192.0.2.0/24"}, io.Discard, io.Discard, testDependencies(service))
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if service.allowCalls != 0 {
		t.Fatalf("allowlist calls = %d, want 0", service.allowCalls)
	}
}

func TestCLIExitCodesDistinguishUsageAndServerFailure(t *testing.T) {
	usage := Run(nil, io.Discard, io.Discard, testDependencies(&fakeService{}))
	if usage != ExitUsage {
		t.Fatalf("usage code = %d", usage)
	}

	unavailable := Run([]string{"health"}, io.Discard, io.Discard, testDependencies(&fakeService{healthErr: client.ErrUnavailable}))
	if unavailable != ExitUnavailable {
		t.Fatalf("unavailable code = %d", unavailable)
	}

	permission := Run([]string{"health"}, io.Discard, io.Discard, testDependencies(&fakeService{healthErr: &client.APIError{StatusCode: 403, Code: "permission_denied"}}))
	if permission != ExitPermission {
		t.Fatalf("permission code = %d", permission)
	}

	runtimeFailure := Run([]string{"health"}, io.Discard, io.Discard, testDependencies(&fakeService{healthErr: errors.New("broken response")}))
	if runtimeFailure != ExitFailure {
		t.Fatalf("runtime code = %d", runtimeFailure)
	}
}

func TestCLIConfigValidateDoesNotCreateDaemonClient(t *testing.T) {
	created := false
	validated := ""
	deps := Dependencies{
		NewClient:      func(string) Service { created = true; return &fakeService{} },
		ValidateConfig: func(path string) error { validated = path; return nil },
	}
	var stdout strings.Builder
	code := Run([]string{"config", "validate", "--config", "/tmp/sg-infosec.yaml"}, &stdout, io.Discard, deps)
	if code != ExitSuccess || created || validated != "/tmp/sg-infosec.yaml" {
		t.Fatalf("code=%d created=%v validated=%q", code, created, validated)
	}
	if !strings.Contains(stdout.String(), "valid") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

type fakeEnforcerService struct {
	ensureCalls       int
	listResponse      enforcerprotocol.ListResponse
	reconcileResponse enforcerprotocol.ReconcileResponse
	reconcileCalls    int
}

func (f *fakeEnforcerService) Ensure(context.Context, string) error { f.ensureCalls++; return nil }
func (f *fakeEnforcerService) List(context.Context) (enforcerprotocol.ListResponse, error) {
	return f.listResponse, nil
}
func (f *fakeEnforcerService) Reconcile(context.Context, string, []enforcerprotocol.Entry) (enforcerprotocol.ReconcileResponse, error) {
	f.reconcileCalls++
	return f.reconcileResponse, nil
}

func TestCLINFTStatusUsesSeparateEnforcerFactory(t *testing.T) {
	service := &fakeEnforcerService{}
	deps := Dependencies{NewEnforcerClient: func(path string) EnforcerService {
		if path != "/tmp/enforcer.sock" {
			t.Fatalf("path=%q", path)
		}
		return service
	}}
	var stdout, stderr strings.Builder
	code := Run([]string{"--enforcer-socket", "/tmp/enforcer.sock", "nft", "status"}, &stdout, &stderr, deps)
	if code != ExitSuccess || service.ensureCalls != 1 || !strings.Contains(stdout.String(), "ready") {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, service.ensureCalls, stdout.String(), stderr.String())
	}
}

func TestCLINFTReconcileUsesCoreSourceOfTruth(t *testing.T) {
	core := &fakeService{}
	enforcer := &fakeEnforcerService{}
	deps := Dependencies{
		NewClient:         func(string) Service { return core },
		NewEnforcerClient: func(string) EnforcerService { return enforcer },
	}
	var stdout, stderr strings.Builder
	code := Run([]string{"nft", "reconcile"}, &stdout, &stderr, deps)
	if code != ExitSuccess {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if core.nftReconcileCalls != 1 || enforcer.reconcileCalls != 0 {
		t.Fatalf("core calls=%d enforcer calls=%d", core.nftReconcileCalls, enforcer.reconcileCalls)
	}
	if !strings.Contains(stdout.String(), "reconciled from SQLite") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
