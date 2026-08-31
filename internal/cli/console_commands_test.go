package cli

import (
	"io"
	"strings"
	"testing"

	consolepkg "github.com/s-gor/sg-infosec/internal/console"
	"github.com/s-gor/sg-infosec/pkg/client"
)

type cliProbe map[string]bool

func (p cliProbe) Hostname() string        { return "cli-host" }
func (p cliProbe) Exists(path string) bool { return p[path] }

func TestCLIOverviewAggregatesCoreAndEnforcer(t *testing.T) {
	core := &fakeService{health: client.HealthResponse{Status: "healthy", Database: "ok", ProtocolVersion: "v1", DatabaseBytes: 42}}
	enforcer := &fakeEnforcerService{}
	base := testDependencies(core)
	base.NewEnforcerClient = func(string) EnforcerService { return enforcer }
	deps := LocalDependencies{
		Dependencies: base,
		Probe: cliProbe{
			"/run/sg-infosec/control.sock":  true,
			"/run/sg-infosec/events.sock":   true,
			"/run/sg-infosec/enforcer.sock": true,
		},
		Paths: consolepkg.DefaultPaths(),
	}

	var stdout, stderr strings.Builder
	code := RunLocal([]string{"overview"}, strings.NewReader(""), &stdout, &stderr, deps)
	if code != ExitSuccess {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"SG InfoSec Console", "cli-host", "HEALTHY", "42"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
	if enforcer.ensureCalls != 1 {
		t.Fatalf("ensure calls=%d", enforcer.ensureCalls)
	}
}

func TestCLIConsoleUsesInjectedInput(t *testing.T) {
	core := &fakeService{health: client.HealthResponse{Status: "healthy", Database: "ok", ProtocolVersion: "v1"}}
	enforcer := &fakeEnforcerService{}
	base := testDependencies(core)
	base.NewEnforcerClient = func(string) EnforcerService { return enforcer }
	deps := LocalDependencies{
		Dependencies: base,
		Stdin:        strings.NewReader("q\n"),
		Probe:        cliProbe{},
		Paths:        consolepkg.DefaultPaths(),
	}

	var stdout, stderr strings.Builder
	code := RunLocal([]string{"console"}, deps.Stdin, &stdout, &stderr, deps)
	if code != ExitSuccess {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Goodbye") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestCLIConsoleRejectsJSONMode(t *testing.T) {
	deps := LocalDependencies{Dependencies: testDependencies(&fakeService{}), Stdin: strings.NewReader("q\n")}
	code := RunLocal([]string{"--json", "console"}, deps.Stdin, io.Discard, io.Discard, deps)
	if code != ExitUsage {
		t.Fatalf("code=%d want=%d", code, ExitUsage)
	}
}
