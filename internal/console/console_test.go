package console

import (
	"context"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/pkg/client"
)

func TestConsoleSupportsManualBlockRevokeAndQuit(t *testing.T) {
	core := &fakeCore{health: client.HealthResponse{Status: "healthy", Database: "ok", ProtocolVersion: "v1"}}
	input := strings.NewReader(strings.Join([]string{
		"2",             // manual block
		"192.0.2.15",    // IP
		"ssh",           // scope
		"30m",           // duration
		"incident test", // reason
		"3",             // revoke
		"decision-1",    // id
		"q",             // quit
	}, "\n") + "\n")
	var output strings.Builder

	err := Run(context.Background(), input, &output, core, &fakeEnforcer{}, fakeProbe{}, DefaultPaths())
	if err != nil {
		t.Fatal(err)
	}
	if len(core.added) != 1 {
		t.Fatalf("added=%+v", core.added)
	}
	request := core.added[0]
	if request.SourceID != "local-admin" || request.Scope != "ssh" || request.Backend != "nftables" || request.IP != "192.0.2.15" || request.Duration != "30m" || request.Reason != "incident test" {
		t.Fatalf("request=%+v", request)
	}
	if len(core.revoked) != 1 || core.revoked[0] != "decision-1" {
		t.Fatalf("revoked=%v", core.revoked)
	}
	for _, want := range []string{"Actions", "Decision created", "Decision revoked", "Goodbye"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
}

func TestConsoleRejectsInvalidIPWithoutCallingCore(t *testing.T) {
	core := &fakeCore{health: client.HealthResponse{Status: "healthy", Database: "ok", ProtocolVersion: "v1"}}
	input := strings.NewReader("2\nnot-an-ip\nq\n")
	var output strings.Builder
	if err := Run(context.Background(), input, &output, core, &fakeEnforcer{}, fakeProbe{}, DefaultPaths()); err != nil {
		t.Fatal(err)
	}
	if len(core.added) != 0 {
		t.Fatalf("added=%+v", core.added)
	}
	if !strings.Contains(output.String(), "Invalid IP address") {
		t.Fatalf("output=%s", output.String())
	}
}
