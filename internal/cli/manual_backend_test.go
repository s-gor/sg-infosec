package cli

import (
	"io"
	"testing"
)

func TestCLIDecisionAddAcceptsExplicitNFTablesBackend(t *testing.T) {
	service := &fakeService{}
	code := Run([]string{
		"decisions", "add",
		"--source", "local-admin",
		"--scope", "ssh",
		"--backend", "nftables",
		"--ip", "203.0.113.10",
		"--duration", "10m",
		"--reason", "server acceptance test",
	}, io.Discard, io.Discard, testDependencies(service))
	if code != ExitSuccess {
		t.Fatalf("code = %d, want %d", code, ExitSuccess)
	}
	if service.addCalls != 1 {
		t.Fatalf("add calls = %d, want 1", service.addCalls)
	}
}
