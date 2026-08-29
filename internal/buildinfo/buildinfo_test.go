package buildinfo

import "testing"

func TestInfoHasStableDevelopmentDefaults(t *testing.T) {
	got := Info()
	if got.Version != "dev" {
		t.Fatalf("Version = %q, want dev", got.Version)
	}
	if got.Commit != "unknown" {
		t.Fatalf("Commit = %q, want unknown", got.Commit)
	}
	if got.BuildTime != "unknown" {
		t.Fatalf("BuildTime = %q, want unknown", got.BuildTime)
	}
	if got.ProtocolVersion != "v1" {
		t.Fatalf("ProtocolVersion = %q, want v1", got.ProtocolVersion)
	}
}
