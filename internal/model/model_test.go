package model

import "testing"

func TestParseScopeAcceptsClosedSet(t *testing.T) {
	for _, value := range []string{"admin-login", "admin-api", "ssh", "panel-port"} {
		if _, err := ParseScope(value); err != nil {
			t.Fatalf("ParseScope(%q): %v", value, err)
		}
	}
}

func TestParseScopeRejectsUnknownValue(t *testing.T) {
	if _, err := ParseScope("vpn"); err == nil {
		t.Fatal("ParseScope(vpn) succeeded, want error")
	}
}

func TestParseEventTypeAcceptsClosedSet(t *testing.T) {
	for _, value := range []string{"auth.failed", "auth.succeeded", "api.auth_failed"} {
		if _, err := ParseEventType(value); err != nil {
			t.Fatalf("ParseEventType(%q): %v", value, err)
		}
	}
}
