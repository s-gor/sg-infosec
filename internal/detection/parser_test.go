package detection

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseSSHFindings(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		message  string
		category Category
		ip       string
	}{
		{name: "failed password", message: "Failed password for root from 203.0.113.10 port 4567 ssh2", category: CategorySSHAuthFailed, ip: "203.0.113.10"},
		{name: "failed public key ipv6", message: "Failed publickey for admin from 2001:db8::10 port 4567 ssh2", category: CategorySSHAuthFailed, ip: "2001:db8::10"},
		{name: "invalid user", message: "Invalid user oracle from 198.51.100.20 port 2222", category: CategorySSHInvalidUser, ip: "198.51.100.20"},
		{name: "pam rhost", message: "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5 user=root", category: CategorySSHAuthFailed, ip: "192.0.2.5"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := Parse(JournalRecord{Unit: "ssh.service", Identifier: "sshd", Message: test.message, OccurredAt: now})
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Category != test.category {
				t.Fatalf("category = %q, want %q", findings[0].Category, test.category)
			}
			if findings[0].IP != netip.MustParseAddr(test.ip) {
				t.Fatalf("ip = %s, want %s", findings[0].IP, test.ip)
			}
			if findings[0].Service != ServiceSSH {
				t.Fatalf("service = %q, want %q", findings[0].Service, ServiceSSH)
			}
		})
	}
}

func TestParseHTTPProbeDropsQueryString(t *testing.T) {
	t.Parallel()
	record := JournalRecord{
		Unit:       "nginx.service",
		Identifier: "nginx",
		Message:    `203.0.113.44 - - [01/Sep/2026:10:00:00 +0000] "GET /.env?token=secret HTTP/1.1" 404 153 "-" "scanner"`,
		OccurredAt: time.Now().UTC(),
	}
	findings := Parse(record)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Category != CategoryHTTPAdminProbe {
		t.Fatalf("category = %q", findings[0].Category)
	}
	if findings[0].Metadata["path"] != "/.env" {
		t.Fatalf("path metadata = %#v, want /.env", findings[0].Metadata["path"])
	}
	for _, value := range findings[0].Metadata {
		if value == "secret" || value == "token=secret" {
			t.Fatalf("query secret leaked into metadata: %#v", findings[0].Metadata)
		}
	}
}

func TestParseGatewayStructuredFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		message  string
		category Category
	}{
		{message: `{"event_type":"auth.failed","ip":"203.0.113.8","route":"/admin/login"}`, category: CategoryGatewayAuthFailed},
		{message: `{"event_type":"api.auth_failed","ip":"203.0.113.9","route":"/api/admin"}`, category: CategoryGatewayAPIAuthFailed},
	}
	for _, test := range tests {
		findings := Parse(JournalRecord{Unit: "sg-gateway.service", Identifier: "sg-gateway", Message: test.message, OccurredAt: time.Now().UTC()})
		if len(findings) != 1 || findings[0].Category != test.category {
			t.Fatalf("Parse(%s) = %#v", test.message, findings)
		}
	}
}

func TestParseRejectsMalformedOrUntrustedAddresses(t *testing.T) {
	t.Parallel()
	records := []JournalRecord{
		{Unit: "ssh.service", Message: "Failed password for root from not-an-ip port 22"},
		{Unit: "nginx.service", Message: "attacker says 203.0.113.1 but this is not an access log"},
		{Unit: "sg-gateway.service", Message: `{"event_type":"auth.failed","ip":"invalid"}`},
		{Unit: "unknown.service", Message: "Failed password for root from 203.0.113.1 port 22"},
	}
	for _, record := range records {
		if findings := Parse(record); len(findings) != 0 {
			t.Fatalf("unexpected findings for %#v: %#v", record, findings)
		}
	}
}
