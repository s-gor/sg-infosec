package sshjournal

import (
	"strings"
	"testing"
	"time"
)

func TestParseRecordRecognizesOpenSSHFailures(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		wantIP     string
		wantUser   string
		wantMethod string
	}{
		{
			name:       "invalid password user",
			message:    "Failed password for invalid user admin from 203.0.113.8 port 41234 ssh2",
			wantIP:     "203.0.113.8",
			wantUser:   "admin",
			wantMethod: "password",
		},
		{
			name:       "public key ipv6",
			message:    "Failed publickey for root from 2001:db8::9 port 50222 ssh2: ED25519 SHA256:example",
			wantIP:     "2001:db8::9",
			wantUser:   "root",
			wantMethod: "publickey",
		},
		{
			name:       "pam authentication failure",
			message:    "PAM: Authentication failure for illegal user test from 192.0.2.44",
			wantIP:     "192.0.2.44",
			wantUser:   "test",
			wantMethod: "pam",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := []byte(`{"MESSAGE":` + quote(tt.message) + `,"__CURSOR":"cursor-1","_SOURCE_REALTIME_TIMESTAMP":"1788182400000000","_SYSTEMD_UNIT":"ssh.service"}`)
			event, ok := ParseRecord(record)
			if !ok {
				t.Fatal("record was not recognized")
			}
			if event.EventType != "auth.failed" || event.Scope != "ssh" || event.IP != tt.wantIP || event.Subject != tt.wantUser {
				t.Fatalf("event=%+v", event)
			}
			if event.Metadata["method"] != tt.wantMethod || event.Metadata["reason"] != "invalid_credentials" || event.Metadata["unit"] != "ssh.service" {
				t.Fatalf("metadata=%v", event.Metadata)
			}
			if !strings.HasPrefix(event.EventID, "ssh-journal-") || len(event.EventID) > 128 {
				t.Fatalf("event id=%q", event.EventID)
			}
			wantTime := time.Unix(1788182400, 0).UTC()
			if !event.OccurredAt.Equal(wantTime) {
				t.Fatalf("occurred_at=%s want=%s", event.OccurredAt, wantTime)
			}
		})
	}
}

func TestParseRecordIsDeterministicAndCanonicalizesMappedIPv4(t *testing.T) {
	record := []byte(`{"MESSAGE":"Failed password for root from ::ffff:192.0.2.10 port 22 ssh2","__CURSOR":"stable-cursor","_SOURCE_REALTIME_TIMESTAMP":"1788182400123456","_SYSTEMD_UNIT":"sshd.service"}`)
	first, ok := ParseRecord(record)
	if !ok {
		t.Fatal("first parse failed")
	}
	second, ok := ParseRecord(record)
	if !ok {
		t.Fatal("second parse failed")
	}
	if first.EventID != second.EventID {
		t.Fatalf("event ids differ: %q %q", first.EventID, second.EventID)
	}
	if first.IP != "192.0.2.10" {
		t.Fatalf("ip=%q", first.IP)
	}
}

func TestParseRecordIgnoresSuccessNoiseAndInvalidJSON(t *testing.T) {
	for _, record := range [][]byte{
		[]byte(`{"MESSAGE":"Accepted publickey for root from 192.0.2.1 port 22 ssh2","__CURSOR":"ok","_SYSTEMD_UNIT":"ssh.service"}`),
		[]byte(`{"MESSAGE":"Connection closed by authenticating user root 192.0.2.1 port 22 [preauth]","__CURSOR":"noise","_SYSTEMD_UNIT":"ssh.service"}`),
		[]byte(`{"MESSAGE":"Failed password for root from 192.0.2.1 port 22 ssh2","__CURSOR":"wrong-unit","_SYSTEMD_UNIT":"nginx.service"}`),
		[]byte(`not-json`),
	} {
		if event, ok := ParseRecord(record); ok {
			t.Fatalf("unexpected event=%+v for %q", event, record)
		}
	}
}

func quote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
