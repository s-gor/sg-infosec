package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeLookup struct{}

func (fakeLookup) User(name string) (uint32, error) {
	if name == "sg-gateway" || name == "same-uid-user" {
		return 1001, nil
	}
	return 0, fmt.Errorf("unknown user %q", name)
}

func (fakeLookup) Group(name string) (uint32, error) {
	if name == "sg-security" || name == "sg-gateway" {
		return 1002, nil
	}
	return 0, fmt.Errorf("unknown group %q", name)
}

func TestLoadRejectsUnknownYAMLFields(t *testing.T) {
	path := writeValidFixture(t)
	appendFile(t, path, "unknown_field: true\n")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadWithOptions error = %v, want unknown field", err)
	}
}

func TestLoadRejectsDuplicateSourceIDs(t *testing.T) {
	path := writeValidFixture(t)
	sources := filepath.Join(filepath.Dir(path), "sources.d")
	writeFile(t, filepath.Join(sources, "duplicate.yaml"), sourceFixture("sg-gateway"))

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "duplicate source_id") {
		t.Fatalf("LoadWithOptions error = %v, want duplicate source_id", err)
	}
}

func TestLoadRejectsPolicyWithZeroThreshold(t *testing.T) {
	path := writeValidFixture(t)
	policy := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policy, "threshold: 5", "threshold: 0")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("LoadWithOptions error = %v, want threshold error", err)
	}
}

func TestLoadRejectsFirewallBackendInCoreMVP(t *testing.T) {
	path := writeValidFixture(t)
	policy := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policy, "backend: application", "backend: nftables")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "nftables") {
		t.Fatalf("LoadWithOptions error = %v, want nftables rejection", err)
	}
}

func TestLoadAcceptsIPv4AndIPv6AllowlistPrefixes(t *testing.T) {
	path := writeValidFixture(t)
	cfg, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err != nil {
		t.Fatalf("LoadWithOptions: %v", err)
	}
	if len(cfg.Allowlist) != 2 {
		t.Fatalf("allowlist count = %d, want 2", len(cfg.Allowlist))
	}
	got := []string{cfg.Allowlist[0].Prefix.String(), cfg.Allowlist[1].Prefix.String()}
	want := []string{"192.0.2.10/32", "2001:db8::/32"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("allowlist[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadResolvesRelativeFragmentDirectoriesFromMainConfig(t *testing.T) {
	path := writeValidFixture(t)
	cfg, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err != nil {
		t.Fatalf("LoadWithOptions: %v", err)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0].ID != "sg-gateway" {
		t.Fatalf("sources = %#v", cfg.Sources)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].ID != "sg-gateway-admin-login" {
		t.Fatalf("policies = %#v", cfg.Policies)
	}
	if cfg.Sources[0].UID != 1001 {
		t.Fatalf("source UID = %d, want 1001", cfg.Sources[0].UID)
	}
	if cfg.Sources[0].GID == nil || *cfg.Sources[0].GID != 1002 {
		t.Fatalf("source GID = %v, want 1002", cfg.Sources[0].GID)
	}
}

func TestLoadRejectsSourcesWithSameResolvedUID(t *testing.T) {
	path := writeValidFixture(t)
	sources := filepath.Join(filepath.Dir(path), "sources.d")
	content := sourceFixture("second-panel")
	content = strings.Replace(content, "user: sg-gateway", "user: same-uid-user", 1)
	writeFile(t, filepath.Join(sources, "second.yaml"), content)

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "same UID") {
		t.Fatalf("LoadWithOptions error = %v, want duplicate UID rejection", err)
	}
}

func TestExampleConfigurationLoadsWithInjectedIdentityLookup(t *testing.T) {
	path := filepath.Join("..", "..", "config", "example", "sg-infosec.yaml")
	cfg, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err != nil {
		t.Fatalf("LoadWithOptions(example): %v", err)
	}
	if len(cfg.Sources) != 1 || len(cfg.Policies) != 1 {
		t.Fatalf("example sources=%d policies=%d", len(cfg.Sources), len(cfg.Policies))
	}
}

func TestLoadRejectsPolicyForUnknownSource(t *testing.T) {
	path := writeValidFixture(t)
	policy := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policy, "source_id: sg-gateway", "source_id: missing-panel")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "unknown source_id") {
		t.Fatalf("LoadWithOptions error = %v, want unknown source_id", err)
	}
}

func TestLoadRejectsUnknownSourceFragmentField(t *testing.T) {
	path := writeValidFixture(t)
	source := filepath.Join(filepath.Dir(path), "sources.d", "sg-gateway.yaml")
	appendFile(t, source, "unexpected: true\n")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadWithOptions error = %v, want unknown field", err)
	}
}

func TestLoadRejectsPolicyPermissionMismatch(t *testing.T) {
	path := writeValidFixture(t)
	policy := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policy, "event_type: auth.failed", "event_type: auth.succeeded")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "does not allow event type") {
		t.Fatalf("LoadWithOptions error = %v, want event permission mismatch", err)
	}
}

func TestLoadRejectsSecondYAMLDocument(t *testing.T) {
	path := writeValidFixture(t)
	appendFile(t, path, "---\ndatabase_path: /tmp/other.db\n")

	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("LoadWithOptions error = %v, want multiple document rejection", err)
	}
}

func writeValidFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sources.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "policies.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	main := `database_path: ./state/sg-infosec.db
events_socket: ./run/events.sock
control_socket: ./run/control.sock
event_body_limit: 16384
sources_dir: sources.d
policies_dir: policies.d
retention:
  events: 168h
  audit: 2160h
allowlist:
  - 192.0.2.10
  - 2001:db8::/32
`
	path := filepath.Join(dir, "sg-infosec.yaml")
	writeFile(t, path, main)
	writeFile(t, filepath.Join(dir, "sources.d", "sg-gateway.yaml"), sourceFixture("sg-gateway"))
	writeFile(t, filepath.Join(dir, "policies.d", "admin.yaml"), `policy_id: sg-gateway-admin-login
enabled: true
event_type: auth.failed
scope: admin-login
source_id: sg-gateway
threshold: 5
window: 10m
base_duration: 30m
escalation_factor: 4
max_duration: 24h
reset_interval: 720h
backend: application
`)
	return path
}

func sourceFixture(id string) string {
	return fmt.Sprintf(`source_id: %s
user: sg-gateway
group: sg-security
allowed_events:
  - auth.failed
  - api.auth_failed
allowed_scopes:
  - admin-login
  - admin-api
permissions:
  - check_decisions
`, id)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func replaceFile(t *testing.T, path, old, new string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), old, new, 1)
	if updated == string(data) {
		t.Fatalf("fixture does not contain %q", old)
	}
	writeFile(t, path, updated)
}
