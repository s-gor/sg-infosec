package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/internal/model"
)

type fakeLookup struct{}

func (fakeLookup) User(name string) (uint32, error) {
	switch name {
	case "sg-gateway", "same-uid-user":
		return 1001, nil
	case "root":
		return 0, nil
	case "sshd-adapter":
		return 1003, nil
	default:
		return 0, fmt.Errorf("unknown user %q", name)
	}
}
func (fakeLookup) Group(name string) (uint32, error) {
	switch name {
	case "sg-security", "sg-gateway":
		return 1002, nil
	case "root":
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown group %q", name)
	}
}

func TestLoadStrictConfiguration(t *testing.T) {
	path := writeValidFixture(t)
	cfg, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 1 || len(cfg.Policies) != 1 || cfg.Policies[0].Backend != model.BackendApplication {
		t.Fatalf("config=%+v", cfg)
	}
	if cfg.Allowlist[0].Prefix.String() != "192.0.2.10/32" || cfg.Allowlist[1].Prefix.String() != "2001:db8::/32" {
		t.Fatalf("allowlist=%+v", cfg.Allowlist)
	}
}

func TestLoadAcceptsNFTablesOnlyForSSH(t *testing.T) {
	path := writeValidFixture(t)
	policyPath := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policyPath, "scope: admin-login", "scope: ssh")
	replaceFile(t, policyPath, "backend: application", "backend: nftables")
	sourcePath := filepath.Join(filepath.Dir(path), "sources.d", "sg-gateway.yaml")
	replaceFile(t, sourcePath, "  - admin-login", "  - ssh")
	cfg, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policies[0].Backend != model.BackendNFTables || cfg.Policies[0].Scope != model.ScopeSSH {
		t.Fatalf("policy=%+v", cfg.Policies[0])
	}
}

func TestLoadRejectsNFTablesForApplicationScopes(t *testing.T) {
	path := writeValidFixture(t)
	policyPath := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policyPath, "backend: application", "backend: nftables")
	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "supports only") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRejectsApplicationForSSH(t *testing.T) {
	path := writeValidFixture(t)
	policyPath := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policyPath, "scope: admin-login", "scope: ssh")
	sourcePath := filepath.Join(filepath.Dir(path), "sources.d", "sg-gateway.yaml")
	replaceFile(t, sourcePath, "  - admin-login", "  - ssh")
	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "application backend") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRejectsUnknownFieldsDuplicatesAndSecondDocument(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate func(string)
		want   string
	}{
		"unknown":   {func(path string) { appendFile(t, path, "unexpected: true\n") }, "unknown field"},
		"duplicate": {func(path string) { appendFile(t, path, "database_path: /tmp/other\n") }, "duplicate key"},
		"document":  {func(path string) { appendFile(t, path, "---\ndatabase_path: /tmp/other\n") }, "multiple YAML documents"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeValidFixture(t)
			testCase.mutate(path)
			_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error=%v want=%s", err, testCase.want)
			}
		})
	}
}

func TestLoadRejectsDuplicateSourceIDsAndUIDs(t *testing.T) {
	path := writeValidFixture(t)
	dir := filepath.Join(filepath.Dir(path), "sources.d")
	writeFile(t, filepath.Join(dir, "duplicate.yaml"), sourceFixture("sg-gateway", "sg-gateway"))
	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "duplicate source_id") {
		t.Fatalf("error=%v", err)
	}

	path = writeValidFixture(t)
	dir = filepath.Join(filepath.Dir(path), "sources.d")
	writeFile(t, filepath.Join(dir, "same-uid.yaml"), sourceFixture("second", "same-uid-user"))
	_, err = LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "same UID") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadRejectsPolicyPermissionMismatchAndUnknownSource(t *testing.T) {
	path := writeValidFixture(t)
	policyPath := filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policyPath, "event_type: auth.failed", "event_type: auth.succeeded")
	_, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "does not allow event type") {
		t.Fatalf("error=%v", err)
	}

	path = writeValidFixture(t)
	policyPath = filepath.Join(filepath.Dir(path), "policies.d", "admin.yaml")
	replaceFile(t, policyPath, "source_id: sg-gateway", "source_id: missing")
	_, err = LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err == nil || !strings.Contains(err.Error(), "unknown source_id") {
		t.Fatalf("error=%v", err)
	}
}

func TestExampleConfigurationLoads(t *testing.T) {
	path := filepath.Join("..", "..", "config", "example", "sg-infosec.yaml")
	cfg, err := LoadWithOptions(path, Options{Lookup: fakeLookup{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources) != 2 || len(cfg.Policies) != 3 {
		t.Fatalf("sources=%d policies=%d", len(cfg.Sources), len(cfg.Policies))
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
	path := filepath.Join(dir, "sg-infosec.yaml")
	writeFile(t, path, `database_path: ./state/sg-infosec.db
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
`)
	writeFile(t, filepath.Join(dir, "sources.d", "sg-gateway.yaml"), sourceFixture("sg-gateway", "sg-gateway"))
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

func sourceFixture(id, user string) string {
	return fmt.Sprintf(`source_id: %s
user: %s
group: sg-security
allowed_events:
  - auth.failed
  - api.auth_failed
allowed_scopes:
  - admin-login
  - admin-api
permissions:
  - check_decisions
`, id, user)
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
func replaceFile(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), old, replacement, 1)
	if updated == string(data) {
		t.Fatalf("fixture missing %q", old)
	}
	writeFile(t, path, updated)
}
