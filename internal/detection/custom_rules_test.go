package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCustomRulesParseReviewedJournalFormat(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.json")
	content := `{
  "rules": [
    {
      "id": "custom-panel-auth",
      "unit_pattern": "^custom-panel\\.service$",
      "identifier_pattern": "^custom-panel$",
      "message_pattern": "^LOGIN_FAIL ip=(?P<ip>[^ ]+) user=(?P<subject>[^ ]+)$",
      "category": "gateway.auth_failed",
      "service": "sg-gateway"
    }
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRuleSet(path)
	if err != nil {
		t.Fatal(err)
	}
	findings := rules.Parse(JournalRecord{
		Unit:       "custom-panel.service",
		Identifier: "custom-panel",
		Message:    "LOGIN_FAIL ip=203.0.113.70 user=admin",
		Cursor:     "cursor-1",
		OccurredAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.IP.String() != "203.0.113.70" {
		t.Fatalf("IP = %s", finding.IP)
	}
	if finding.Category != CategoryGatewayAuthFailed {
		t.Fatalf("category = %s", finding.Category)
	}
	if finding.Service != ServiceGateway {
		t.Fatalf("service = %s", finding.Service)
	}
	if finding.SubjectHash == "" || finding.SubjectHash == "admin" {
		t.Fatalf("subject hash = %q", finding.SubjectHash)
	}
	if finding.Metadata["rule_id"] != "custom-panel-auth" {
		t.Fatalf("metadata = %#v", finding.Metadata)
	}
}

func TestCustomRulesRequireNamedIPCapture(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"bad","message_pattern":"failed from ([^ ]+)","category":"ssh.auth_failed","service":"ssh"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRuleSet(path)
	if err == nil {
		t.Fatal("rule without named IP capture was accepted")
	}
}

func TestCustomRulesRejectUnknownCategoryAndOversizedRuleSet(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"bad","message_pattern":"(?P<ip>[^ ]+)","category":"unknown","service":"ssh"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuleSet(path); err == nil {
		t.Fatal("unknown category was accepted")
	}
}

func TestCustomRulesRejectTrailingJSONAndOversizedFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	trailing := filepath.Join(directory, "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{"rules":[]} {"rules":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuleSet(trailing); err == nil {
		t.Fatal("trailing JSON object was accepted")
	}

	oversized := filepath.Join(directory, "oversized.json")
	payload := `{"rules":[],"padding":"` + strings.Repeat("x", maxRuleFileBytes) + `"}`
	if err := os.WriteFile(oversized, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuleSet(oversized); err == nil {
		t.Fatal("oversized rules file was accepted")
	}
}

func TestCustomRulesIgnoreInvalidAddressAndDoNotStoreRawMessage(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{"id":"ssh-custom","message_pattern":"bad ip=(?P<ip>[^ ]+)","category":"ssh.auth_failed","service":"ssh"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRuleSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if findings := rules.Parse(JournalRecord{Message: "bad ip=not-an-ip secret=password"}); len(findings) != 0 {
		t.Fatalf("invalid address produced findings: %#v", findings)
	}
	findings := rules.Parse(JournalRecord{Message: "bad ip=198.51.100.7 secret=password"})
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	if len(findings[0].Metadata) != 1 || findings[0].Metadata["rule_id"] != "ssh-custom" {
		t.Fatalf("unsafe metadata = %#v", findings[0].Metadata)
	}
}

func TestMissingCustomRulesFileProducesEmptySet(t *testing.T) {
	t.Parallel()
	rules, err := LoadRuleSet(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rules.Count() != 0 {
		t.Fatalf("rules = %d", rules.Count())
	}
}
