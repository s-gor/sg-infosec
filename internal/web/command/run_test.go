package command

import (
	"bytes"
	"strings"
	"testing"
)

func TestIssueSetupCodeCommand(t *testing.T) {
	t.Setenv("SG_INFOSEC_WEB_STATE", t.TempDir()+"/auth.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"--issue-setup-code"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	value := strings.TrimSpace(stdout.String())
	parts := strings.Split(value, "-")
	if len(parts) != 3 || len(parts[0]) != 4 || len(parts[1]) != 4 || len(parts[2]) != 4 {
		t.Fatalf("unexpected setup code %q", value)
	}
}

func TestResetAdminCommandReadsPasswordFromStdin(t *testing.T) {
	t.Setenv("SG_INFOSEC_WEB_STATE", t.TempDir()+"/auth.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"--reset-admin", "admin"}, strings.NewReader("correct horse battery staple\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "administrator reset") {
		t.Fatalf("unexpected stdout=%q", stdout.String())
	}
}
