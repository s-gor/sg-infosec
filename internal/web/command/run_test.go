package command

import (
	"bytes"
	"strings"
	"testing"
)

func TestSetupCodeCommandsAreNotExposed(t *testing.T) {
	for _, args := range [][]string{{"--issue-setup-code"}, {"--ensure-setup-code"}} {
		t.Run(args[0], func(t *testing.T) {
			t.Setenv("SG_INFOSEC_WEB_STATE", t.TempDir()+"/auth.json")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := Run(args, strings.NewReader(""), &stdout, &stderr); code != 2 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestResetAdminCommandAcceptsSimpleEightCharacterPasswordFromStdin(t *testing.T) {
	state := t.TempDir() + "/auth.json"
	t.Setenv("SG_INFOSEC_WEB_STATE", state)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"--reset-admin", "admin"}, strings.NewReader("12345678\n"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "administrator reset") {
		t.Fatalf("unexpected stdout=%q", stdout.String())
	}
}
