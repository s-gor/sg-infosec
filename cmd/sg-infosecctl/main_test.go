package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/cli"
)

func TestRunVersionPrintsBuildMetadataJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, &stdout, &stderr)
	if code != cli.ExitSuccess {
		t.Fatalf("exit code = %d; stderr=%q", code, stderr.String())
	}
	var got buildinfo.Metadata
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("version output is not JSON: %v", err)
	}
	if got != buildinfo.Info() {
		t.Fatalf("metadata = %#v, want %#v", got, buildinfo.Info())
	}
}

func TestRunWithoutArgumentsReturnsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != cli.ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, cli.ExitUsage)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
