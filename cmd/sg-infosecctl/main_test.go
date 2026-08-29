package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
)

func TestRunVersionPrintsBuildMetadataJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"--version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var got buildinfo.Metadata
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("version output is not JSON: %v; output=%q", err, stdout.String())
	}
	if got != buildinfo.Info() {
		t.Fatalf("metadata = %#v, want %#v", got, buildinfo.Info())
	}
}

func TestRunWithoutArgumentsReportsUnimplementedStartup(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "command handling is not implemented") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
