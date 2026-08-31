package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
)

func TestRunVersionPrintsBuildMetadata(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var metadata buildinfo.Metadata
	if err := json.Unmarshal(stdout.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata != buildinfo.Info() {
		t.Fatalf("metadata=%+v", metadata)
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"unexpected"}, &bytes.Buffer{}, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
