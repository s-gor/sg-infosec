//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/internal/config"
)

func TestRunCheckConfigValidatesRuntimeRules(t *testing.T) {
	var stdout, stderr bytes.Buffer
	validated := false
	code := runWith(
		[]string{"--check-config", "--config", "test.yaml"},
		&stdout,
		&stderr,
		runtimeDependencies{
			loadConfig: func(string) (config.Config, error) {
				return config.Config{}, nil
			},
			validateRuntime: func() error {
				validated = true
				return nil
			},
			newApp: func(config.Config) (application, error) {
				t.Fatal("newApp called")
				return nil, nil
			},
			context: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
	)
	if code != 0 || !validated {
		t.Fatalf("code=%d validated=%v stderr=%s", code, validated, stderr.String())
	}
}

func TestRunCheckConfigRejectsInvalidRuntimeRules(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith(
		[]string{"--check-config"},
		&stdout,
		&stderr,
		runtimeDependencies{
			loadConfig: func(string) (config.Config, error) {
				return config.Config{}, nil
			},
			validateRuntime: func() error {
				return errors.New("bad detection rules")
			},
			newApp: func(config.Config) (application, error) {
				t.Fatal("newApp called")
				return nil, nil
			},
			context: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
		},
	)
	if code != 2 || !strings.Contains(stderr.String(), "runtime configuration") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}
