//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/config"
)

type fakeApp struct {
	runErr error
	ran    bool
	closed bool
}

func (f *fakeApp) Run(context.Context) error { f.ran = true; return f.runErr }
func (f *fakeApp) Close() error              { f.closed = true; return nil }

func TestRunVersionPrintsBuildMetadataJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith([]string{"--version"}, &stdout, &stderr, runtimeDependencies{})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var got buildinfo.Metadata
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got != buildinfo.Info() {
		t.Fatalf("got=%+v", got)
	}
}

func TestRunCheckConfigLoadsWithoutStartingApp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	loaded := ""
	code := runWith([]string{"--check-config", "--config", "test.yaml"}, &stdout, &stderr, runtimeDependencies{
		loadConfig: func(path string) (config.Config, error) { loaded = path; return config.Config{}, nil },
		newApp:     func(config.Config) (application, error) { t.Fatal("newApp called"); return nil, nil },
		context:    func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
	})
	if code != 0 || loaded != "test.yaml" {
		t.Fatalf("code=%d loaded=%q stderr=%s", code, loaded, stderr.String())
	}
}

func TestRunReturnsTwoForConfigurationFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith(nil, &stdout, &stderr, runtimeDependencies{
		loadConfig: func(string) (config.Config, error) { return config.Config{}, errors.New("bad config") },
		newApp:     func(config.Config) (application, error) { return nil, nil },
		context:    func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
	})
	if code != 2 || !strings.Contains(stderr.String(), "configuration:") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestRunStartsAndClosesApplication(t *testing.T) {
	var stdout, stderr bytes.Buffer
	fakeApplication := &fakeApp{}
	code := runWith([]string{"--config", "ok.yaml"}, &stdout, &stderr, runtimeDependencies{
		loadConfig: func(string) (config.Config, error) { return config.Config{}, nil },
		newApp:     func(config.Config) (application, error) { return fakeApplication, nil },
		context:    func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
	})
	if code != 0 || !fakeApplication.ran || !fakeApplication.closed {
		t.Fatalf("code=%d app=%+v stderr=%s", code, fakeApplication, stderr.String())
	}
}
