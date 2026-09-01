//go:build linux && cgo

package app

import (
	"context"
	"os"
	"testing"

	"github.com/s-gor/sg-infosec/internal/detection"
)

type blockingDetectorSource struct{}

func (blockingDetectorSource) Run(ctx context.Context, _ func(detection.JournalRecord)) error {
	<-ctx.Done()
	return nil
}

func TestNewWiresAutonomousDetectorFromInjectedSource(t *testing.T) {
	cfg := testConfig(t)
	application, err := New(cfg, Dependencies{
		UID:            uint32(os.Getuid()),
		DetectorSource: blockingDetectorSource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	if application.detector == nil {
		t.Fatal("autonomous detector was not wired")
	}
}

func TestAutonomousDetectorCanBeExplicitlyDisabled(t *testing.T) {
	t.Setenv("SG_INFOSEC_AUTONOMOUS_DETECTION", "0")
	cfg := testConfig(t)
	application, err := New(cfg, Dependencies{UID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer application.Close()
	if application.detector != nil {
		t.Fatal("autonomous detector remained enabled")
	}
}

func TestAutonomousDetectorRejectsAmbiguousMode(t *testing.T) {
	t.Setenv("SG_INFOSEC_AUTONOMOUS_DETECTION", "maybe")
	cfg := testConfig(t)
	application, err := New(cfg, Dependencies{UID: uint32(os.Getuid())})
	if application != nil {
		_ = application.Close()
	}
	if err == nil {
		t.Fatal("ambiguous autonomous detection mode was accepted")
	}
}
