//go:build linux && cgo

package app

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/detection"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

type scriptedDetectorSource struct {
	records []detection.JournalRecord
}

func (source scriptedDetectorSource) Run(ctx context.Context, consume func(detection.JournalRecord)) error {
	for _, record := range source.records {
		consume(record)
	}
	<-ctx.Done()
	return nil
}

type detectorIntegrationEnforcer struct {
	mu      sync.Mutex
	entries []enforcerprotocol.Entry
}

func (client *detectorIntegrationEnforcer) Reconcile(_ context.Context, _ string, entries []enforcerprotocol.Entry) (enforcerprotocol.ReconcileResponse, error) {
	client.mu.Lock()
	client.entries = append([]enforcerprotocol.Entry(nil), entries...)
	client.mu.Unlock()
	return enforcerprotocol.ReconcileResponse{}, nil
}

func (*detectorIntegrationEnforcer) CloseIdleConnections() {}

func (client *detectorIntegrationEnforcer) snapshot() []enforcerprotocol.Entry {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]enforcerprotocol.Entry(nil), client.entries...)
}

func TestAutonomousSSHDetectionCreatesDecisionAndReconcilesEnforcer(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	records := make([]detection.JournalRecord, 0, 5)
	for index := 0; index < 5; index++ {
		records = append(records, detection.JournalRecord{
			Unit:       "ssh.service",
			Identifier: "sshd",
			Message:    "Failed password for root from 203.0.113.77 port 22 ssh2",
			Cursor:     string(rune('a' + index)),
			OccurredAt: base.Add(time.Duration(index) * time.Minute),
		})
	}

	cfg := testConfig(t)
	fakeClock := &clock.Fake{Current: base.Add(4 * time.Minute)}
	enforcer := &detectorIntegrationEnforcer{}
	application, err := New(cfg, Dependencies{
		Clock:             fakeClock,
		UID:               uint32(os.Getuid()),
		EnforcerInterval:  time.Hour,
		EnforcerClient:    enforcer,
		DetectorSource:    scriptedDetectorSource{records: records},
		RetentionInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("application shutdown: %v", err)
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, listErr := application.store.ListDecisions(context.Background(), store.DecisionFilter{
			SourceID: detection.DetectorSourceID,
			Scope:    model.ScopeSSH,
			State:    model.DecisionActive,
			Limit:    10,
		})
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(page.Items) == 1 {
			decision := page.Items[0]
			if decision.IP != netip.MustParseAddr("203.0.113.77") {
				t.Fatalf("decision IP = %s", decision.IP)
			}
			if decision.Backend != model.BackendNFTables || decision.PolicyID != "sg-infosec-detector-ssh" {
				t.Fatalf("decision = %#v", decision)
			}
			for _, entry := range enforcer.snapshot() {
				if entry.IP == "203.0.113.77" && entry.Port == 22 && entry.Scope == string(model.ScopeSSH) {
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("detector decision or nftables reconciliation did not appear; entries=%#v", enforcer.snapshot())
}
