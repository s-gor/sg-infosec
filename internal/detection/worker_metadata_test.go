package detection

import (
	"context"
	"testing"
	"time"
)

func TestWorkerEmitsJSONCompatibleEvidenceCount(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	source := recordSourceFunc(func(_ context.Context, consume func(JournalRecord)) error {
		for index := 0; index < 5; index++ {
			consume(JournalRecord{
				Unit:       "ssh.service",
				Identifier: "sshd",
				Message:    "Failed password for root from 203.0.113.25 port 22 ssh2",
				Cursor:     string(rune('a' + index)),
				OccurredAt: base.Add(time.Duration(index) * time.Second),
			})
		}
		return nil
	})
	processor := &captureProcessor{}
	worker := NewWorker(source, processor, NewCorrelator(DefaultCorrelatorConfig()))
	if err := worker.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(processor.events) != 1 {
		t.Fatalf("events = %d, want 1", len(processor.events))
	}
	value, ok := processor.events[0].request.Metadata["evidence_count"].(float64)
	if !ok || value != 5 {
		t.Fatalf("evidence_count = %#v", processor.events[0].request.Metadata["evidence_count"])
	}
}
