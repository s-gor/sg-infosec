package detection

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type recordSourceFunc func(context.Context, func(JournalRecord)) error

func (function recordSourceFunc) Run(ctx context.Context, consume func(JournalRecord)) error {
	return function(ctx, consume)
}

type capturedEvent struct {
	identity sourceauth.Identity
	request  protocol.EventRequest
}

type captureProcessor struct {
	events []capturedEvent
	err    error
}

func (processor *captureProcessor) Process(_ context.Context, identity sourceauth.Identity, request protocol.EventRequest) (protocol.EventResponse, error) {
	processor.events = append(processor.events, capturedEvent{identity: identity, request: request})
	return protocol.EventResponse{Accepted: processor.err == nil}, processor.err
}

func TestWorkerConvertsCorrelatedJournalAttackIntoInternalEvent(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	source := recordSourceFunc(func(_ context.Context, consume func(JournalRecord)) error {
		for index := 0; index < 5; index++ {
			consume(JournalRecord{
				Unit:       "ssh.service",
				Identifier: "sshd",
				Message:    "Failed password for root from 203.0.113.10 port 22 ssh2",
				Cursor:     string(rune('a' + index)),
				OccurredAt: base.Add(time.Duration(index) * time.Minute),
			})
		}
		return nil
	})
	processor := &captureProcessor{}
	worker := NewWorker(source, processor, NewCorrelator(DefaultCorrelatorConfig()))
	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(processor.events) != 1 {
		t.Fatalf("events = %d, want 1", len(processor.events))
	}
	event := processor.events[0]
	if event.identity.SourceID != DetectorSourceID {
		t.Fatalf("source = %q", event.identity.SourceID)
	}
	if event.request.EventType != string(model.EventAuthFailed) || event.request.Scope != string(model.ScopeSSH) {
		t.Fatalf("request = %#v", event.request)
	}
	if event.request.IP != "203.0.113.10" || event.request.EventID == "" {
		t.Fatalf("request = %#v", event.request)
	}
}

func TestWorkerTreatsProcessorFailureAsFailOpen(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	source := recordSourceFunc(func(_ context.Context, consume func(JournalRecord)) error {
		for index := 0; index < 6; index++ {
			consume(JournalRecord{
				Unit:       "nginx.service",
				Identifier: "nginx",
				Message:    `203.0.113.20 - - [01/Sep/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "scanner"`,
				Cursor:     string(rune('a' + index)),
				OccurredAt: base.Add(time.Duration(index) * time.Second),
			})
		}
		return nil
	})
	processor := &captureProcessor{err: errors.New("database unavailable")}
	worker := NewWorker(source, processor, NewCorrelator(DefaultCorrelatorConfig()))
	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("processor error escaped fail-open worker: %v", err)
	}
	if len(processor.events) == 0 {
		t.Fatal("processor was not called")
	}
}
