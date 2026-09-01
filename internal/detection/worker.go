package detection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type RecordSource interface {
	Run(context.Context, func(JournalRecord)) error
}

type EventProcessor interface {
	Process(context.Context, sourceauth.Identity, protocol.EventRequest) (protocol.EventResponse, error)
}

type Worker struct {
	source     RecordSource
	processor  EventProcessor
	correlator *Correlator
	identity   sourceauth.Identity
}

func NewWorker(source RecordSource, processor EventProcessor, correlator *Correlator) *Worker {
	if correlator == nil {
		correlator = NewCorrelator(DefaultCorrelatorConfig())
	}
	return &Worker{
		source:     source,
		processor:  processor,
		correlator: correlator,
		identity: sourceauth.Identity{
			SourceID: DetectorSourceID,
			AllowedEvents: map[model.EventType]struct{}{
				model.EventAuthFailed:    {},
				model.EventAPIAuthFailed: {},
			},
			AllowedScopes: map[model.Scope]struct{}{
				model.ScopeSSH:        {},
				model.ScopeAdminLogin: {},
				model.ScopeAdminAPI:   {},
			},
		},
	}
}

func (worker *Worker) Run(ctx context.Context) error {
	if worker == nil || worker.source == nil || worker.processor == nil || worker.correlator == nil {
		return fmt.Errorf("autonomous detection worker is not initialized")
	}
	return worker.source.Run(ctx, func(record JournalRecord) {
		worker.handle(ctx, record)
	})
}

func (worker *Worker) handle(ctx context.Context, record JournalRecord) {
	for _, finding := range Parse(record) {
		for _, signal := range worker.correlator.Observe(finding) {
			request := protocol.EventRequest{
				EventID:    detectorEventID(record, signal),
				EventType:  signal.EventType,
				Scope:      signal.Scope,
				IP:         signal.IP.String(),
				OccurredAt: signal.OccurredAt.UTC(),
				Metadata: map[string]any{
					"detector_reason": signal.Reason,
					"evidence_count":  float64(signal.Evidence),
				},
			}
			_, _ = worker.processor.Process(ctx, worker.identity, request)
		}
	}
}

func detectorEventID(record JournalRecord, signal Signal) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(record.Cursor))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(record.Unit))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(signal.EventType))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(signal.Scope))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(signal.IP.String()))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(strconv.FormatInt(signal.OccurredAt.UnixNano(), 10)))
	return "detector-" + hex.EncodeToString(digest.Sum(nil))
}
