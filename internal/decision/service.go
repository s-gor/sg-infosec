package decision

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
)

type CheckResult struct {
	Blocked    bool
	DecisionID string
	ExpiresAt  time.Time
	ReasonCode string
}

type Service struct {
	store *store.Store
	clock clock.Clock
}

func NewService(database *store.Store, sourceClock clock.Clock) *Service {
	return &Service{store: database, clock: sourceClock}
}

func (s *Service) Check(ctx context.Context, sourceID string, scope model.Scope, ip netip.Addr) (CheckResult, error) {
	if s == nil || s.store == nil || s.clock == nil {
		return CheckResult{}, fmt.Errorf("decision service is not initialized")
	}
	if sourceID == "" {
		return CheckResult{}, fmt.Errorf("source ID is required")
	}
	if !ip.IsValid() {
		return CheckResult{}, fmt.Errorf("IP address is invalid")
	}
	now := s.clock.Now().UTC()
	var result CheckResult
	err := s.store.WithTx(ctx, func(tx *store.Tx) error {
		current, err := tx.FindLatestActiveDecision(ctx, sourceID, scope, ip.Unmap())
		if err != nil {
			return err
		}
		if current == nil {
			return nil
		}
		if !current.ExpiresAt.After(now) {
			if err := tx.MarkDecisionExpired(ctx, current.ID, now); err != nil {
				return err
			}
			return tx.AppendAudit(ctx, model.AuditEntry{
				OccurredAt: now, Actor: "system", Action: "decision.expired",
				TargetType: "decision", TargetID: current.ID,
				RequestID: "expiry:" + current.ID, Result: "success",
			})
		}
		result = CheckResult{Blocked: true, DecisionID: current.ID, ExpiresAt: current.ExpiresAt, ReasonCode: current.ReasonCode}
		return nil
	})
	return result, err
}
