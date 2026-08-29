package decision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
)

const MaxManualDuration = 168 * time.Hour

var (
	ErrAllowlisted   = errors.New("IP address is allowlisted")
	ErrAlreadyActive = errors.New("an active decision already exists")
	ErrInvalidManual = errors.New("invalid manual decision")
)

type CheckResult struct {
	Blocked    bool
	DecisionID string
	ExpiresAt  time.Time
	ReasonCode string
}

type ManualInput struct {
	SourceID          string
	Scope             model.Scope
	Backend           model.Backend
	IP                netip.Addr
	Duration          time.Duration
	Reason            string
	OverrideAllowlist bool
	Actor             string
	RequestID         string
}

type Service struct {
	store       *store.Store
	clock       clock.Clock
	idGenerator func() (string, error)
}

func NewService(database *store.Store, sourceClock clock.Clock) *Service {
	return &Service{store: database, clock: sourceClock, idGenerator: randomID}
}

func (s *Service) Check(ctx context.Context, sourceID string, scope model.Scope, ip netip.Addr) (CheckResult, error) {
	if err := s.validate(); err != nil {
		return CheckResult{}, err
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
			return tx.AppendAudit(ctx, model.AuditEntry{OccurredAt: now, Actor: "system", Action: "decision.expired", TargetType: "decision", TargetID: current.ID, RequestID: "expiry:" + current.ID, Result: "success"})
		}
		result = CheckResult{Blocked: true, DecisionID: current.ID, ExpiresAt: current.ExpiresAt, ReasonCode: current.ReasonCode}
		return nil
	})
	return result, err
}

func (s *Service) CreateManual(ctx context.Context, input ManualInput) (model.Decision, error) {
	if err := s.validate(); err != nil {
		return model.Decision{}, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.SourceID == "" || !input.IP.IsValid() || input.Duration <= 0 || input.Duration > MaxManualDuration || input.Reason == "" || len(input.Reason) > 256 {
		return model.Decision{}, ErrInvalidManual
	}
	if input.Backend == "" {
		input.Backend = model.BackendApplication
	}
	validApplication := input.Backend == model.BackendApplication && (input.Scope == model.ScopeAdminLogin || input.Scope == model.ScopeAdminAPI)
	validNFTables := input.Backend == model.BackendNFTables && input.Scope == model.ScopeSSH
	if !validApplication && !validNFTables {
		return model.Decision{}, ErrInvalidManual
	}
	if input.Actor == "" || input.RequestID == "" {
		return model.Decision{}, ErrInvalidManual
	}
	now := s.clock.Now().UTC()
	input.IP = input.IP.Unmap()
	var created model.Decision
	err := s.store.WithTx(ctx, func(tx *store.Tx) error {
		allowlisted, err := tx.IsAllowlisted(ctx, input.Scope, input.IP, now)
		if err != nil {
			return err
		}
		if allowlisted && !input.OverrideAllowlist {
			return ErrAllowlisted
		}
		active, err := tx.FindActiveDecision(ctx, input.SourceID, input.Scope, input.IP, now)
		if err != nil {
			return err
		}
		if active != nil {
			return ErrAlreadyActive
		}
		id, err := s.idGenerator()
		if err != nil {
			return fmt.Errorf("generate decision ID: %w", err)
		}
		created = model.Decision{ID: id, SourceID: input.SourceID, PolicyID: "manual", Scope: input.Scope, IP: input.IP, Backend: input.Backend, State: model.DecisionActive, ReasonCode: "manual", Strike: 1, StartsAt: now, ExpiresAt: now.Add(input.Duration), CreatedAt: now, UpdatedAt: now}
		if err := tx.InsertDecision(ctx, created); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, model.AuditEntry{OccurredAt: now, Actor: input.Actor, Action: "decision.manual_created", TargetType: "decision", TargetID: id, RequestID: input.RequestID, Result: "success", Details: map[string]any{"source_id": input.SourceID, "scope": string(input.Scope), "backend": string(input.Backend), "reason": input.Reason, "override_allowlist": input.OverrideAllowlist}})
	})
	return created, err
}

func (s *Service) Revoke(ctx context.Context, id, actor, requestID string) (bool, error) {
	if err := s.validate(); err != nil {
		return false, err
	}
	if id == "" || actor == "" || requestID == "" {
		return false, fmt.Errorf("decision ID, actor, and request ID are required")
	}
	return s.store.RevokeDecision(ctx, id, actor, requestID, s.clock.Now().UTC())
}

func (s *Service) validate() error {
	if s == nil || s.store == nil || s.clock == nil || s.idGenerator == nil {
		return fmt.Errorf("decision service is not initialized")
	}
	return nil
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
