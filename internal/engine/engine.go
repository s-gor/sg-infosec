package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
)

type Result struct {
	Duplicate  bool
	DecisionID string
}

type Engine struct {
	mu          sync.Mutex
	store       *store.Store
	clock       clock.Clock
	policies    []model.Policy
	idGenerator func() (string, error)
}

func New(database *store.Store, sourceClock clock.Clock, policies []model.Policy) *Engine {
	copied := append([]model.Policy(nil), policies...)
	return &Engine{store: database, clock: sourceClock, policies: copied, idGenerator: randomID}
}

func (e *Engine) Process(ctx context.Context, source sourceauth.Identity, event model.Event) (Result, error) {
	if e == nil || e.store == nil || e.clock == nil || e.idGenerator == nil {
		return Result{}, fmt.Errorf("policy engine is not initialized")
	}
	if source.SourceID == "" {
		return Result{}, fmt.Errorf("source identity is required")
	}
	if event.SourceID != "" && event.SourceID != source.SourceID {
		return Result{}, fmt.Errorf("event source %q does not match peer source %q", event.SourceID, source.SourceID)
	}
	if !event.IP.IsValid() {
		return Result{}, fmt.Errorf("event IP is invalid")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock.Now().UTC()
	event.SourceID = source.SourceID
	event.IP = event.IP.Unmap()
	event.ReceivedAt = now
	if event.OccurredAt.IsZero() {
		event.OccurredAt = now
	}

	result := Result{}
	err := e.store.WithTx(ctx, func(tx *store.Tx) error {
		inserted, err := tx.InsertEvent(ctx, event)
		if err != nil {
			return err
		}
		if !inserted {
			result.Duplicate = true
			return nil
		}

		for _, policy := range e.policies {
			if !policy.Enabled || policy.EventType != event.EventType || policy.Scope != event.Scope {
				continue
			}
			if policy.SourceID != "" && policy.SourceID != source.SourceID {
				continue
			}
			if policy.Backend != model.BackendApplication && policy.Backend != model.BackendNFTables {
				return fmt.Errorf("policy %q uses unsupported backend %q", policy.ID, policy.Backend)
			}
			if policy.Backend == model.BackendNFTables && policy.Scope != model.ScopeSSH {
				return fmt.Errorf("policy %q uses nftables for non-SSH scope %q", policy.ID, policy.Scope)
			}
			decisionSourceID := source.SourceID
			if policy.DecisionSourceID != "" {
				decisionSourceID = policy.DecisionSourceID
			}
			count, err := tx.CountEvents(ctx, source.SourceID, event.EventType, event.Scope, event.IP, now.Add(-policy.Window))
			if err != nil {
				return err
			}
			if uint32(count) < policy.Threshold {
				continue
			}
			allowlisted, err := tx.IsAllowlisted(ctx, event.Scope, event.IP, now)
			if err != nil {
				return err
			}
			if allowlisted {
				continue
			}
			active, err := tx.FindActiveDecision(ctx, decisionSourceID, event.Scope, event.IP, now)
			if err != nil {
				return err
			}
			if active != nil {
				continue
			}

			strike := uint32(1)
			previous, err := tx.FindLastPolicyDecision(ctx, decisionSourceID, policy.ID, event.IP, now.Add(-policy.ResetInterval))
			if err != nil {
				return err
			}
			if previous != nil {
				strike = previous.Strike + 1
			}
			duration := durationForStrike(policy.BaseDuration, policy.EscalationFactor, strike, policy.MaxDuration)
			id, err := e.idGenerator()
			if err != nil {
				return fmt.Errorf("generate decision ID: %w", err)
			}
			decision := model.Decision{ID: id, SourceID: decisionSourceID, PolicyID: policy.ID, Scope: policy.Scope, IP: event.IP, Backend: policy.Backend, State: model.DecisionActive, ReasonCode: "threshold_exceeded", Strike: strike, StartsAt: now, ExpiresAt: now.Add(duration), CreatedAt: now, UpdatedAt: now}
			if err := tx.InsertDecision(ctx, decision); err != nil {
				return err
			}
			if err := tx.AppendAudit(ctx, model.AuditEntry{OccurredAt: now, Actor: "system:" + source.SourceID, Action: "decision.auto_created", TargetType: "decision", TargetID: id, RequestID: event.EventID, Result: "success", Details: map[string]any{"policy_id": policy.ID, "scope": string(policy.Scope), "strike": strike, "event_source_id": source.SourceID, "decision_source_id": decisionSourceID}}); err != nil {
				return err
			}
			if result.DecisionID == "" {
				result.DecisionID = id
			}
		}
		return nil
	})
	return result, err
}

func durationForStrike(base time.Duration, factor uint32, strike uint32, maximum time.Duration) time.Duration {
	if base <= 0 || maximum <= 0 {
		return 0
	}
	if base >= maximum {
		return maximum
	}
	value := base
	for n := uint32(1); n < strike; n++ {
		if factor == 0 {
			return maximum
		}
		if factor == 1 {
			return value
		}
		if value > maximum/time.Duration(factor) {
			return maximum
		}
		value *= time.Duration(factor)
		if value >= maximum {
			return maximum
		}
	}
	return value
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
