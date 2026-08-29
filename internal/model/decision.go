package model

import (
	"net/netip"
	"time"
)

type DecisionState string

const (
	DecisionPending DecisionState = "pending"
	DecisionActive  DecisionState = "active"
	DecisionExpired DecisionState = "expired"
	DecisionRevoked DecisionState = "revoked"
	DecisionFailed  DecisionState = "failed"
)

type Decision struct {
	ID         string
	SourceID   string
	PolicyID   string
	Scope      Scope
	IP         netip.Addr
	Backend    Backend
	State      DecisionState
	ReasonCode string
	Strike     uint32
	StartsAt   time.Time
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	RevokedAt  *time.Time
	RevokedBy  string
}

type AuditEntry struct {
	ID         int64
	OccurredAt time.Time
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	RequestID  string
	Result     string
	Details    map[string]any
}
