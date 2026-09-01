package model

import (
	"fmt"
	"time"
)

type Scope string

const (
	ScopeAdminLogin Scope = "admin-login"
	ScopeAdminAPI   Scope = "admin-api"
	ScopeSSH        Scope = "ssh"
	ScopePanelPort  Scope = "panel-port"
)

func ParseScope(value string) (Scope, error) {
	switch Scope(value) {
	case ScopeAdminLogin, ScopeAdminAPI, ScopeSSH, ScopePanelPort:
		return Scope(value), nil
	default:
		return "", fmt.Errorf("unsupported scope %q", value)
	}
}

type Backend string

const (
	BackendApplication Backend = "application"
	BackendNFTables    Backend = "nftables"
)

func ParseBackend(value string) (Backend, error) {
	switch Backend(value) {
	case BackendApplication, BackendNFTables:
		return Backend(value), nil
	default:
		return "", fmt.Errorf("unsupported backend %q", value)
	}
}

type Policy struct {
	ID               string
	Enabled          bool
	EventType        EventType
	Scope            Scope
	SourceID         string
	DecisionSourceID string
	Threshold        uint32
	Window           time.Duration
	BaseDuration     time.Duration
	EscalationFactor uint32
	MaxDuration      time.Duration
	ResetInterval    time.Duration
	Backend          Backend
}
