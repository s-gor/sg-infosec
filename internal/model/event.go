package model

import (
	"fmt"
	"net/netip"
	"time"
)

type EventType string

const (
	EventAuthFailed    EventType = "auth.failed"
	EventAuthSucceeded EventType = "auth.succeeded"
	EventAPIAuthFailed EventType = "api.auth_failed"
)

func ParseEventType(value string) (EventType, error) {
	switch EventType(value) {
	case EventAuthFailed, EventAuthSucceeded, EventAPIAuthFailed:
		return EventType(value), nil
	default:
		return "", fmt.Errorf("unsupported event type %q", value)
	}
}

type Event struct {
	ID         int64
	SourceID   string
	EventID    string
	EventType  EventType
	Scope      Scope
	IP         netip.Addr
	Subject    string
	OccurredAt time.Time
	ReceivedAt time.Time
	Metadata   map[string]any
}
