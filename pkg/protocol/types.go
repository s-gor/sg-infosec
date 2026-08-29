package protocol

import "time"

type EventRequest struct {
	EventID    string         `json:"event_id"`
	EventType  string         `json:"event_type"`
	Scope      string         `json:"scope"`
	IP         string         `json:"ip"`
	Subject    string         `json:"subject,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type EventResponse struct {
	Accepted   bool   `json:"accepted"`
	Duplicate  bool   `json:"duplicate"`
	DecisionID string `json:"decision_id,omitempty"`
	RequestID  string `json:"request_id"`
}

type ErrorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}
