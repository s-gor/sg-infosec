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

type DecisionCheckRequest struct {
	Scope   string `json:"scope"`
	IP      string `json:"ip"`
	RouteID string `json:"route_id"`
}

type DecisionCheckResponse struct {
	Blocked    bool       `json:"blocked"`
	DecisionID string     `json:"decision_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ReasonCode string     `json:"reason_code,omitempty"`
}

type ManualDecisionRequest struct {
	SourceID          string `json:"source_id"`
	Scope             string `json:"scope"`
	Backend           string `json:"backend,omitempty"`
	IP                string `json:"ip"`
	Duration          string `json:"duration"`
	Reason            string `json:"reason"`
	OverrideAllowlist bool   `json:"override_allowlist"`
}

type DecisionView struct {
	ID         string    `json:"id"`
	SourceID   string    `json:"source_id"`
	PolicyID   string    `json:"policy_id"`
	Scope      string    `json:"scope"`
	IP         string    `json:"ip"`
	Backend    string    `json:"backend"`
	State      string    `json:"state"`
	ReasonCode string    `json:"reason_code"`
	Strike     uint32    `json:"strike"`
	StartsAt   time.Time `json:"starts_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type DecisionListResponse struct {
	Items      []DecisionView `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

type AllowlistCreateRequest struct {
	Prefix      string     `json:"prefix"`
	Scope       string     `json:"scope,omitempty"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type AllowlistView struct {
	ID          string     `json:"id"`
	Prefix      string     `json:"prefix"`
	Scope       string     `json:"scope,omitempty"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
}

type AllowlistListResponse struct {
	Items      []AllowlistView `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

type AuditView struct {
	ID         int64     `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	RequestID  string    `json:"request_id"`
	Result     string    `json:"result"`
}

type AuditListResponse struct {
	Items      []AuditView `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

type ActionResponse struct {
	Changed   bool   `json:"changed"`
	RequestID string `json:"request_id"`
}
