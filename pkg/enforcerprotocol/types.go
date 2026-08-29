package enforcerprotocol

import "time"

const (
	APIVersion    = "v1"
	SchemaVersion = 1
)

type Protocol string

const ProtocolTCP Protocol = "tcp"

type Key struct {
	Scope    string   `json:"scope"`
	Protocol Protocol `json:"protocol"`
	Port     uint16   `json:"port"`
	IP       string   `json:"ip"`
}

type Entry struct {
	Scope     string    `json:"scope"`
	Protocol  Protocol  `json:"protocol"`
	Port      uint16    `json:"port"`
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

type EnsureRequest struct {
	RequestID     string `json:"request_id"`
	SchemaVersion int    `json:"schema_version"`
}

type MutationRequest struct {
	RequestID string `json:"request_id"`
	Entry     Entry  `json:"entry"`
}

type RemoveRequest struct {
	RequestID string `json:"request_id"`
	Key       Key    `json:"key"`
}

type ReconcileRequest struct {
	RequestID string  `json:"request_id"`
	Entries   []Entry `json:"entries"`
}

type ReconcileResponse struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Removed   int `json:"removed"`
	Unchanged int `json:"unchanged"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ActionResponse struct {
	OK bool `json:"ok"`
}

type ListResponse struct {
	Entries []Entry `json:"entries"`
}
