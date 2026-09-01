package detection

import (
	"net/netip"
	"time"
)

type Service string

const (
	ServiceSSH     Service = "ssh"
	ServiceHTTP    Service = "http"
	ServiceGateway Service = "sg-gateway"
)

type Category string

const (
	CategorySSHAuthFailed        Category = "ssh.auth_failed"
	CategorySSHInvalidUser       Category = "ssh.invalid_user"
	CategoryHTTPAdminProbe       Category = "http.admin_probe"
	CategoryGatewayAuthFailed    Category = "gateway.auth_failed"
	CategoryGatewayAPIAuthFailed Category = "gateway.api_auth_failed"
)

type JournalRecord struct {
	Unit       string
	Identifier string
	Message    string
	Cursor     string
	OccurredAt time.Time
}

type Finding struct {
	IP          netip.Addr
	Category    Category
	Service     Service
	OccurredAt  time.Time
	SubjectHash string
	Metadata    map[string]any
}

type Signal struct {
	EventType  string
	Scope      string
	IP         netip.Addr
	Reason     string
	Evidence   int
	OccurredAt time.Time
}

type CorrelatorConfig struct {
	MaxStates      int
	StateTTL       time.Duration
	Cooldown       time.Duration
	CrossWindow    time.Duration
	CrossThreshold int
}

func DefaultCorrelatorConfig() CorrelatorConfig {
	return CorrelatorConfig{
		MaxStates:      4096,
		StateTTL:       60 * time.Minute,
		Cooldown:       10 * time.Minute,
		CrossWindow:    15 * time.Minute,
		CrossThreshold: 100,
	}
}
