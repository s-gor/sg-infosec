package model

import (
	"net/netip"
	"time"
)

type AllowlistEntry struct {
	ID          string
	Prefix      netip.Prefix
	Scope       *Scope
	Description string
	ExpiresAt   *time.Time
	CreatedAt   time.Time
	CreatedBy   string
}
