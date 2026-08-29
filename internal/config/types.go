package config

import (
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

type Permission string

const (
	PermissionCheckDecisions Permission = "check_decisions"
	PermissionReadAdmin      Permission = "read_admin"
	PermissionWriteAdmin     Permission = "write_admin"
)

type Source struct {
	ID            string
	User          string
	Group         string
	UID           uint32
	GID           *uint32
	AllowedEvents map[model.EventType]struct{}
	AllowedScopes map[model.Scope]struct{}
	Permissions   map[Permission]struct{}
}

type EventRetention struct {
	Events time.Duration
	Audit  time.Duration
}

type Config struct {
	DatabasePath   string
	EventsSocket   string
	ControlSocket  string
	EventBodyLimit int64
	Retention      EventRetention
	Sources        []Source
	Policies       []model.Policy
	Allowlist      []model.AllowlistEntry
}
