package sourceauth

import (
	"context"
	"fmt"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
)

type Credentials struct {
	PID int
	UID uint32
	GID uint32
}

type Identity struct {
	SourceID      string
	PID           int
	UID           uint32
	GID           uint32
	AllowedEvents map[model.EventType]struct{}
	AllowedScopes map[model.Scope]struct{}
	Permissions   map[config.Permission]struct{}
}

func (i Identity) Authorize(eventType model.EventType, scope model.Scope) error {
	if _, ok := i.AllowedEvents[eventType]; !ok {
		return fmt.Errorf("source %q is not allowed to emit event type %q", i.SourceID, eventType)
	}
	if _, ok := i.AllowedScopes[scope]; !ok {
		return fmt.Errorf("source %q is not allowed to use scope %q", i.SourceID, scope)
	}
	return nil
}

func (i Identity) HasPermission(permission config.Permission) bool {
	_, ok := i.Permissions[permission]
	return ok
}

type Resolver struct {
	byUID map[uint32]config.Source
}

func NewResolver(sources []config.Source) (*Resolver, error) {
	resolver := &Resolver{byUID: make(map[uint32]config.Source, len(sources))}
	for _, source := range sources {
		if source.ID == "" {
			return nil, fmt.Errorf("source ID is required")
		}
		if existing, ok := resolver.byUID[source.UID]; ok {
			return nil, fmt.Errorf("sources %q and %q use the same UID %d", existing.ID, source.ID, source.UID)
		}
		resolver.byUID[source.UID] = source
	}
	return resolver, nil
}

func (r *Resolver) Resolve(credentials Credentials) (Identity, error) {
	if r == nil {
		return Identity{}, fmt.Errorf("source resolver is nil")
	}
	source, ok := r.byUID[credentials.UID]
	if !ok {
		return Identity{}, fmt.Errorf("unknown local UID %d", credentials.UID)
	}
	return Identity{
		SourceID:      source.ID,
		PID:           credentials.PID,
		UID:           credentials.UID,
		GID:           credentials.GID,
		AllowedEvents: source.AllowedEvents,
		AllowedScopes: source.AllowedScopes,
		Permissions:   source.Permissions,
	}, nil
}

type identityContextKey struct{}
type authenticationErrorContextKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

func WithAuthenticationError(ctx context.Context, err error) context.Context {
	return context.WithValue(ctx, authenticationErrorContextKey{}, err)
}

func AuthenticationErrorFromContext(ctx context.Context) error {
	err, _ := ctx.Value(authenticationErrorContextKey{}).(error)
	return err
}
