package sourceauth

import (
	"testing"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
)

func TestResolverMapsExactUIDToConfiguredSource(t *testing.T) {
	resolver, err := NewResolver([]config.Source{testSource(1001)})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	identity, err := resolver.Resolve(Credentials{PID: 42, UID: 1001, GID: 1002})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if identity.SourceID != "sg-gateway" || identity.UID != 1001 || identity.PID != 42 {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestResolverRejectsUnknownUID(t *testing.T) {
	resolver, err := NewResolver([]config.Source{testSource(1001)})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	if _, err := resolver.Resolve(Credentials{UID: 2001}); err == nil {
		t.Fatal("Resolve accepted an unknown UID")
	}
}

func TestResolverRejectsEventOutsideSourcePermissions(t *testing.T) {
	resolver, err := NewResolver([]config.Source{testSource(1001)})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	identity, err := resolver.Resolve(Credentials{UID: 1001})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if err := identity.Authorize(model.EventAuthFailed, model.ScopeAdminLogin); err != nil {
		t.Fatalf("Authorize allowed pair: %v", err)
	}
	if err := identity.Authorize(model.EventAuthSucceeded, model.ScopeAdminLogin); err == nil {
		t.Fatal("Authorize accepted a disallowed event type")
	}
	if err := identity.Authorize(model.EventAuthFailed, model.ScopeSSH); err == nil {
		t.Fatal("Authorize accepted a disallowed scope")
	}
}

func testSource(uid uint32) config.Source {
	return config.Source{
		ID:  "sg-gateway",
		UID: uid,
		AllowedEvents: map[model.EventType]struct{}{
			model.EventAuthFailed: {},
		},
		AllowedScopes: map[model.Scope]struct{}{
			model.ScopeAdminLogin: {},
		},
		Permissions: map[config.Permission]struct{}{
			config.PermissionCheckDecisions: {},
		},
	}
}
