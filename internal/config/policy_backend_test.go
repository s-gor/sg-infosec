package config

import (
	"testing"

	"github.com/s-gor/sg-infosec/internal/model"
)

func TestValidatePolicyBackend(t *testing.T) {
	tests := []struct {
		name    string
		backend model.Backend
		scope   model.Scope
		valid   bool
	}{
		{name: "application login", backend: model.BackendApplication, scope: model.ScopeAdminLogin, valid: true},
		{name: "application api", backend: model.BackendApplication, scope: model.ScopeAdminAPI, valid: true},
		{name: "nftables ssh", backend: model.BackendNFTables, scope: model.ScopeSSH, valid: true},
		{name: "nftables login", backend: model.BackendNFTables, scope: model.ScopeAdminLogin},
		{name: "nftables panel", backend: model.BackendNFTables, scope: model.ScopePanelPort},
		{name: "application ssh", backend: model.BackendApplication, scope: model.ScopeSSH},
		{name: "unknown", backend: "other", scope: model.ScopeSSH},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyBackend(model.Policy{ID: "p", Backend: test.backend, Scope: test.scope})
			if (err == nil) != test.valid {
				t.Fatalf("error=%v valid=%v", err, test.valid)
			}
		})
	}
}
