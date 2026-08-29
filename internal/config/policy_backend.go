package config

import (
	"fmt"

	"github.com/s-gor/sg-infosec/internal/model"
)

func validatePolicyBackend(policy model.Policy) error {
	switch policy.Backend {
	case model.BackendApplication:
		if policy.Scope != model.ScopeAdminLogin && policy.Scope != model.ScopeAdminAPI {
			return fmt.Errorf("policy %q: application backend does not support scope %q", policy.ID, policy.Scope)
		}
	case model.BackendNFTables:
		if policy.Scope != model.ScopeSSH {
			return fmt.Errorf("policy %q: nftables backend supports only scope %q", policy.ID, model.ScopeSSH)
		}
	default:
		return fmt.Errorf("policy %q: unsupported backend %q", policy.ID, policy.Backend)
	}
	return nil
}
