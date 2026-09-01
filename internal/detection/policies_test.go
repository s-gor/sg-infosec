package detection

import (
	"testing"

	"github.com/s-gor/sg-infosec/internal/model"
)

func TestBuiltInPoliciesCreateNarrowScopedDecisionsFromSignals(t *testing.T) {
	t.Parallel()
	policies := BuiltInPolicies()
	if len(policies) != 3 {
		t.Fatalf("policies = %d, want 3", len(policies))
	}
	byScope := make(map[model.Scope]model.Policy, len(policies))
	for _, policy := range policies {
		if policy.SourceID != DetectorSourceID || policy.Threshold != 1 || !policy.Enabled {
			t.Fatalf("unsafe detector policy: %#v", policy)
		}
		byScope[policy.Scope] = policy
	}
	if byScope[model.ScopeSSH].Backend != model.BackendNFTables || byScope[model.ScopeSSH].DecisionSourceID != DetectorSourceID {
		t.Fatalf("SSH policy = %#v", byScope[model.ScopeSSH])
	}
	if byScope[model.ScopeAdminLogin].Backend != model.BackendApplication || byScope[model.ScopeAdminLogin].DecisionSourceID != GatewayDecisionSourceID {
		t.Fatalf("admin-login policy = %#v", byScope[model.ScopeAdminLogin])
	}
	if byScope[model.ScopeAdminAPI].Backend != model.BackendApplication || byScope[model.ScopeAdminAPI].DecisionSourceID != GatewayDecisionSourceID {
		t.Fatalf("admin-api policy = %#v", byScope[model.ScopeAdminAPI])
	}
}
