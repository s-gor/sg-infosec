package detection

import (
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

const (
	DetectorSourceID        = "sg-infosec-detector"
	GatewayDecisionSourceID = "sg-gateway"
)

func BuiltInPolicies() []model.Policy {
	return []model.Policy{
		{
			ID:               "sg-infosec-detector-ssh",
			Enabled:          true,
			EventType:        model.EventAuthFailed,
			Scope:            model.ScopeSSH,
			SourceID:         DetectorSourceID,
			DecisionSourceID: DetectorSourceID,
			Threshold:        1,
			Window:           time.Minute,
			BaseDuration:     30 * time.Minute,
			EscalationFactor: 4,
			MaxDuration:      24 * time.Hour,
			ResetInterval:    30 * 24 * time.Hour,
			Backend:          model.BackendNFTables,
		},
		{
			ID:               "sg-infosec-detector-admin-login",
			Enabled:          true,
			EventType:        model.EventAuthFailed,
			Scope:            model.ScopeAdminLogin,
			SourceID:         DetectorSourceID,
			DecisionSourceID: GatewayDecisionSourceID,
			Threshold:        1,
			Window:           time.Minute,
			BaseDuration:     30 * time.Minute,
			EscalationFactor: 4,
			MaxDuration:      24 * time.Hour,
			ResetInterval:    30 * 24 * time.Hour,
			Backend:          model.BackendApplication,
		},
		{
			ID:               "sg-infosec-detector-admin-api",
			Enabled:          true,
			EventType:        model.EventAPIAuthFailed,
			Scope:            model.ScopeAdminAPI,
			SourceID:         DetectorSourceID,
			DecisionSourceID: GatewayDecisionSourceID,
			Threshold:        1,
			Window:           time.Minute,
			BaseDuration:     15 * time.Minute,
			EscalationFactor: 4,
			MaxDuration:      24 * time.Hour,
			ResetInterval:    30 * 24 * time.Hour,
			Backend:          model.BackendApplication,
		},
	}
}

func MergePolicies(configured []model.Policy) []model.Policy {
	configuredByID := make(map[string]model.Policy, len(configured))
	for _, policy := range configured {
		configuredByID[policy.ID] = policy
	}

	result := make([]model.Policy, 0, len(configured)+len(BuiltInPolicies()))
	used := make(map[string]struct{}, len(configured))
	for _, builtIn := range BuiltInPolicies() {
		if override, exists := configuredByID[builtIn.ID]; exists {
			if override.SourceID == "" {
				override.SourceID = builtIn.SourceID
			}
			if override.DecisionSourceID == "" {
				override.DecisionSourceID = builtIn.DecisionSourceID
			}
			result = append(result, override)
			used[builtIn.ID] = struct{}{}
			continue
		}
		result = append(result, builtIn)
	}
	for _, policy := range configured {
		if _, exists := used[policy.ID]; exists {
			continue
		}
		result = append(result, policy)
	}
	return result
}
