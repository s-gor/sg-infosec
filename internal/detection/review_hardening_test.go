package detection

import (
	"net/netip"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

func TestCorrelatorEmitsAtMostOneSignalPerEventTypeAndScope(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	config := DefaultCorrelatorConfig()
	config.CrossThreshold = 175
	correlator := NewCorrelator(config)
	address := "203.0.113.90"
	for index := 0; index < 5; index++ {
		correlator.Observe(finding(address, CategoryHTTPAdminProbe, ServiceHTTP, base.Add(time.Duration(index)*time.Second), ""))
	}
	for index := 0; index < 4; index++ {
		correlator.Observe(finding(address, CategorySSHAuthFailed, ServiceSSH, base.Add(time.Duration(10+index)*time.Second), ""))
	}
	signals := correlator.Observe(finding(address, CategorySSHAuthFailed, ServiceSSH, base.Add(20*time.Second), ""))
	counts := make(map[string]int)
	for _, signal := range signals {
		counts[signal.EventType+"/"+signal.Scope]++
	}
	if counts["auth.failed/ssh"] != 1 {
		t.Fatalf("SSH signals = %d, want 1: %#v", counts["auth.failed/ssh"], signals)
	}
	if counts["api.auth_failed/admin-api"] != 1 {
		t.Fatalf("admin-api signals = %d, want 1: %#v", counts["api.auth_failed/admin-api"], signals)
	}
}

func TestCorrelatorPrunesLateOutOfOrderFindings(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("198.51.100.80")
	correlator := NewCorrelator(DefaultCorrelatorConfig())
	correlator.Observe(finding(address.String(), CategorySSHAuthFailed, ServiceSSH, base.Add(60*time.Minute), ""))
	correlator.Observe(finding(address.String(), CategorySSHAuthFailed, ServiceSSH, base.Add(-120*time.Minute), ""))
	correlator.Observe(finding(address.String(), CategorySSHAuthFailed, ServiceSSH, base.Add(61*time.Minute), ""))
	state := correlator.states[address]
	if state == nil {
		t.Fatal("state disappeared")
	}
	for _, item := range state.findings {
		if item.OccurredAt.Before(base.Add(time.Minute)) {
			t.Fatalf("expired out-of-order finding retained: %s", item.OccurredAt)
		}
	}
}

func TestMergePoliciesKeepsDetectorPolicyAheadOfBroadConfiguredPolicy(t *testing.T) {
	t.Parallel()
	broad := model.Policy{
		ID:               "custom-broad-ssh",
		Enabled:          true,
		EventType:        model.EventAuthFailed,
		Scope:            model.ScopeSSH,
		Threshold:        1,
		Window:           time.Minute,
		BaseDuration:     time.Minute,
		EscalationFactor: 1,
		MaxDuration:      time.Minute,
		ResetInterval:    time.Hour,
		Backend:          model.BackendApplication,
	}
	policies := MergePolicies([]model.Policy{broad})
	if len(policies) < 4 {
		t.Fatalf("policies = %d, want at least 4", len(policies))
	}
	if policies[0].ID != "sg-infosec-detector-ssh" || policies[0].Backend != model.BackendNFTables {
		t.Fatalf("first policy = %#v", policies[0])
	}
}

func TestMergePoliciesAllowsExplicitBuiltInOverrideInItsPrioritySlot(t *testing.T) {
	t.Parallel()
	override := BuiltInPolicies()[0]
	override.BaseDuration = 45 * time.Minute
	policies := MergePolicies([]model.Policy{override})
	if policies[0].ID != override.ID || policies[0].BaseDuration != override.BaseDuration {
		t.Fatalf("override not applied in detector slot: %#v", policies[0])
	}
	count := 0
	for _, policy := range policies {
		if policy.ID == override.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("override policy occurs %d times", count)
	}
}
