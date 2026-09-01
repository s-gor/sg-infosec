//go:build cgo

package engine

import (
	"context"
	"net/netip"
	"testing"

	"github.com/s-gor/sg-infosec/internal/model"
)

func TestEngineCanTargetDecisionAtProtectedSource(t *testing.T) {
	fixture := newFixture(t, 1)
	fixture.policy.SourceID = "sg-infosec-detector"
	fixture.policy.DecisionSourceID = "sg-gateway"
	fixture.engine = New(fixture.store, fixture.clock, []model.Policy{fixture.policy})

	result, err := fixture.process(0, "sg-infosec-detector", "192.0.2.44")
	if err != nil {
		t.Fatal(err)
	}
	if result.DecisionID == "" {
		t.Fatal("targeted decision was not created")
	}

	address := netip.MustParseAddr("192.0.2.44")
	gatewayDecision, err := fixture.store.GetActiveDecision(context.Background(), "sg-gateway", model.ScopeAdminLogin, address, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if gatewayDecision == nil || gatewayDecision.SourceID != "sg-gateway" {
		t.Fatalf("gateway decision = %#v", gatewayDecision)
	}
	detectorDecision, err := fixture.store.GetActiveDecision(context.Background(), "sg-infosec-detector", model.ScopeAdminLogin, address, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if detectorDecision != nil {
		t.Fatalf("decision leaked into event source: %#v", detectorDecision)
	}
}
