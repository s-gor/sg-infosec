//go:build linux

package nftbackend

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/nftentries"
	"github.com/s-gor/sg-infosec/internal/nftschema"
)

func TestEnsureInspectsAndAppliesOnlyMissingOwnedSchema(t *testing.T) {
	driver := &fakeDriver{snapshot: nftschema.Snapshot{}}
	backend := New(driver, &clock.Fake{Current: time.Now().UTC()})
	if err := backend.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if driver.inspectCalls != 1 || len(driver.schemaOperations) != 10 {
		t.Fatalf("inspect=%d operations=%+v", driver.inspectCalls, driver.schemaOperations)
	}
	if driver.schemaOperations[0].Kind != nftschema.CreateTable {
		t.Fatalf("operations=%+v", driver.schemaOperations)
	}
}

func TestSchemaConflictStopsAllMutation(t *testing.T) {
	driver := &fakeDriver{snapshot: nftschema.Snapshot{Tables: []nftschema.TableState{{Family: nftschema.FamilyINET, Name: "sg_infosec", Comment: "foreign"}}}}
	backend := New(driver, &clock.Fake{Current: time.Now().UTC()})
	if err := backend.Ensure(context.Background()); !errors.Is(err, nftschema.ErrSchemaConflict) {
		t.Fatalf("error=%v", err)
	}
	if len(driver.schemaOperations) != 0 || driver.elementApplyCalls != 0 {
		t.Fatalf("driver mutated state: %+v", driver)
	}
}

func TestAddAndRemoveValidateSchemaBeforeElementMutation(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	driver := &fakeDriver{snapshot: nftschema.CompleteSnapshot()}
	backend := New(driver, &clock.Fake{Current: now})
	entry := enforcer.Entry{Key: enforcer.Key{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22, IP: netip.MustParseAddr("203.0.113.7")}, ExpiresAt: now.Add(time.Hour)}
	if err := backend.Add(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if len(driver.added) != 1 || driver.added[0].SetName != "ssh_v4" {
		t.Fatalf("added=%+v", driver.added)
	}
	if err := backend.Remove(context.Background(), entry.Key); err != nil {
		t.Fatal(err)
	}
	if len(driver.removed) != 1 || driver.removed[0].StableID() != driver.added[0].StableID() {
		t.Fatalf("added=%+v removed=%+v", driver.added, driver.removed)
	}
	if driver.inspectCalls != 2 {
		t.Fatalf("inspect calls=%d", driver.inspectCalls)
	}
}

func TestListDecodesKernelElementsToAbsoluteEntries(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	driver := &fakeDriver{
		snapshot: nftschema.CompleteSnapshot(),
		elements: []nftentries.Element{{SetName: "panel_v4", Key: []byte{203, 0, 113, 7, 0xf7, 0xd3, 0, 0}, Timeout: time.Hour}},
	}
	backend := New(driver, &clock.Fake{Current: now})
	entries, err := backend.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Scope != model.ScopePanelPort || entries[0].Port != 63443 || entries[0].IP.String() != "203.0.113.7" || !entries[0].ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestReconcileBuildsAndAppliesOneValidatedPlan(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	current, err := nftentries.Encode(now, enforcer.Entry{Key: enforcer.Key{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22, IP: netip.MustParseAddr("203.0.113.1")}, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	driver := &fakeDriver{snapshot: nftschema.CompleteSnapshot(), elements: []nftentries.Element{current}}
	backend := New(driver, &clock.Fake{Current: now})
	desired := []enforcer.Entry{
		{Key: enforcer.Key{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22, IP: netip.MustParseAddr("203.0.113.1")}, ExpiresAt: now.Add(time.Hour)},
		{Key: enforcer.Key{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22, IP: netip.MustParseAddr("203.0.113.2")}, ExpiresAt: now.Add(2 * time.Hour)},
	}
	report, err := backend.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if report.Created != 1 || report.Unchanged != 1 || driver.elementApplyCalls != 1 || len(driver.plan.Add) != 1 {
		t.Fatalf("report=%+v driver=%+v", report, driver)
	}
}

func TestReconcileDoesNotApplyPartialPlanOnInvalidKernelState(t *testing.T) {
	driver := &fakeDriver{snapshot: nftschema.CompleteSnapshot(), elements: []nftentries.Element{{SetName: "foreign", Key: []byte{1, 2, 3, 4}, Timeout: time.Hour}}}
	backend := New(driver, &clock.Fake{Current: time.Now().UTC()})
	report, err := backend.Reconcile(context.Background(), nil)
	if !errors.Is(err, nftentries.ErrStateConflict) || report != (enforcer.ReconcileReport{}) || driver.elementApplyCalls != 0 {
		t.Fatalf("report=%+v err=%v calls=%d", report, err, driver.elementApplyCalls)
	}
}

func TestInvalidDesiredStateDoesNotCreateSchema(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	driver := &fakeDriver{snapshot: nftschema.Snapshot{}}
	backend := New(driver, &clock.Fake{Current: now})
	invalid := enforcer.Entry{
		Key:       enforcer.Key{Scope: model.ScopePanelPort, Protocol: enforcer.ProtocolTCP, Port: 585, IP: netip.MustParseAddr("203.0.113.7")},
		ExpiresAt: now.Add(time.Hour),
	}
	if err := backend.Add(context.Background(), invalid); !errors.Is(err, nftentries.ErrInvalidElement) {
		t.Fatalf("add error=%v", err)
	}
	if _, err := backend.Reconcile(context.Background(), []enforcer.Entry{invalid}); !errors.Is(err, nftentries.ErrInvalidElement) {
		t.Fatalf("reconcile error=%v", err)
	}
	if driver.inspectCalls != 0 || len(driver.schemaOperations) != 0 || len(driver.added) != 0 || driver.elementApplyCalls != 0 {
		t.Fatalf("invalid input mutated or inspected driver: %+v", driver)
	}
}

func TestBackendRejectsMissingDependencies(t *testing.T) {
	for index, backend := range []*Backend{nil, New(nil, &clock.Fake{}), New(&fakeDriver{}, nil)} {
		if err := backend.Ensure(context.Background()); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

type fakeDriver struct {
	snapshot          nftschema.Snapshot
	elements          []nftentries.Element
	inspectCalls      int
	schemaOperations  []nftschema.Operation
	added             []nftentries.Element
	removed           []nftentries.ElementKey
	plan              nftentries.Plan
	elementApplyCalls int
}

func (f *fakeDriver) Inspect(context.Context) (nftschema.Snapshot, error) {
	f.inspectCalls++
	return f.snapshot, nil
}
func (f *fakeDriver) ApplySchema(_ context.Context, operations []nftschema.Operation) error {
	f.schemaOperations = append([]nftschema.Operation(nil), operations...)
	return nil
}
func (f *fakeDriver) ListElements(context.Context) ([]nftentries.Element, error) {
	return append([]nftentries.Element(nil), f.elements...), nil
}
func (f *fakeDriver) AddElement(_ context.Context, element nftentries.Element) error {
	f.added = append(f.added, element)
	return nil
}
func (f *fakeDriver) RemoveElement(_ context.Context, element nftentries.ElementKey) error {
	f.removed = append(f.removed, element)
	return nil
}
func (f *fakeDriver) ApplyElementPlan(_ context.Context, plan nftentries.Plan) error {
	f.elementApplyCalls++
	f.plan = plan
	return nil
}

var _ Driver = (*fakeDriver)(nil)
