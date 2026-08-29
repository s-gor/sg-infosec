//go:build linux

package nftbackend

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/internal/nftentries"
	"github.com/s-gor/sg-infosec/internal/nftschema"
)

type Driver interface {
	Inspect(context.Context) (nftschema.Snapshot, error)
	ApplySchema(context.Context, []nftschema.Operation) error
	ListElements(context.Context) ([]nftentries.Element, error)
	AddElement(context.Context, nftentries.Element) error
	RemoveElement(context.Context, nftentries.ElementKey) error
	ApplyElementPlan(context.Context, nftentries.Plan) error
}

type Backend struct {
	driver Driver
	clock  clock.Clock
	mu     sync.Mutex
}

func New(driver Driver, sourceClock clock.Clock) *Backend {
	return &Backend{driver: driver, clock: sourceClock}
}

func (b *Backend) validate() error {
	if b == nil || b.driver == nil || b.clock == nil {
		return fmt.Errorf("nftables backend is not initialized")
	}
	return nil
}

func (b *Backend) Ensure(ctx context.Context) error {
	if err := b.validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ensureLocked(ctx)
}

func (b *Backend) Add(ctx context.Context, entry enforcer.Entry) error {
	if err := b.validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	element, err := nftentries.Encode(b.clock.Now(), entry)
	if err != nil {
		return fmt.Errorf("encode nftables element: %w", err)
	}
	if err := b.ensureLocked(ctx); err != nil {
		return err
	}
	if err := b.driver.AddElement(ctx, element); err != nil {
		return fmt.Errorf("add nftables element: %w", err)
	}
	return nil
}

func (b *Backend) Remove(ctx context.Context, key enforcer.Key) error {
	if err := b.validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	elementKey, err := nftentries.EncodeKey(key)
	if err != nil {
		return fmt.Errorf("encode nftables element key: %w", err)
	}
	if err := b.ensureLocked(ctx); err != nil {
		return err
	}
	if err := b.driver.RemoveElement(ctx, elementKey); err != nil {
		return fmt.Errorf("remove nftables element: %w", err)
	}
	return nil
}

func (b *Backend) List(ctx context.Context) ([]enforcer.Entry, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.ensureLocked(ctx); err != nil {
		return nil, err
	}
	elements, err := b.driver.ListElements(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nftables elements: %w", err)
	}
	now := b.clock.Now()
	entries := make([]enforcer.Entry, 0, len(elements))
	for index, element := range elements {
		entry, err := nftentries.Decode(now, element)
		if err != nil {
			return nil, fmt.Errorf("%w: decode kernel element %d: %v", nftentries.ErrStateConflict, index, err)
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].StableID() < entries[right].StableID()
	})
	return entries, nil
}

func (b *Backend) Reconcile(ctx context.Context, desired []enforcer.Entry) (enforcer.ReconcileReport, error) {
	if err := b.validate(); err != nil {
		return enforcer.ReconcileReport{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	wanted := make([]nftentries.Element, 0, len(desired))
	for index, entry := range desired {
		element, err := nftentries.Encode(now, entry)
		if err != nil {
			return enforcer.ReconcileReport{}, fmt.Errorf("encode desired element %d: %w", index, err)
		}
		wanted = append(wanted, element)
	}
	if err := b.ensureLocked(ctx); err != nil {
		return enforcer.ReconcileReport{}, err
	}
	current, err := b.driver.ListElements(ctx)
	if err != nil {
		return enforcer.ReconcileReport{}, fmt.Errorf("list nftables elements: %w", err)
	}
	plan, err := nftentries.PlanReconcile(current, wanted)
	if err != nil {
		return enforcer.ReconcileReport{}, err
	}
	if len(plan.Add)+len(plan.Update)+len(plan.Remove) > 0 {
		if err := b.driver.ApplyElementPlan(ctx, plan); err != nil {
			return enforcer.ReconcileReport{}, fmt.Errorf("apply nftables element plan: %w", err)
		}
	}
	return enforcer.ReconcileReport{
		Created: len(plan.Add), Updated: len(plan.Update), Removed: len(plan.Remove), Unchanged: plan.Unchanged,
	}, nil
}

func (b *Backend) ensureLocked(ctx context.Context) error {
	snapshot, err := b.driver.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("inspect nftables schema: %w", err)
	}
	operations, err := nftschema.PlanEnsure(snapshot)
	if err != nil {
		return err
	}
	if len(operations) == 0 {
		return nil
	}
	if err := b.driver.ApplySchema(ctx, operations); err != nil {
		return fmt.Errorf("apply nftables schema: %w", err)
	}
	return nil
}

var _ enforcer.Backend = (*Backend)(nil)
