package nftsync

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

type Client interface {
	Reconcile(context.Context, string, []enforcerprotocol.Entry) (enforcerprotocol.ReconcileResponse, error)
}

type Worker struct {
	store    *store.Store
	client   Client
	clock    clock.Clock
	interval time.Duration
	trigger  chan struct{}
	sequence atomic.Uint64
	mu       sync.Mutex
}

func New(database *store.Store, client Client, sourceClock clock.Clock, interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Worker{store: database, client: client, clock: sourceClock, interval: interval, trigger: make(chan struct{}, 1)}
}

func (w *Worker) Trigger() {
	if w == nil {
		return
	}
	select {
	case w.trigger <- struct{}{}:
	default:
	}
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	if err := w.SyncOnce(ctx); err != nil {
		// Keep the unprivileged core available when the privileged helper is temporarily down.
	}
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-w.trigger:
		}
		syncCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = w.SyncOnce(syncCtx)
		cancel()
	}
}

func (w *Worker) SyncOnce(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock.Now().UTC()
	entries := make([]enforcerprotocol.Entry, 0)
	cursor := (*store.DecisionCursor)(nil)
	for {
		page, err := w.store.ListDecisions(ctx, store.DecisionFilter{State: model.DecisionActive, Limit: 200, Cursor: cursor})
		if err != nil {
			return fmt.Errorf("list active decisions: %w", err)
		}
		for _, decision := range page.Items {
			if decision.Backend != model.BackendNFTables || !decision.ExpiresAt.After(now) {
				continue
			}
			if decision.Scope != model.ScopeSSH {
				continue
			}
			entries = append(entries, enforcerprotocol.Entry{
				Scope: string(decision.Scope), Protocol: enforcerprotocol.ProtocolTCP,
				Port: 22, IP: decision.IP.Unmap().String(), ExpiresAt: decision.ExpiresAt.UTC(),
			})
		}
		if page.Next == nil {
			break
		}
		cursor = page.Next
	}
	requestID := fmt.Sprintf("core-reconcile-%d", w.sequence.Add(1))
	if _, err := w.client.Reconcile(ctx, requestID, entries); err != nil {
		return fmt.Errorf("reconcile enforcer: %w", err)
	}
	return nil
}

func (w *Worker) validate() error {
	if w == nil || w.store == nil || w.client == nil || w.clock == nil {
		return fmt.Errorf("nftables sync worker is not initialized")
	}
	return nil
}
