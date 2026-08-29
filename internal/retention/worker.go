package retention

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/store"
)

type Config struct {
	EventRetention time.Duration
	AuditRetention time.Duration
	Interval       time.Duration
	BatchSize      int
	MaxBatches     int
}

type Result struct {
	EventsDeleted int64
	AuditDeleted  int64
}

type Status struct {
	LastSuccessAt *time.Time
	LastError     string
}

type Worker struct {
	store  *store.Store
	clock  clock.Clock
	config Config
	mu     sync.RWMutex
	status Status
}

func New(database *store.Store, sourceClock clock.Clock, config Config) *Worker {
	if config.Interval <= 0 {
		config.Interval = 15 * time.Minute
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 1000
	}
	if config.MaxBatches <= 0 {
		config.MaxBatches = 10
	}
	return &Worker{store: database, clock: sourceClock, config: config}
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(w.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_, _ = w.RunOnce(ctx)
		}
	}
}

func (w *Worker) RunOnce(ctx context.Context) (Result, error) {
	if err := w.validate(); err != nil {
		return Result{}, err
	}
	now := w.clock.Now().UTC()
	var result Result
	var err error
	result.EventsDeleted, err = w.deleteBatches(ctx, func(ctx context.Context, limit int) (int64, error) {
		return w.store.DeleteEventsBefore(ctx, now.Add(-w.config.EventRetention), limit)
	})
	if err == nil {
		result.AuditDeleted, err = w.deleteBatches(ctx, func(ctx context.Context, limit int) (int64, error) {
			return w.store.DeleteAuditBefore(ctx, now.Add(-w.config.AuditRetention), limit)
		})
	}
	w.mu.Lock()
	if err != nil {
		w.status.LastError = "retention cycle failed"
	} else {
		at := now
		w.status.LastSuccessAt = &at
		w.status.LastError = ""
	}
	w.mu.Unlock()
	return result, err
}

func (w *Worker) Status() Status {
	w.mu.RLock()
	defer w.mu.RUnlock()
	status := w.status
	if status.LastSuccessAt != nil {
		value := *status.LastSuccessAt
		status.LastSuccessAt = &value
	}
	return status
}

func (w *Worker) deleteBatches(ctx context.Context, deleteFn func(context.Context, int) (int64, error)) (int64, error) {
	var total int64
	for i := 0; i < w.config.MaxBatches; i++ {
		deleted, err := deleteFn(ctx, w.config.BatchSize)
		if err != nil {
			return total, err
		}
		total += deleted
		if deleted < int64(w.config.BatchSize) {
			break
		}
	}
	return total, nil
}

func (w *Worker) validate() error {
	if w == nil || w.store == nil || w.clock == nil {
		return fmt.Errorf("retention worker is not initialized")
	}
	if w.config.EventRetention <= 0 || w.config.AuditRetention <= 0 {
		return fmt.Errorf("retention durations must be greater than zero")
	}
	if w.config.Interval <= 0 || w.config.BatchSize < 1 || w.config.MaxBatches < 1 {
		return fmt.Errorf("retention worker configuration is invalid")
	}
	return nil
}
