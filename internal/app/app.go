//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/s-gor/sg-infosec/internal/api/control"
	"github.com/s-gor/sg-infosec/internal/api/events"
	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/decision"
	"github.com/s-gor/sg-infosec/internal/health"
	"github.com/s-gor/sg-infosec/internal/nftsync"
	"github.com/s-gor/sg-infosec/internal/retention"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/internal/transport/unixhttp"
	"github.com/s-gor/sg-infosec/pkg/enforcerclient"
)

type EnforcerClient interface {
	nftsync.Client
	CloseIdleConnections()
}

type Dependencies struct {
	Clock             clock.Clock
	UID               uint32
	RetentionInterval time.Duration
	EnforcerInterval  time.Duration
	EnforcerClient    EnforcerClient
}

type App struct {
	store          *store.Store
	lock           *instanceLock
	events         *unixhttp.Server
	control        *unixhttp.Server
	retention      *retention.Worker
	nftWorker      *nftsync.Worker
	enforcerClient EnforcerClient
	closeOnce      sync.Once
	closeErr       error
	runMu          sync.Mutex
	running        bool
	closed         bool
}

func New(cfg config.Config, dependencies Dependencies) (*App, error) {
	if cfg.DatabasePath == "" || cfg.EventsSocket == "" || cfg.ControlSocket == "" {
		return nil, fmt.Errorf("database and socket paths are required")
	}
	if cfg.EventsSocket == cfg.ControlSocket {
		return nil, fmt.Errorf("events and control sockets must be different")
	}
	if cfg.EventBodyLimit <= 0 {
		return nil, fmt.Errorf("event body limit must be greater than zero")
	}
	if cfg.Retention.Events <= 0 || cfg.Retention.Audit <= 0 {
		return nil, fmt.Errorf("retention durations must be greater than zero")
	}
	if dependencies.Clock == nil {
		dependencies.Clock = clock.Real{}
	}
	if dependencies.UID == 0 && os.Getuid() != 0 {
		dependencies.UID = uint32(os.Getuid())
	}

	lock, err := acquireInstanceLock(cfg.DatabasePath + ".lock")
	if err != nil {
		return nil, err
	}
	application := &App{lock: lock}
	cleanup := func() { _ = application.Close() }
	database, err := store.Open(context.Background(), cfg.DatabasePath)
	if err != nil {
		cleanup()
		return nil, err
	}
	application.store = database
	resolver, err := sourceauth.NewResolver(cfg.Sources)
	if err != nil {
		cleanup()
		return nil, err
	}
	worker := retention.New(database, dependencies.Clock, retention.Config{EventRetention: cfg.Retention.Events, AuditRetention: cfg.Retention.Audit, Interval: dependencies.RetentionInterval, BatchSize: 1000, MaxBatches: 10})
	application.retention = worker
	if dependencies.EnforcerClient == nil {
		dependencies.EnforcerClient = enforcerclient.New("/run/sg-infosec/enforcer.sock")
	}
	application.enforcerClient = dependencies.EnforcerClient
	application.nftWorker = nftsync.New(database, dependencies.EnforcerClient, dependencies.Clock, dependencies.EnforcerInterval)
	decisionService := decision.NewService(database, dependencies.Clock)
	eventsProcessor := events.NewProcessor(database, dependencies.Clock, cfg.Policies...).WithDecisionNotifier(application.nftWorker)
	eventsHandler := events.NewHandler(eventsProcessor, cfg.EventBodyLimit)
	knownSources := make([]string, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		knownSources = append(knownSources, source.ID)
	}
	controlHandler := control.NewHandler(decisionService, database, dependencies.Clock, knownSources, cfg.EventBodyLimit, application.nftWorker)
	healthService := health.New(database, worker, func() time.Time { return dependencies.Clock.Now().UTC() })
	mux := http.NewServeMux()
	mux.Handle("/v1/health", healthService.Handler())
	mux.Handle("/", controlHandler)
	application.events, err = unixhttp.New(unixhttp.Config{SocketPath: cfg.EventsSocket, Mode: 0660, ExpectedOwnerUID: dependencies.UID}, eventsHandler, resolver)
	if err != nil {
		cleanup()
		return nil, err
	}
	application.control, err = unixhttp.New(unixhttp.Config{SocketPath: cfg.ControlSocket, Mode: 0660, ExpectedOwnerUID: dependencies.UID}, mux, resolver)
	if err != nil {
		cleanup()
		return nil, err
	}
	return application, nil
}

func (a *App) Run(ctx context.Context) error {
	if a == nil {
		return fmt.Errorf("application is nil")
	}
	a.runMu.Lock()
	if a.closed {
		a.runMu.Unlock()
		return fmt.Errorf("application is closed")
	}
	if a.running {
		a.runMu.Unlock()
		return fmt.Errorf("application is already running")
	}
	a.running = true
	a.runMu.Unlock()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type componentResult struct {
		name string
		err  error
	}
	componentCount := 3
	if a.nftWorker != nil {
		componentCount++
	}
	results := make(chan componentResult, componentCount)
	go func() { results <- componentResult{name: "events server", err: a.events.Serve()} }()
	go func() { results <- componentResult{name: "control server", err: a.control.Serve()} }()
	go func() { results <- componentResult{name: "retention worker", err: a.retention.Run(runCtx)} }()
	if a.nftWorker != nil {
		go func() { results <- componentResult{name: "nftables sync worker", err: a.nftWorker.Run(runCtx)} }()
	}
	var runErr error
	select {
	case <-ctx.Done():
	case result := <-results:
		if result.err != nil {
			runErr = fmt.Errorf("%s: %w", result.name, result.err)
		} else {
			runErr = fmt.Errorf("%s stopped unexpectedly", result.name)
		}
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	shutdownErr := a.shutdown(shutdownCtx, true)
	return errors.Join(runErr, shutdownErr)
}

func (a *App) Close() error { return a.shutdown(context.Background(), false) }

func (a *App) shutdown(ctx context.Context, graceful bool) error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		a.runMu.Lock()
		a.closed = true
		a.runMu.Unlock()
		var errs []error
		if a.events != nil {
			if graceful {
				errs = append(errs, a.events.Shutdown(ctx))
			} else {
				errs = append(errs, a.events.Close())
			}
		}
		if a.control != nil {
			if graceful {
				errs = append(errs, a.control.Shutdown(ctx))
			} else {
				errs = append(errs, a.control.Close())
			}
		}
		if a.enforcerClient != nil {
			a.enforcerClient.CloseIdleConnections()
		}
		if a.store != nil {
			errs = append(errs, a.store.Close())
		}
		if a.lock != nil {
			errs = append(errs, a.lock.Close())
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}
