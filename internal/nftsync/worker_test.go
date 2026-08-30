package nftsync

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

type fakeClient struct {
	entries []enforcerprotocol.Entry
	calls   int
}

func (f *fakeClient) Reconcile(_ context.Context, _ string, entries []enforcerprotocol.Entry) (enforcerprotocol.ReconcileResponse, error) {
	f.calls++
	f.entries = append([]enforcerprotocol.Entry(nil), entries...)
	return enforcerprotocol.ReconcileResponse{}, nil
}

func TestSyncOnceExportsOnlyActiveNFTablesSSHDecisions(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	decisions := []model.Decision{
		{ID: "nft", SourceID: "local", PolicyID: "p", Scope: model.ScopeSSH, IP: netip.MustParseAddr("203.0.113.7"), Backend: model.BackendNFTables, State: model.DecisionActive, Strike: 1, ReasonCode: "test", StartsAt: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now},
		{ID: "app", SourceID: "local", PolicyID: "p", Scope: model.ScopeAdminLogin, IP: netip.MustParseAddr("203.0.113.8"), Backend: model.BackendApplication, State: model.DecisionActive, Strike: 1, ReasonCode: "test", StartsAt: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now},
	}
	for _, decision := range decisions {
		if err := db.WithTx(context.Background(), func(tx *store.Tx) error { return tx.InsertDecision(context.Background(), decision) }); err != nil {
			t.Fatal(err)
		}
	}
	client := &fakeClient{}
	worker := New(db, client, &clock.Fake{Current: now}, time.Minute)
	if err := worker.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 || len(client.entries) != 1 || client.entries[0].Port != 22 || client.entries[0].IP != "203.0.113.7" {
		t.Fatalf("calls=%d entries=%+v", client.calls, client.entries)
	}
}
