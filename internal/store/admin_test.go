//go:build cgo

package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAdminReadQueriesRejectClosedStore(t *testing.T) {
	database, err := Open(context.Background(), filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDecisionByID(context.Background(), "missing"); err == nil {
		t.Fatal("GetDecisionByID accepted a closed store")
	}
	if _, err := database.ListAllowlist(context.Background(), AllowlistFilter{}); err == nil {
		t.Fatal("ListAllowlist accepted a closed store")
	}
	if _, err := database.ListAudit(context.Background(), AuditFilter{}); err == nil {
		t.Fatal("ListAudit accepted a closed store")
	}
}
