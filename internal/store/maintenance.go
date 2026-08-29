package store

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

func (s *Store) Ping(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	value, err := scalarInt64(s.db, "SELECT 1")
	if err != nil {
		return err
	}
	if value != 1 {
		return fmt.Errorf("database ping returned %d", value)
	}
	return nil
}

func (s *Store) CountActiveDecisions(ctx context.Context, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stmt, err := s.db.prepare(`SELECT COUNT(*) FROM decisions WHERE state = ? AND expires_at > ?`)
	if err != nil {
		return 0, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, string(model.DecisionActive)); err != nil {
		return 0, err
	}
	if err := stmt.bindText(2, formatTime(now)); err != nil {
		return 0, err
	}
	row, err := stmt.step()
	if err != nil {
		return 0, err
	}
	if !row {
		return 0, fmt.Errorf("count active decisions returned no row")
	}
	return stmt.columnInt64(0), nil
}

func (s *Store) DatabaseBytes() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fmt.Errorf("store is closed")
	}
	var total int64
	for _, path := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

func (s *Store) DeleteEventsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return s.deleteBefore(ctx, "events", "received_at", cutoff, limit)
}

func (s *Store) DeleteAuditBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	return s.deleteBefore(ctx, "audit_log", "occurred_at", cutoff, limit)
}

func (s *Store) deleteBefore(ctx context.Context, table, column string, cutoff time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 10000 {
		return 0, fmt.Errorf("delete limit must be between 1 and 10000")
	}
	if table != "events" && table != "audit_log" {
		return 0, fmt.Errorf("unsupported retention table %q", table)
	}
	var deleted int64
	err := s.WithTx(ctx, func(tx *Tx) error {
		query := fmt.Sprintf(`DELETE FROM %s WHERE id IN (SELECT id FROM %s WHERE %s < ? ORDER BY id ASC LIMIT ?)`, table, table, column)
		stmt, err := tx.db.prepare(query)
		if err != nil {
			return err
		}
		defer stmt.close()
		if err := stmt.bindText(1, formatTime(cutoff)); err != nil {
			return err
		}
		if err := stmt.bindInt64(2, int64(limit)); err != nil {
			return err
		}
		if _, err := stmt.step(); err != nil {
			return err
		}
		deleted = tx.db.changes()
		return nil
	})
	return deleted, err
}
