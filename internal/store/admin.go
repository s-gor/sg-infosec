package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

var ErrNotFound = errors.New("not found")

type AllowlistCursor struct {
	CreatedAt time.Time
	ID        string
}

type AllowlistFilter struct {
	Limit  int
	Cursor *AllowlistCursor
}

type AllowlistPage struct {
	Items []model.AllowlistEntry
	Next  *AllowlistCursor
}

type AuditCursor struct {
	OccurredAt time.Time
	ID         int64
}

type AuditFilter struct {
	Limit  int
	Cursor *AuditCursor
}

type AuditPage struct {
	Items []model.AuditEntry
	Next  *AuditCursor
}

func (s *Store) GetDecisionByID(ctx context.Context, id string) (*model.Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stmt, err := s.db.prepare(decisionSelect + ` WHERE id = ? LIMIT 1`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, id); err != nil {
		return nil, err
	}
	row, err := stmt.step()
	if err != nil {
		return nil, err
	}
	if !row {
		return nil, ErrNotFound
	}
	return scanDecision(stmt)
}

func (s *Store) RevokeDecision(ctx context.Context, id, actor, requestID string, now time.Time) (bool, error) {
	changed := false
	err := s.WithTx(ctx, func(tx *Tx) error {
		decision, err := tx.findDecisionByID(ctx, id)
		if err != nil {
			return err
		}
		if decision.State == model.DecisionRevoked || decision.State == model.DecisionExpired {
			return nil
		}
		stmt, err := tx.db.prepare(`UPDATE decisions SET state = ?, updated_at = ?, revoked_at = ?, revoked_by = ? WHERE id = ? AND state NOT IN (?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.close()
		values := []string{string(model.DecisionRevoked), formatTime(now), formatTime(now), actor, id, string(model.DecisionRevoked), string(model.DecisionExpired)}
		for index, value := range values {
			if err := stmt.bindText(index+1, value); err != nil {
				return err
			}
		}
		if _, err := stmt.step(); err != nil {
			return err
		}
		if tx.db.changes() == 0 {
			return nil
		}
		changed = true
		return tx.AppendAudit(ctx, model.AuditEntry{OccurredAt: now, Actor: actor, Action: "decision.revoked", TargetType: "decision", TargetID: id, RequestID: requestID, Result: "success"})
	})
	return changed, err
}

func (tx *Tx) findDecisionByID(ctx context.Context, id string) (*model.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stmt, err := tx.db.prepare(decisionSelect + ` WHERE id = ? LIMIT 1`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, id); err != nil {
		return nil, err
	}
	row, err := stmt.step()
	if err != nil {
		return nil, err
	}
	if !row {
		return nil, ErrNotFound
	}
	return scanDecision(stmt)
}

func (s *Store) ListAllowlist(ctx context.Context, filter AllowlistFilter) (AllowlistPage, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	if filter.Limit < 1 || filter.Limit > 200 {
		return AllowlistPage{}, fmt.Errorf("allowlist page limit must be between 1 and 200")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return AllowlistPage{}, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return AllowlistPage{}, err
	}
	query := `SELECT id, prefix, scope, description, expires_at, created_at, created_by FROM allowlist_entries`
	var args []string
	if filter.Cursor != nil {
		query += ` WHERE (created_at < ? OR (created_at = ? AND id < ?))`
		created := formatTime(filter.Cursor.CreatedAt)
		args = []string{created, created, filter.Cursor.ID}
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	stmt, err := s.db.prepare(query)
	if err != nil {
		return AllowlistPage{}, err
	}
	defer stmt.close()
	for i, v := range args {
		if err := stmt.bindText(i+1, v); err != nil {
			return AllowlistPage{}, err
		}
	}
	if err := stmt.bindInt64(len(args)+1, int64(filter.Limit+1)); err != nil {
		return AllowlistPage{}, err
	}
	items := make([]model.AllowlistEntry, 0, filter.Limit+1)
	for {
		row, err := stmt.step()
		if err != nil {
			return AllowlistPage{}, err
		}
		if !row {
			break
		}
		entry, err := scanAllowlist(stmt)
		if err != nil {
			return AllowlistPage{}, err
		}
		items = append(items, *entry)
	}
	page := AllowlistPage{Items: items}
	if len(items) > filter.Limit {
		page.Items = items[:filter.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &AllowlistCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}

func scanAllowlist(stmt *sqliteStmt) (*model.AllowlistEntry, error) {
	prefix, err := netip.ParsePrefix(stmt.columnText(1))
	if err != nil {
		return nil, err
	}
	entry := &model.AllowlistEntry{ID: stmt.columnText(0), Prefix: prefix, Description: stmt.columnText(3), CreatedBy: stmt.columnText(6)}
	if !stmt.columnIsNull(2) {
		scope := model.Scope(stmt.columnText(2))
		entry.Scope = &scope
	}
	if !stmt.columnIsNull(4) {
		expires, err := parseTime(stmt.columnText(4))
		if err != nil {
			return nil, err
		}
		entry.ExpiresAt = &expires
	}
	created, err := parseTime(stmt.columnText(5))
	if err != nil {
		return nil, err
	}
	entry.CreatedAt = created
	return entry, nil
}

func (s *Store) DeleteAllowlistEntry(ctx context.Context, id, actor, requestID string, now time.Time) (bool, error) {
	changed := false
	err := s.WithTx(ctx, func(tx *Tx) error {
		stmt, err := tx.db.prepare(`DELETE FROM allowlist_entries WHERE id = ?`)
		if err != nil {
			return err
		}
		defer stmt.close()
		if err := stmt.bindText(1, id); err != nil {
			return err
		}
		if _, err := stmt.step(); err != nil {
			return err
		}
		if tx.db.changes() == 0 {
			return ErrNotFound
		}
		changed = true
		return tx.AppendAudit(ctx, model.AuditEntry{OccurredAt: now, Actor: actor, Action: "allowlist.deleted", TargetType: "allowlist", TargetID: id, RequestID: requestID, Result: "success"})
	})
	return changed, err
}

func (s *Store) ListAudit(ctx context.Context, filter AuditFilter) (AuditPage, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	if filter.Limit < 1 || filter.Limit > 200 {
		return AuditPage{}, fmt.Errorf("audit page limit must be between 1 and 200")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return AuditPage{}, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return AuditPage{}, err
	}
	query := `SELECT id, occurred_at, actor, action, target_type, target_id, request_id, result, details_json FROM audit_log`
	if filter.Cursor != nil {
		query += ` WHERE (occurred_at < ? OR (occurred_at = ? AND id < ?))`
	}
	query += ` ORDER BY occurred_at DESC, id DESC LIMIT ?`
	stmt, err := s.db.prepare(query)
	if err != nil {
		return AuditPage{}, err
	}
	defer stmt.close()
	limitIndex := 1
	if filter.Cursor != nil {
		at := formatTime(filter.Cursor.OccurredAt)
		if err := stmt.bindText(1, at); err != nil {
			return AuditPage{}, err
		}
		if err := stmt.bindText(2, at); err != nil {
			return AuditPage{}, err
		}
		if err := stmt.bindInt64(3, filter.Cursor.ID); err != nil {
			return AuditPage{}, err
		}
		limitIndex = 4
	}
	if err := stmt.bindInt64(limitIndex, int64(filter.Limit+1)); err != nil {
		return AuditPage{}, err
	}
	items := make([]model.AuditEntry, 0, filter.Limit+1)
	for {
		row, err := stmt.step()
		if err != nil {
			return AuditPage{}, err
		}
		if !row {
			break
		}
		at, err := parseTime(stmt.columnText(1))
		if err != nil {
			return AuditPage{}, err
		}
		entry := model.AuditEntry{ID: stmt.columnInt64(0), OccurredAt: at, Actor: stmt.columnText(2), Action: stmt.columnText(3), TargetType: stmt.columnText(4), TargetID: stmt.columnText(5), RequestID: stmt.columnText(6), Result: stmt.columnText(7)}
		if raw := stmt.columnText(8); raw != "" {
			_ = json.Unmarshal([]byte(raw), &entry.Details)
		}
		items = append(items, entry)
	}
	page := AuditPage{Items: items}
	if len(items) > filter.Limit {
		page.Items = items[:filter.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &AuditCursor{OccurredAt: last.OccurredAt, ID: last.ID}
	}
	return page, nil
}
