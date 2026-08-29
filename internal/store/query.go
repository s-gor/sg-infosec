package store

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

const decisionSelect = `SELECT id, source_id, policy_id, scope, ip, backend, state, reason_code,
	strike_count, starts_at, expires_at, created_at, updated_at, revoked_at, revoked_by FROM decisions`

type DecisionCursor struct {
	CreatedAt time.Time
	ID        string
}

type DecisionFilter struct {
	SourceID string
	Scope    model.Scope
	State    model.DecisionState
	Limit    int
	Cursor   *DecisionCursor
}

type DecisionPage struct {
	Items []model.Decision
	Next  *DecisionCursor
}

func (s *Store) GetActiveDecision(ctx context.Context, sourceID string, scope model.Scope, ip netip.Addr, now time.Time) (*model.Decision, error) {
	var decision *model.Decision
	err := s.WithTx(ctx, func(tx *Tx) error {
		var err error
		decision, err = tx.FindActiveDecision(ctx, sourceID, scope, ip, now)
		return err
	})
	return decision, err
}

func (s *Store) IsAllowlisted(ctx context.Context, scope model.Scope, ip netip.Addr, now time.Time) (bool, error) {
	var matched bool
	err := s.WithTx(ctx, func(tx *Tx) error {
		var err error
		matched, err = tx.IsAllowlisted(ctx, scope, ip, now)
		return err
	})
	return matched, err
}

func (s *Store) PutAllowlistEntry(ctx context.Context, entry model.AllowlistEntry, actor, requestID string) error {
	if !entry.Prefix.IsValid() {
		return fmt.Errorf("allowlist prefix is invalid")
	}
	if entry.ID == "" {
		return fmt.Errorf("allowlist ID is required")
	}
	if entry.Description == "" {
		return fmt.Errorf("allowlist description is required")
	}
	if entry.CreatedAt.IsZero() {
		return fmt.Errorf("allowlist created_at is required")
	}
	return s.WithTx(ctx, func(tx *Tx) error {
		stmt, err := tx.db.prepare(`INSERT INTO allowlist_entries
			(id, prefix, scope, description, expires_at, created_at, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.close()
		if err := stmt.bindText(1, entry.ID); err != nil {
			return err
		}
		if err := stmt.bindText(2, entry.Prefix.Masked().String()); err != nil {
			return err
		}
		if entry.Scope == nil {
			if err := stmt.bindNull(3); err != nil {
				return err
			}
		} else if err := stmt.bindText(3, string(*entry.Scope)); err != nil {
			return err
		}
		if err := stmt.bindText(4, entry.Description); err != nil {
			return err
		}
		if entry.ExpiresAt == nil {
			if err := stmt.bindNull(5); err != nil {
				return err
			}
		} else if err := stmt.bindText(5, formatTime(*entry.ExpiresAt)); err != nil {
			return err
		}
		if err := stmt.bindText(6, formatTime(entry.CreatedAt)); err != nil {
			return err
		}
		if err := stmt.bindText(7, entry.CreatedBy); err != nil {
			return err
		}
		if _, err := stmt.step(); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, model.AuditEntry{OccurredAt: entry.CreatedAt, Actor: actor, Action: "allowlist.created", TargetType: "allowlist", TargetID: entry.ID, RequestID: requestID, Result: "success"})
	})
}

func (s *Store) ListDecisions(ctx context.Context, filter DecisionFilter) (DecisionPage, error) {
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	if filter.Limit < 1 || filter.Limit > 200 {
		return DecisionPage{}, fmt.Errorf("decision page limit must be between 1 and 200")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return DecisionPage{}, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return DecisionPage{}, err
	}
	query := decisionSelect
	var clauses []string
	var args []string
	if filter.SourceID != "" {
		clauses = append(clauses, "source_id = ?")
		args = append(args, filter.SourceID)
	}
	if filter.Scope != "" {
		clauses = append(clauses, "scope = ?")
		args = append(args, string(filter.Scope))
	}
	if filter.State != "" {
		clauses = append(clauses, "state = ?")
		args = append(args, string(filter.State))
	}
	if filter.Cursor != nil {
		clauses = append(clauses, "(created_at < ? OR (created_at = ? AND id < ?))")
		created := formatTime(filter.Cursor.CreatedAt)
		args = append(args, created, created, filter.Cursor.ID)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT ?"
	stmt, err := s.db.prepare(query)
	if err != nil {
		return DecisionPage{}, err
	}
	defer stmt.close()
	for index, value := range args {
		if err := stmt.bindText(index+1, value); err != nil {
			return DecisionPage{}, err
		}
	}
	if err := stmt.bindInt64(len(args)+1, int64(filter.Limit+1)); err != nil {
		return DecisionPage{}, err
	}
	items := make([]model.Decision, 0, filter.Limit+1)
	for {
		row, err := stmt.step()
		if err != nil {
			return DecisionPage{}, err
		}
		if !row {
			break
		}
		decision, err := scanDecision(stmt)
		if err != nil {
			return DecisionPage{}, err
		}
		items = append(items, *decision)
	}
	page := DecisionPage{Items: items}
	if len(items) > filter.Limit {
		page.Items = items[:filter.Limit]
		last := page.Items[len(page.Items)-1]
		page.Next = &DecisionCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
}

func scanDecision(stmt *sqliteStmt) (*model.Decision, error) {
	ip, err := netip.ParseAddr(stmt.columnText(4))
	if err != nil {
		return nil, err
	}
	startsAt, err := parseTime(stmt.columnText(9))
	if err != nil {
		return nil, err
	}
	expiresAt, err := parseTime(stmt.columnText(10))
	if err != nil {
		return nil, err
	}
	createdAt, err := parseTime(stmt.columnText(11))
	if err != nil {
		return nil, err
	}
	updatedAt, err := parseTime(stmt.columnText(12))
	if err != nil {
		return nil, err
	}
	decision := &model.Decision{
		ID: stmt.columnText(0), SourceID: stmt.columnText(1), PolicyID: stmt.columnText(2), Scope: model.Scope(stmt.columnText(3)),
		IP: ip, Backend: model.Backend(stmt.columnText(5)), State: model.DecisionState(stmt.columnText(6)), ReasonCode: stmt.columnText(7),
		Strike: uint32(stmt.columnInt64(8)), StartsAt: startsAt, ExpiresAt: expiresAt, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	if !stmt.columnIsNull(13) {
		value, err := parseTime(stmt.columnText(13))
		if err != nil {
			return nil, err
		}
		decision.RevokedAt = &value
	}
	if !stmt.columnIsNull(14) {
		decision.RevokedBy = stmt.columnText(14)
	}
	return decision, nil
}

func (s *Store) pragmaInt(ctx context.Context, name string) (int64, error) {
	if name != "foreign_keys" && name != "busy_timeout" {
		return 0, fmt.Errorf("unsupported pragma %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return scalarInt64(s.db, "PRAGMA "+name)
}

func (s *Store) pragmaText(ctx context.Context, name string) (string, error) {
	if name != "journal_mode" {
		return "", fmt.Errorf("unsupported pragma %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return scalarText(s.db, "PRAGMA "+name)
}

func (s *Store) tableCount(ctx context.Context, table string) (int64, error) {
	switch table {
	case "schema_migrations", "events", "decisions", "allowlist_entries", "audit_log":
	default:
		return 0, fmt.Errorf("unsupported table %q", table)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return scalarInt64(s.db, "SELECT COUNT(*) FROM "+table)
}
