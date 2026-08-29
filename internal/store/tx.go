package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(value time.Time) string { return value.UTC().Format(timeLayout) }

func parseTime(value string) (time.Time, error) { return time.Parse(timeLayout, value) }

func canonicalAddr(addr netip.Addr) (string, error) {
	if !addr.IsValid() {
		return "", fmt.Errorf("invalid IP address")
	}
	addr = addr.Unmap()
	return addr.String(), nil
}

func (tx *Tx) InsertEvent(ctx context.Context, event model.Event) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ip, err := canonicalAddr(event.IP)
	if err != nil {
		return false, err
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return false, fmt.Errorf("encode event metadata: %w", err)
	}
	stmt, err := tx.db.prepare(`INSERT OR IGNORE INTO events
		(source_id, event_id, event_type, scope, ip, subject, occurred_at, received_at, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return false, err
	}
	defer stmt.close()
	values := []string{event.SourceID, event.EventID, string(event.EventType), string(event.Scope), ip, event.Subject, formatTime(event.OccurredAt), formatTime(event.ReceivedAt), string(metadata)}
	for index, value := range values {
		if err := stmt.bindText(index+1, value); err != nil {
			return false, err
		}
	}
	if _, err := stmt.step(); err != nil {
		return false, err
	}
	return tx.db.changes() == 1, nil
}

func (tx *Tx) InsertDecision(ctx context.Context, decision model.Decision) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ip, err := canonicalAddr(decision.IP)
	if err != nil {
		return err
	}
	stmt, err := tx.db.prepare(`INSERT INTO decisions
		(id, source_id, policy_id, scope, ip, backend, state, reason_code, strike_count,
		 starts_at, expires_at, created_at, updated_at, revoked_at, revoked_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.close()
	texts := []string{decision.ID, decision.SourceID, decision.PolicyID, string(decision.Scope), ip, string(decision.Backend), string(decision.State), decision.ReasonCode}
	for index, value := range texts {
		if err := stmt.bindText(index+1, value); err != nil {
			return err
		}
	}
	if err := stmt.bindInt64(9, int64(decision.Strike)); err != nil {
		return err
	}
	for index, value := range []time.Time{decision.StartsAt, decision.ExpiresAt, decision.CreatedAt, decision.UpdatedAt} {
		if err := stmt.bindText(10+index, formatTime(value)); err != nil {
			return err
		}
	}
	if decision.RevokedAt == nil {
		if err := stmt.bindNull(14); err != nil {
			return err
		}
	} else if err := stmt.bindText(14, formatTime(*decision.RevokedAt)); err != nil {
		return err
	}
	if decision.RevokedBy == "" {
		if err := stmt.bindNull(15); err != nil {
			return err
		}
	} else if err := stmt.bindText(15, decision.RevokedBy); err != nil {
		return err
	}
	_, err = stmt.step()
	return err
}

func (tx *Tx) FindActiveDecision(ctx context.Context, sourceID string, scope model.Scope, ip netip.Addr, now time.Time) (*model.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := canonicalAddr(ip)
	if err != nil {
		return nil, err
	}
	stmt, err := tx.db.prepare(decisionSelect + ` WHERE source_id = ? AND scope = ? AND ip = ? AND state = ? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	for index, value := range []string{sourceID, string(scope), canonical, string(model.DecisionActive), formatTime(now)} {
		if err := stmt.bindText(index+1, value); err != nil {
			return nil, err
		}
	}
	row, err := stmt.step()
	if err != nil || !row {
		return nil, err
	}
	return scanDecision(stmt)
}

func (tx *Tx) IsAllowlisted(ctx context.Context, scope model.Scope, ip netip.Addr, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false, fmt.Errorf("invalid IP address")
	}
	stmt, err := tx.db.prepare(`SELECT prefix, expires_at FROM allowlist_entries WHERE (scope IS NULL OR scope = ?)`)
	if err != nil {
		return false, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, string(scope)); err != nil {
		return false, err
	}
	for {
		row, err := stmt.step()
		if err != nil {
			return false, err
		}
		if !row {
			return false, nil
		}
		if !stmt.columnIsNull(1) {
			expiresAt, err := parseTime(stmt.columnText(1))
			if err != nil {
				return false, err
			}
			if !expiresAt.After(now) {
				continue
			}
		}
		prefix, err := netip.ParsePrefix(stmt.columnText(0))
		if err != nil {
			return false, fmt.Errorf("stored allowlist prefix: %w", err)
		}
		if prefix.Contains(ip) {
			return true, nil
		}
	}
}

func (tx *Tx) AppendAudit(ctx context.Context, entry model.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	details, err := json.Marshal(entry.Details)
	if err != nil {
		return err
	}
	stmt, err := tx.db.prepare(`INSERT INTO audit_log
		(occurred_at, actor, action, target_type, target_id, request_id, result, details_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.close()
	values := []string{formatTime(entry.OccurredAt), entry.Actor, entry.Action, entry.TargetType, entry.TargetID, entry.RequestID, entry.Result, string(details)}
	for index, value := range values {
		if err := stmt.bindText(index+1, value); err != nil {
			return err
		}
	}
	_, err = stmt.step()
	return err
}

func (tx *Tx) CountEvents(ctx context.Context, sourceID string, eventType model.EventType, scope model.Scope, ip netip.Addr, since time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	canonical, err := canonicalAddr(ip)
	if err != nil {
		return 0, err
	}
	stmt, err := tx.db.prepare(`SELECT COUNT(*) FROM events
		WHERE source_id = ? AND event_type = ? AND scope = ? AND ip = ? AND received_at >= ?`)
	if err != nil {
		return 0, err
	}
	defer stmt.close()
	for index, value := range []string{sourceID, string(eventType), string(scope), canonical, formatTime(since)} {
		if err := stmt.bindText(index+1, value); err != nil {
			return 0, err
		}
	}
	row, err := stmt.step()
	if err != nil {
		return 0, err
	}
	if !row {
		return 0, fmt.Errorf("count events returned no row")
	}
	return int(stmt.columnInt64(0)), nil
}

func (tx *Tx) FindLastPolicyDecision(ctx context.Context, sourceID, policyID string, ip netip.Addr, since time.Time) (*model.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := canonicalAddr(ip)
	if err != nil {
		return nil, err
	}
	stmt, err := tx.db.prepare(decisionSelect + ` WHERE source_id = ? AND policy_id = ? AND ip = ? AND created_at >= ? ORDER BY created_at DESC, id DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	for index, value := range []string{sourceID, policyID, canonical, formatTime(since)} {
		if err := stmt.bindText(index+1, value); err != nil {
			return nil, err
		}
	}
	row, err := stmt.step()
	if err != nil || !row {
		return nil, err
	}
	return scanDecision(stmt)
}
