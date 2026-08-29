package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

func (tx *Tx) FindLatestActiveDecision(ctx context.Context, sourceID string, scope model.Scope, ip netip.Addr) (*model.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := canonicalAddr(ip)
	if err != nil {
		return nil, err
	}
	stmt, err := tx.db.prepare(decisionSelect + ` WHERE source_id = ? AND scope = ? AND ip = ? AND state = ? ORDER BY expires_at DESC, id DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	for index, value := range []string{sourceID, string(scope), canonical, string(model.DecisionActive)} {
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

func (tx *Tx) MarkDecisionExpired(ctx context.Context, id string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stmt, err := tx.db.prepare(`UPDATE decisions SET state = ?, updated_at = ? WHERE id = ? AND state = ?`)
	if err != nil {
		return err
	}
	defer stmt.close()
	for index, value := range []string{string(model.DecisionExpired), formatTime(now), id, string(model.DecisionActive)} {
		if err := stmt.bindText(index+1, value); err != nil {
			return err
		}
	}
	_, err = stmt.step()
	return err
}
