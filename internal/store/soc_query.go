package store

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
)

type EventFilter struct {
	SourceID  string
	Scope     model.Scope
	EventType model.EventType
	Since     *time.Time
	Limit     int
}

type EventPage struct {
	Items []model.Event
}

type OverviewBreakdown struct {
	Key   string
	Count int64
}

type OverviewBucket struct {
	Start time.Time
	Count int64
}

type SourceActivity struct {
	SourceID string
	Count    int64
	LastSeen time.Time
}

type OverviewSummary struct {
	EventsTotal        int64
	FailedEvents       int64
	UniqueIPs          int64
	ActiveDecisions    int64
	AutomaticDecisions int64
	ByScope            []OverviewBreakdown
	ByEventType        []OverviewBreakdown
	Hourly             []OverviewBucket
	Sources            []SourceActivity
}

func (s *Store) ListEvents(ctx context.Context, filter EventFilter) (EventPage, error) {
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	if filter.Limit < 1 || filter.Limit > 200 {
		return EventPage{}, fmt.Errorf("event page limit must be between 1 and 200")
	}
	if filter.EventType != "" {
		if _, err := model.ParseEventType(string(filter.EventType)); err != nil {
			return EventPage{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return EventPage{}, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return EventPage{}, err
	}

	query := `SELECT id, source_id, event_id, event_type, scope, ip, subject, occurred_at, received_at FROM events`
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
	if filter.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, string(filter.EventType))
	}
	if filter.Since != nil {
		clauses = append(clauses, "received_at >= ?")
		args = append(args, formatTime(filter.Since.UTC()))
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY received_at DESC, id DESC LIMIT ?"

	stmt, err := s.db.prepare(query)
	if err != nil {
		return EventPage{}, err
	}
	defer stmt.close()
	for index, value := range args {
		if err := stmt.bindText(index+1, value); err != nil {
			return EventPage{}, err
		}
	}
	if err := stmt.bindInt64(len(args)+1, int64(filter.Limit)); err != nil {
		return EventPage{}, err
	}

	items := make([]model.Event, 0, filter.Limit)
	for {
		row, err := stmt.step()
		if err != nil {
			return EventPage{}, err
		}
		if !row {
			break
		}
		event, err := scanSOCEvent(stmt)
		if err != nil {
			return EventPage{}, err
		}
		items = append(items, event)
	}
	return EventPage{Items: items}, nil
}

func scanSOCEvent(stmt *sqliteStmt) (model.Event, error) {
	eventType, err := model.ParseEventType(stmt.columnText(3))
	if err != nil {
		return model.Event{}, err
	}
	ip, err := netip.ParseAddr(stmt.columnText(5))
	if err != nil {
		return model.Event{}, err
	}
	occurredAt, err := parseTime(stmt.columnText(7))
	if err != nil {
		return model.Event{}, err
	}
	receivedAt, err := parseTime(stmt.columnText(8))
	if err != nil {
		return model.Event{}, err
	}
	return model.Event{
		ID:         stmt.columnInt64(0),
		SourceID:   stmt.columnText(1),
		EventID:    stmt.columnText(2),
		EventType:  eventType,
		Scope:      model.Scope(stmt.columnText(4)),
		IP:         ip,
		Subject:    stmt.columnText(6),
		OccurredAt: occurredAt,
		ReceivedAt: receivedAt,
	}, nil
}

func (s *Store) Overview(ctx context.Context, since, now time.Time) (OverviewSummary, error) {
	since = since.UTC()
	now = now.UTC()
	if since.IsZero() || now.IsZero() || since.After(now) {
		return OverviewSummary{}, fmt.Errorf("invalid overview window")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return OverviewSummary{}, fmt.Errorf("store is closed")
	}
	if err := ctx.Err(); err != nil {
		return OverviewSummary{}, err
	}

	summary := OverviewSummary{}
	var err error
	if summary.EventsTotal, err = s.countSOC(ctx, `SELECT COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ?`, since, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.FailedEvents, err = s.countSOC(ctx, `SELECT COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ? AND event_type IN ('auth.failed','api.auth_failed')`, since, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.UniqueIPs, err = s.countSOC(ctx, `SELECT COUNT(DISTINCT ip) FROM events WHERE received_at >= ? AND received_at <= ? AND event_type IN ('auth.failed','api.auth_failed')`, since, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.ActiveDecisions, err = s.countDecisionSOC(ctx, `SELECT COUNT(*) FROM decisions WHERE state = 'active' AND expires_at > ?`, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.AutomaticDecisions, err = s.countDecisionSOC(ctx, `SELECT COUNT(*) FROM decisions WHERE state = 'active' AND expires_at > ? AND policy_id <> 'manual'`, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.ByScope, err = s.breakdownSOC(ctx, "scope", since, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.ByEventType, err = s.breakdownSOC(ctx, "event_type", since, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.Sources, err = s.sourceActivitySOC(ctx, since, now); err != nil {
		return OverviewSummary{}, err
	}
	if summary.Hourly, err = s.hourlySOC(ctx, since, now); err != nil {
		return OverviewSummary{}, err
	}
	return summary, nil
}

func (s *Store) countSOC(ctx context.Context, query string, since, now time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stmt, err := s.db.prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, formatTime(since)); err != nil {
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
		return 0, fmt.Errorf("aggregate query returned no row")
	}
	return stmt.columnInt64(0), nil
}

func (s *Store) countDecisionSOC(ctx context.Context, query string, now time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stmt, err := s.db.prepare(query)
	if err != nil {
		return 0, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, formatTime(now)); err != nil {
		return 0, err
	}
	row, err := stmt.step()
	if err != nil {
		return 0, err
	}
	if !row {
		return 0, fmt.Errorf("decision aggregate returned no row")
	}
	return stmt.columnInt64(0), nil
}

func (s *Store) breakdownSOC(ctx context.Context, column string, since, now time.Time) ([]OverviewBreakdown, error) {
	if column != "scope" && column != "event_type" {
		return nil, fmt.Errorf("unsupported overview breakdown")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	query := `SELECT ` + column + `, COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ? GROUP BY ` + column + ` ORDER BY COUNT(*) DESC, ` + column
	stmt, err := s.db.prepare(query)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, formatTime(since)); err != nil {
		return nil, err
	}
	if err := stmt.bindText(2, formatTime(now)); err != nil {
		return nil, err
	}
	var values []OverviewBreakdown
	for {
		row, err := stmt.step()
		if err != nil {
			return nil, err
		}
		if !row {
			break
		}
		values = append(values, OverviewBreakdown{Key: stmt.columnText(0), Count: stmt.columnInt64(1)})
	}
	return values, nil
}

func (s *Store) sourceActivitySOC(ctx context.Context, since, now time.Time) ([]SourceActivity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stmt, err := s.db.prepare(`SELECT source_id, COUNT(*), MAX(received_at) FROM events WHERE received_at >= ? AND received_at <= ? GROUP BY source_id ORDER BY source_id`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, formatTime(since)); err != nil {
		return nil, err
	}
	if err := stmt.bindText(2, formatTime(now)); err != nil {
		return nil, err
	}
	var values []SourceActivity
	for {
		row, err := stmt.step()
		if err != nil {
			return nil, err
		}
		if !row {
			break
		}
		lastSeen, err := parseTime(stmt.columnText(2))
		if err != nil {
			return nil, err
		}
		values = append(values, SourceActivity{SourceID: stmt.columnText(0), Count: stmt.columnInt64(1), LastSeen: lastSeen})
	}
	return values, nil
}

func (s *Store) hourlySOC(ctx context.Context, since, now time.Time) ([]OverviewBucket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stmt, err := s.db.prepare(`SELECT substr(received_at, 1, 13), COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ? GROUP BY substr(received_at, 1, 13) ORDER BY substr(received_at, 1, 13)`)
	if err != nil {
		return nil, err
	}
	defer stmt.close()
	if err := stmt.bindText(1, formatTime(since)); err != nil {
		return nil, err
	}
	if err := stmt.bindText(2, formatTime(now)); err != nil {
		return nil, err
	}
	counts := make(map[string]int64)
	for {
		row, err := stmt.step()
		if err != nil {
			return nil, err
		}
		if !row {
			break
		}
		counts[stmt.columnText(0)] = stmt.columnInt64(1)
	}

	start := since.Truncate(time.Hour)
	end := now.Truncate(time.Hour)
	buckets := make([]OverviewBucket, 0, int(end.Sub(start)/time.Hour)+1)
	for current := start; !current.After(end); current = current.Add(time.Hour) {
		key := current.Format("2006-01-02T15")
		buckets = append(buckets, OverviewBucket{Start: current, Count: counts[key]})
	}
	return buckets, nil
}
