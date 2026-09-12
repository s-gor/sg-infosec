package control

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func (h *Handler) handleEventList(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	if !identity.HasPermission(config.PermissionReadAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "read_admin permission is required", requestID)
		return
	}

	query := request.URL.Query()
	filter := store.EventFilter{Limit: 100}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200", requestID)
			return
		}
		filter.Limit = limit
	}
	filter.SourceID = strings.TrimSpace(query.Get("source_id"))
	filter.Scope = model.Scope(strings.TrimSpace(query.Get("scope")))
	if raw := strings.TrimSpace(query.Get("event_type")); raw != "" {
		eventType, err := model.ParseEventType(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_event_type", "unsupported event type", requestID)
			return
		}
		filter.EventType = eventType
	}
	if raw := strings.TrimSpace(query.Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_since", "since must be RFC3339", requestID)
			return
		}
		since = since.UTC()
		filter.Since = &since
	}

	page, err := h.store.ListEvents(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "event_list_failed", "events could not be listed", requestID)
		return
	}
	items := make([]protocol.EventView, 0, len(page.Items))
	for _, event := range page.Items {
		items = append(items, protocol.EventView{
			ID: event.ID, SourceID: event.SourceID, EventID: event.EventID,
			EventType: string(event.EventType), Scope: string(event.Scope), IP: event.IP.String(), Subject: event.Subject,
			OccurredAt: event.OccurredAt, ReceivedAt: event.ReceivedAt,
		})
	}
	writeJSON(w, http.StatusOK, protocol.EventListResponse{Items: items})
}

func (h *Handler) handleOverview(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	if !identity.HasPermission(config.PermissionReadAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "read_admin permission is required", requestID)
		return
	}

	window := strings.TrimSpace(request.URL.Query().Get("window"))
	if window == "" {
		window = "24h"
	}
	var duration time.Duration
	switch window {
	case "1h":
		duration = time.Hour
	case "24h":
		duration = 24 * time.Hour
	default:
		writeError(w, http.StatusBadRequest, "invalid_window", "window must be 1h or 24h", requestID)
		return
	}
	now := h.clock.Now().UTC()
	summary, err := h.store.Overview(request.Context(), now.Add(-duration), now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "overview_failed", "overview could not be generated", requestID)
		return
	}

	response := protocol.OverviewResponse{
		Window: window, EventsTotal: summary.EventsTotal, FailedEvents: summary.FailedEvents,
		UniqueIPs: summary.UniqueIPs, ActiveDecisions: summary.ActiveDecisions, AutomaticDecisions: summary.AutomaticDecisions,
		ByScope: make([]protocol.OverviewBreakdown, 0, len(summary.ByScope)),
		ByEventType: make([]protocol.OverviewBreakdown, 0, len(summary.ByEventType)),
		Hourly: make([]protocol.OverviewBucket, 0, len(summary.Hourly)),
		Sources: make([]protocol.SourceActivity, 0, len(summary.Sources)),
	}
	for _, item := range summary.ByScope {
		response.ByScope = append(response.ByScope, protocol.OverviewBreakdown{Key: item.Key, Count: item.Count})
	}
	for _, item := range summary.ByEventType {
		response.ByEventType = append(response.ByEventType, protocol.OverviewBreakdown{Key: item.Key, Count: item.Count})
	}
	for _, item := range summary.Hourly {
		response.Hourly = append(response.Hourly, protocol.OverviewBucket{Start: item.Start, Count: item.Count})
	}
	for _, item := range summary.Sources {
		response.Sources = append(response.Sources, protocol.SourceActivity{SourceID: item.SourceID, Count: item.Count, LastSeen: item.LastSeen})
	}
	writeJSON(w, http.StatusOK, response)
}
