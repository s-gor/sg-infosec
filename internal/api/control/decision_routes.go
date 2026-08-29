package control

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/decision"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func (h *Handler) handleDecisionCheck(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if !identity.HasPermission(config.PermissionCheckDecisions) {
		writeError(w, http.StatusForbidden, "permission_denied", "check_decisions permission is required", requestID)
		return
	}
	var body protocol.DecisionCheckRequest
	if !h.decodeJSON(w, request, requestID, &body) {
		return
	}
	if body.RouteID == "" || len(body.RouteID) > 128 {
		writeError(w, http.StatusBadRequest, "invalid_route_id", "route_id must contain 1 to 128 bytes", requestID)
		return
	}
	scope, err := model.ParseScope(body.Scope)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_scope", "scope is not supported", requestID)
		return
	}
	ip, err := netip.ParseAddr(body.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_ip", "ip must be a valid IPv4 or IPv6 address", requestID)
		return
	}
	result, err := h.decisions.Check(request.Context(), identity.SourceID, scope, ip.Unmap())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "decision could not be checked", requestID)
		return
	}
	response := protocol.DecisionCheckResponse{Blocked: result.Blocked, DecisionID: result.DecisionID, ReasonCode: result.ReasonCode}
	if result.Blocked {
		expiresAt := result.ExpiresAt
		response.ExpiresAt = &expiresAt
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleDecisionList(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodGet {
		methodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	if !identity.HasPermission(config.PermissionReadAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "read_admin permission is required", requestID)
		return
	}
	limit, ok := parseLimit(w, request, requestID)
	if !ok {
		return
	}
	filter := store.DecisionFilter{Limit: limit, SourceID: request.URL.Query().Get("source_id")}
	if value := request.URL.Query().Get("scope"); value != "" {
		scope, err := model.ParseScope(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_scope", "scope is not supported", requestID)
			return
		}
		filter.Scope = scope
	}
	if value := request.URL.Query().Get("state"); value != "" {
		state, err := parseDecisionState(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_state", "decision state is not supported", requestID)
			return
		}
		filter.State = state
	}
	if value := request.URL.Query().Get("cursor"); value != "" {
		var cursor decisionCursor
		if err := decodeCursor(value, &cursor); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid", requestID)
			return
		}
		filter.Cursor = &store.DecisionCursor{CreatedAt: cursor.At, ID: cursor.ID}
	}
	page, err := h.store.ListDecisions(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "decisions could not be listed", requestID)
		return
	}
	response := protocol.DecisionListResponse{Items: make([]protocol.DecisionView, 0, len(page.Items))}
	for _, item := range page.Items {
		response.Items = append(response.Items, decisionView(item))
	}
	if page.Next != nil {
		response.NextCursor, _ = encodeCursor(decisionCursor{At: page.Next.CreatedAt, ID: page.Next.ID})
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleManualDecision(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if !identity.HasPermission(config.PermissionWriteAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "write_admin permission is required", requestID)
		return
	}
	var body protocol.ManualDecisionRequest
	if !h.decodeJSON(w, request, requestID, &body) {
		return
	}
	if _, ok := h.knownSources[body.SourceID]; !ok {
		writeError(w, http.StatusBadRequest, "unknown_source", "source_id is not configured", requestID)
		return
	}
	scope, err := model.ParseScope(body.Scope)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_scope", "scope is not supported", requestID)
		return
	}
	backend := model.BackendApplication
	if body.Backend != "" {
		backend, err = model.ParseBackend(body.Backend)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_backend", "backend is not supported", requestID)
			return
		}
	}
	ip, err := netip.ParseAddr(body.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_ip", "ip must be a valid IPv4 or IPv6 address", requestID)
		return
	}
	duration, err := time.ParseDuration(body.Duration)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_duration", "duration is invalid", requestID)
		return
	}
	created, err := h.decisions.CreateManual(request.Context(), decision.ManualInput{SourceID: body.SourceID, Scope: scope, Backend: backend, IP: ip.Unmap(), Duration: duration, Reason: body.Reason, OverrideAllowlist: body.OverrideAllowlist, Actor: identity.SourceID, RequestID: requestID})
	if err != nil {
		switch {
		case errors.Is(err, decision.ErrAllowlisted):
			writeError(w, http.StatusConflict, "allowlist_override_required", "IP is allowlisted; explicit override is required", requestID)
		case errors.Is(err, decision.ErrAlreadyActive):
			writeError(w, http.StatusConflict, "decision_already_active", "an active decision already exists", requestID)
		case errors.Is(err, decision.ErrInvalidManual):
			writeError(w, http.StatusBadRequest, "invalid_manual_decision", "manual decision is invalid", requestID)
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "manual decision could not be created", requestID)
		}
		return
	}
	if created.Backend == model.BackendNFTables && h.nft != nil {
		h.nft.Trigger()
	}
	writeJSON(w, http.StatusCreated, decisionView(created))
}

func (h *Handler) handleDecisionRevoke(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if !identity.HasPermission(config.PermissionWriteAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "write_admin permission is required", requestID)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/decisions/"), "/revoke")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, "not_found", "decision not found", requestID)
		return
	}
	if request.ContentLength != 0 {
		var body struct{}
		if !h.decodeJSON(w, request, requestID, &body) {
			return
		}
	}
	changed, err := h.decisions.Revoke(request.Context(), id, identity.SourceID, requestID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "decision not found", requestID)
		} else {
			writeError(w, http.StatusInternalServerError, "internal_error", "decision could not be revoked", requestID)
		}
		return
	}
	if changed && h.nft != nil {
		h.nft.Trigger()
	}
	writeJSON(w, http.StatusOK, protocol.ActionResponse{Changed: changed, RequestID: requestID})
}
