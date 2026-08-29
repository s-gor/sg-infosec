package control

import (
	"errors"
	"net/http"
	"strings"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func (h *Handler) handleAllowlistCreate(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodPost {
		methodNotAllowed(w, requestID, http.MethodGet, http.MethodPost)
		return
	}
	if !identity.HasPermission(config.PermissionWriteAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "write_admin permission is required", requestID)
		return
	}
	var body protocol.AllowlistCreateRequest
	if !h.decodeJSON(w, request, requestID, &body) {
		return
	}
	prefix, err := parsePrefix(body.Prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_prefix", "prefix must be an IP address or CIDR", requestID)
		return
	}
	description := strings.TrimSpace(body.Description)
	if description == "" || len(description) > 256 {
		writeError(w, http.StatusBadRequest, "invalid_description", "description must contain 1 to 256 bytes", requestID)
		return
	}
	var scope *model.Scope
	if body.Scope != "" {
		parsed, err := model.ParseScope(body.Scope)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_scope", "scope is not supported", requestID)
			return
		}
		scope = &parsed
	}
	now := h.clock.Now().UTC()
	if body.ExpiresAt != nil && !body.ExpiresAt.After(now) {
		writeError(w, http.StatusBadRequest, "invalid_expiry", "expires_at must be in the future", requestID)
		return
	}
	id, err := randomID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_id_failure", "allowlist entry could not be initialized", requestID)
		return
	}
	entry := model.AllowlistEntry{ID: id, Prefix: prefix, Scope: scope, Description: description, ExpiresAt: body.ExpiresAt, CreatedAt: now, CreatedBy: identity.SourceID}
	if err := h.store.PutAllowlistEntry(request.Context(), entry, identity.SourceID, requestID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "allowlist entry could not be created", requestID)
		return
	}
	writeJSON(w, http.StatusCreated, allowlistView(entry))
}

func (h *Handler) handleAllowlistList(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if !identity.HasPermission(config.PermissionReadAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "read_admin permission is required", requestID)
		return
	}
	limit, ok := parseLimit(w, request, requestID)
	if !ok {
		return
	}
	filter := store.AllowlistFilter{Limit: limit}
	if value := request.URL.Query().Get("cursor"); value != "" {
		var cursor decisionCursor
		if err := decodeCursor(value, &cursor); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid", requestID)
			return
		}
		filter.Cursor = &store.AllowlistCursor{CreatedAt: cursor.At, ID: cursor.ID}
	}
	page, err := h.store.ListAllowlist(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "allowlist could not be listed", requestID)
		return
	}
	response := protocol.AllowlistListResponse{Items: make([]protocol.AllowlistView, 0, len(page.Items))}
	for _, item := range page.Items {
		response.Items = append(response.Items, allowlistView(item))
	}
	if page.Next != nil {
		response.NextCursor, _ = encodeCursor(decisionCursor{At: page.Next.CreatedAt, ID: page.Next.ID})
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleAllowlistDelete(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
	if request.Method != http.MethodDelete {
		methodNotAllowed(w, requestID, http.MethodDelete)
		return
	}
	if !identity.HasPermission(config.PermissionWriteAdmin) {
		writeError(w, http.StatusForbidden, "permission_denied", "write_admin permission is required", requestID)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/v1/allowlist/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, "not_found", "allowlist entry not found", requestID)
		return
	}
	changed, err := h.store.DeleteAllowlistEntry(request.Context(), id, identity.SourceID, requestID, h.clock.Now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "allowlist entry not found", requestID)
		} else {
			writeError(w, http.StatusInternalServerError, "internal_error", "allowlist entry could not be deleted", requestID)
		}
		return
	}
	writeJSON(w, http.StatusOK, protocol.ActionResponse{Changed: changed, RequestID: requestID})
}
