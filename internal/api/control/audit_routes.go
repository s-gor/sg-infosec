package control

import (
	"net/http"

	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func (h *Handler) handleAuditList(w http.ResponseWriter, request *http.Request, identity sourceauth.Identity, requestID string) {
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
	filter := store.AuditFilter{Limit: limit}
	if value := request.URL.Query().Get("cursor"); value != "" {
		var cursor auditCursor
		if err := decodeCursor(value, &cursor); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid", requestID)
			return
		}
		filter.Cursor = &store.AuditCursor{OccurredAt: cursor.At, ID: cursor.ID}
	}
	page, err := h.store.ListAudit(request.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "audit could not be listed", requestID)
		return
	}
	response := protocol.AuditListResponse{Items: make([]protocol.AuditView, 0, len(page.Items))}
	for _, item := range page.Items {
		response.Items = append(response.Items, protocol.AuditView{ID: item.ID, OccurredAt: item.OccurredAt, Actor: item.Actor, Action: item.Action, TargetType: item.TargetType, TargetID: item.TargetID, RequestID: item.RequestID, Result: item.Result})
	}
	if page.Next != nil {
		response.NextCursor, _ = encodeCursor(auditCursor{At: page.Next.OccurredAt, ID: page.Next.ID})
	}
	writeJSON(w, http.StatusOK, response)
}
