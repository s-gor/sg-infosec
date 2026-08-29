package enforcerapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

type Service interface {
	Ensure(context.Context, string) error
	Add(context.Context, string, enforcerprotocol.Entry) error
	Remove(context.Context, string, enforcerprotocol.Key) error
	List(context.Context) ([]enforcer.Entry, error)
	Reconcile(context.Context, string, []enforcerprotocol.Entry) (enforcer.ReconcileReport, error)
}

type Handler struct {
	service   Service
	bodyLimit int64
}

func New(service Service, bodyLimit int64) http.Handler {
	return &Handler{service: service, bodyLimit: bodyLimit}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/v1/ensure":
		h.requirePost(w, request, h.handleEnsure)
	case "/v1/add":
		h.requirePost(w, request, h.handleAdd)
	case "/v1/remove":
		h.requirePost(w, request, h.handleRemove)
	case "/v1/list":
		if request.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed")
			return
		}
		h.handleList(w, request)
	case "/v1/reconcile":
		h.requirePost(w, request, h.handleReconcile)
	default:
		writeError(w, http.StatusNotFound, "not_found", "route not found")
	}
}

func (h *Handler) requirePost(w http.ResponseWriter, request *http.Request, next func(http.ResponseWriter, *http.Request)) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is allowed")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	if h == nil || h.service == nil || h.bodyLimit <= 0 {
		writeError(w, http.StatusInternalServerError, "service_unavailable", "enforcer service is not initialized")
		return
	}
	next(w, request)
}

func (h *Handler) handleEnsure(w http.ResponseWriter, request *http.Request) {
	var input enforcerprotocol.EnsureRequest
	if !decodeStrict(w, request, h.bodyLimit, &input) {
		return
	}
	if input.SchemaVersion != enforcerprotocol.SchemaVersion {
		writeError(w, http.StatusBadRequest, "unsupported_schema", "schema_version is not supported")
		return
	}
	if err := h.service.Ensure(request.Context(), input.RequestID); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, enforcerprotocol.ActionResponse{OK: true})
}

func (h *Handler) handleAdd(w http.ResponseWriter, request *http.Request) {
	var input enforcerprotocol.MutationRequest
	if !decodeStrict(w, request, h.bodyLimit, &input) {
		return
	}
	if err := h.service.Add(request.Context(), input.RequestID, input.Entry); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, enforcerprotocol.ActionResponse{OK: true})
}

func (h *Handler) handleRemove(w http.ResponseWriter, request *http.Request) {
	var input enforcerprotocol.RemoveRequest
	if !decodeStrict(w, request, h.bodyLimit, &input) {
		return
	}
	if err := h.service.Remove(request.Context(), input.RequestID, input.Key); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, enforcerprotocol.ActionResponse{OK: true})
}

func (h *Handler) handleList(w http.ResponseWriter, request *http.Request) {
	if h == nil || h.service == nil {
		writeError(w, http.StatusInternalServerError, "service_unavailable", "enforcer service is not initialized")
		return
	}
	entries, err := h.service.List(request.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	response := enforcerprotocol.ListResponse{Entries: make([]enforcerprotocol.Entry, 0, len(entries))}
	for _, entry := range entries {
		response.Entries = append(response.Entries, enforcerprotocol.Entry{
			Scope: string(entry.Scope), Protocol: entry.Protocol, Port: entry.Port,
			IP: entry.IP.String(), ExpiresAt: entry.ExpiresAt.UTC(),
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) handleReconcile(w http.ResponseWriter, request *http.Request) {
	var input enforcerprotocol.ReconcileRequest
	if !decodeStrict(w, request, h.bodyLimit, &input) {
		return
	}
	report, err := h.service.Reconcile(request.Context(), input.RequestID, input.Entries)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, enforcerprotocol.ReconcileResponse{
		Created: report.Created, Updated: report.Updated,
		Removed: report.Removed, Unchanged: report.Unchanged,
	})
}

func decodeStrict(w http.ResponseWriter, request *http.Request, limit int64, target any) bool {
	request.Body = http.MaxBytesReader(w, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds configured limit")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be one valid JSON object")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds configured limit")
			return false
		}
		writeError(w, http.StatusBadRequest, "multiple_json_values", "request body must contain exactly one JSON value")
		return false
	}
	return true
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enforcer.ErrInvalidRequestID):
		writeError(w, http.StatusBadRequest, "invalid_request_id", "request_id is invalid")
	case errors.Is(err, enforcer.ErrUnsupportedTarget):
		writeError(w, http.StatusBadRequest, "unsupported_target", "target is not allowed")
	case errors.Is(err, enforcer.ErrInvalidEntry):
		writeError(w, http.StatusBadRequest, "invalid_entry", "entry is invalid")
	case errors.Is(err, enforcer.ErrDuplicateEntry):
		writeError(w, http.StatusConflict, "duplicate_entry", "entry is duplicated")
	default:
		writeError(w, http.StatusInternalServerError, "backend_failure", "enforcer operation failed")
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, enforcerprotocol.ErrorResponse{Code: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
