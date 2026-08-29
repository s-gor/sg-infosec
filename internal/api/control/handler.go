package control

import (
	"net/http"
	"strings"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/decision"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
)

type Handler struct {
	decisions    *decision.Service
	store        *store.Store
	clock        clock.Clock
	knownSources map[string]struct{}
	bodyLimit    int64
}

func NewHandler(decisions *decision.Service, database *store.Store, sourceClock clock.Clock, knownSources []string, bodyLimit int64) http.Handler {
	sources := make(map[string]struct{}, len(knownSources))
	for _, sourceID := range knownSources {
		if sourceID != "" {
			sources[sourceID] = struct{}{}
		}
	}
	return &Handler{decisions: decisions, store: database, clock: sourceClock, knownSources: sources, bodyLimit: bodyLimit}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	requestID, err := resolveRequestID(request.Header.Get("X-Request-ID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_id_failure", "request could not be initialized", "unknown")
		return
	}
	identity, ok := sourceauth.IdentityFromContext(request.Context())
	if !ok || identity.SourceID == "" {
		writeError(w, http.StatusUnauthorized, "missing_peer_identity", "local source identity is required", requestID)
		return
	}
	if h == nil || h.decisions == nil || h.store == nil || h.clock == nil || h.bodyLimit <= 0 {
		writeError(w, http.StatusInternalServerError, "service_unavailable", "control service is not initialized", requestID)
		return
	}

	switch {
	case request.URL.Path == "/v1/decisions/check":
		h.handleDecisionCheck(w, request, identity, requestID)
	case request.URL.Path == "/v1/decisions/manual":
		h.handleManualDecision(w, request, identity, requestID)
	case request.URL.Path == "/v1/decisions":
		h.handleDecisionList(w, request, identity, requestID)
	case strings.HasPrefix(request.URL.Path, "/v1/decisions/") && strings.HasSuffix(request.URL.Path, "/revoke"):
		h.handleDecisionRevoke(w, request, identity, requestID)
	case request.URL.Path == "/v1/allowlist":
		if request.Method == http.MethodGet {
			h.handleAllowlistList(w, request, identity, requestID)
		} else {
			h.handleAllowlistCreate(w, request, identity, requestID)
		}
	case strings.HasPrefix(request.URL.Path, "/v1/allowlist/"):
		h.handleAllowlistDelete(w, request, identity, requestID)
	case request.URL.Path == "/v1/audit":
		h.handleAuditList(w, request, identity, requestID)
	default:
		writeError(w, http.StatusNotFound, "not_found", "route not found", requestID)
	}
}
