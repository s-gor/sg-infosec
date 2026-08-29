package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/sourceauth"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

const metadataLimit = 8 * 1024

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var sensitiveMetadataKeys = map[string]struct{}{
	"password":         {},
	"passwd":           {},
	"token":            {},
	"authorization":    {},
	"cookie":           {},
	"private_key":      {},
	"subscription_url": {},
	"config":           {},
}

type Processor struct {
	store *store.Store
	clock clock.Clock
}

func NewProcessor(database *store.Store, sourceClock clock.Clock) *Processor {
	return &Processor{store: database, clock: sourceClock}
}

func (p *Processor) Process(ctx context.Context, source sourceauth.Identity, request protocol.EventRequest) (protocol.EventResponse, error) {
	if p == nil || p.store == nil || p.clock == nil {
		return protocol.EventResponse{}, fmt.Errorf("events processor is not initialized")
	}
	if source.SourceID == "" {
		return protocol.EventResponse{}, newRequestError(http.StatusUnauthorized, "missing_peer_identity", "local source identity is required")
	}
	if request.EventID == "" || len(request.EventID) > 128 || !utf8.ValidString(request.EventID) {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_event_id", "event_id must contain 1 to 128 UTF-8 bytes")
	}
	eventType, err := model.ParseEventType(request.EventType)
	if err != nil {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_event_type", "event_type is not supported")
	}
	scope, err := model.ParseScope(request.Scope)
	if err != nil {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_scope", "scope is not supported")
	}
	if err := source.Authorize(eventType, scope); err != nil {
		return protocol.EventResponse{}, newRequestError(http.StatusForbidden, "source_not_authorized", "local source is not authorized for this event")
	}
	address, err := netip.ParseAddr(request.IP)
	if err != nil {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_ip", "ip must be a valid IPv4 or IPv6 address")
	}
	address = address.Unmap()
	if request.OccurredAt.IsZero() {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_occurred_at", "occurred_at is required")
	}
	now := p.clock.Now().UTC()
	if request.OccurredAt.After(now.Add(5 * time.Minute)) {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "occurred_at_in_future", "occurred_at is too far in the future")
	}
	if err := validateMetadata(request.Metadata, 0); err != nil {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_metadata", err.Error())
	}
	encodedMetadata, err := json.Marshal(request.Metadata)
	if err != nil {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "invalid_metadata", "metadata cannot be encoded as JSON")
	}
	if len(encodedMetadata) > metadataLimit {
		return protocol.EventResponse{}, newRequestError(http.StatusBadRequest, "metadata_too_large", "metadata exceeds 8192 bytes")
	}

	event := model.Event{
		SourceID:   source.SourceID,
		EventID:    request.EventID,
		EventType:  eventType,
		Scope:      scope,
		IP:         address,
		Subject:    request.Subject,
		OccurredAt: request.OccurredAt.UTC(),
		ReceivedAt: now,
		Metadata:   request.Metadata,
	}
	inserted := false
	err = p.store.WithTx(ctx, func(tx *store.Tx) error {
		var insertErr error
		inserted, insertErr = tx.InsertEvent(ctx, event)
		return insertErr
	})
	if err != nil {
		return protocol.EventResponse{}, err
	}
	return protocol.EventResponse{Accepted: true, Duplicate: !inserted}, nil
}

type Handler struct {
	processor *Processor
	bodyLimit int64
}

func NewHandler(processor *Processor, bodyLimit int64) http.Handler {
	return &Handler{processor: processor, bodyLimit: bodyLimit}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	requestID, err := resolveRequestID(request.Header.Get("X-Request-ID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "request_id_failure", "request could not be initialized", "unknown")
		return
	}
	if request.URL.Path != "/v1/events" {
		writeError(w, http.StatusNotFound, "not_found", "route not found", requestID)
		return
	}
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "only POST is allowed", requestID)
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", requestID)
		return
	}
	identity, ok := sourceauth.IdentityFromContext(request.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing_peer_identity", "local source identity is required", requestID)
		return
	}
	if h == nil || h.processor == nil || h.bodyLimit <= 0 {
		writeError(w, http.StatusInternalServerError, "service_unavailable", "events service is not initialized", requestID)
		return
	}

	request.Body = http.MaxBytesReader(w, request.Body, h.bodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var eventRequest protocol.EventRequest
	if err := decoder.Decode(&eventRequest); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds configured limit", requestID)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be one valid JSON object", requestID)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds configured limit", requestID)
			return
		}
		writeError(w, http.StatusBadRequest, "multiple_json_values", "request body must contain exactly one JSON value", requestID)
		return
	}

	response, processErr := h.processor.Process(request.Context(), identity, eventRequest)
	if processErr != nil {
		var clientErr *requestError
		if errors.As(processErr, &clientErr) {
			writeError(w, clientErr.status, clientErr.code, clientErr.message, requestID)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "event could not be processed", requestID)
		return
	}
	response.RequestID = requestID
	status := http.StatusAccepted
	if response.Duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, response)
}

type requestError struct {
	status  int
	code    string
	message string
}

func newRequestError(status int, code, message string) *requestError {
	return &requestError{status: status, code: code, message: message}
}

func (e *requestError) Error() string { return e.code + ": " + e.message }

func resolveRequestID(value string) (string, error) {
	if requestIDPattern.MatchString(value) {
		return value, nil
	}
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func validateMetadata(value any, depth int) error {
	if depth > 8 {
		return fmt.Errorf("metadata nesting exceeds 8 levels")
	}
	switch typed := value.(type) {
	case nil, string, bool, float64, json.Number:
		return nil
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(key)
			if _, forbidden := sensitiveMetadataKeys[normalized]; forbidden {
				return fmt.Errorf("metadata key %q is forbidden", key)
			}
			if err := validateMetadata(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for _, child := range typed {
			if err := validateMetadata(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("metadata contains unsupported value type")
	}
}

func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, protocol.ErrorResponse{Code: code, Message: message, RequestID: requestID})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
