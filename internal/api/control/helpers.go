package control

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (h *Handler) decodeJSON(w http.ResponseWriter, request *http.Request, requestID string, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", requestID)
		return false
	}
	request.Body = http.MaxBytesReader(w, request.Body, h.bodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds configured limit", requestID)
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body must be one valid JSON object", requestID)
		}
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "multiple_json_values", "request body must contain exactly one JSON value", requestID)
		return false
	}
	return true
}

type decisionCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}
type auditCursor struct {
	At time.Time `json:"at"`
	ID int64     `json:"id"`
}

func encodeCursor(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func decodeCursor(value string, target any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("cursor must contain exactly one JSON value")
	}
	return nil
}
func parseLimit(w http.ResponseWriter, request *http.Request, requestID string) (int, bool) {
	value := request.URL.Query().Get("limit")
	if value == "" {
		return 50, true
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 200 {
		writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200", requestID)
		return 0, false
	}
	return limit, true
}
func parseDecisionState(value string) (model.DecisionState, error) {
	state := model.DecisionState(value)
	switch state {
	case model.DecisionPending, model.DecisionActive, model.DecisionExpired, model.DecisionRevoked, model.DecisionFailed:
		return state, nil
	default:
		return "", fmt.Errorf("unsupported decision state %q", value)
	}
}
func parsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	address = address.Unmap()
	bits := 128
	if address.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(address, bits), nil
}
func decisionView(item model.Decision) protocol.DecisionView {
	return protocol.DecisionView{ID: item.ID, SourceID: item.SourceID, PolicyID: item.PolicyID, Scope: string(item.Scope), IP: item.IP.String(), Backend: string(item.Backend), State: string(item.State), ReasonCode: item.ReasonCode, Strike: item.Strike, StartsAt: item.StartsAt, ExpiresAt: item.ExpiresAt, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}
func allowlistView(item model.AllowlistEntry) protocol.AllowlistView {
	view := protocol.AllowlistView{ID: item.ID, Prefix: item.Prefix.Masked().String(), Description: item.Description, ExpiresAt: item.ExpiresAt, CreatedAt: item.CreatedAt, CreatedBy: item.CreatedBy}
	if item.Scope != nil {
		view.Scope = string(*item.Scope)
	}
	return view
}
func methodNotAllowed(w http.ResponseWriter, requestID string, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed", requestID)
}
func resolveRequestID(value string) (string, error) {
	if requestIDPattern.MatchString(value) {
		return value, nil
	}
	return randomID()
}
func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, protocol.ErrorResponse{Code: code, Message: message, RequestID: requestID})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
