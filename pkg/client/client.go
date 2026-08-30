package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/pkg/protocol"
)

const defaultTimeout = 2 * time.Second

var ErrUnavailable = errors.New("SG InfoSec daemon unavailable")

type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	if e == nil {
		return "SG InfoSec API error"
	}
	if e.Code == "" {
		return fmt.Sprintf("SG InfoSec API returned HTTP %d", e.StatusCode)
	}
	if e.Message == "" {
		return fmt.Sprintf("SG InfoSec API error %s", e.Code)
	}
	return fmt.Sprintf("SG InfoSec API error %s: %s", e.Code, e.Message)
}

func IsUnavailable(err error) bool { return errors.Is(err, ErrUnavailable) }

func IsPermissionDenied(err error) bool {
	var apiError *APIError
	return errors.As(err, &apiError) && (apiError.StatusCode == http.StatusUnauthorized || apiError.StatusCode == http.StatusForbidden || apiError.Code == "permission_denied")
}

type BuildMetadata struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BuildTime       string `json:"build_time"`
	ProtocolVersion string `json:"protocol_version"`
}

type HealthResponse struct {
	Status          string        `json:"status"`
	Database        string        `json:"database"`
	ProtocolVersion string        `json:"protocol_version"`
	Build           BuildMetadata `json:"build"`
	ActiveDecisions int64         `json:"active_decisions"`
	DatabaseBytes   int64         `json:"database_bytes"`
	LastRetentionAt *time.Time    `json:"last_retention_at,omitempty"`
}

type ListOptions struct {
	Limit    int
	Cursor   string
	SourceID string
	Scope    string
	State    string
}

type settings struct{ timeout time.Duration }
type Option func(*settings)

func WithTimeout(timeout time.Duration) Option {
	return func(settings *settings) {
		if timeout > 0 {
			settings.timeout = timeout
		}
	}
}

type Client struct {
	socketPath string
	baseURL    string
	httpClient *http.Client
	transport  *http.Transport
}

func New(socketPath string, options ...Option) *Client {
	configuration := settings{timeout: defaultTimeout}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		socketPath: socketPath,
		baseURL:    "http://unix",
		httpClient: &http.Client{Transport: transport, Timeout: configuration.timeout},
		transport:  transport,
	}
}

func (c *Client) CloseIdleConnections() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

func (c *Client) Health(ctx context.Context) (HealthResponse, error) {
	var response HealthResponse
	err := c.do(ctx, http.MethodGet, "/v1/health", nil, &response)
	return response, err
}

func (c *Client) CheckDecision(ctx context.Context, request protocol.DecisionCheckRequest) (protocol.DecisionCheckResponse, error) {
	var response protocol.DecisionCheckResponse
	err := c.do(ctx, http.MethodPost, "/v1/decisions/check", request, &response)
	return response, err
}

func (c *Client) ListDecisions(ctx context.Context, options ListOptions) (protocol.DecisionListResponse, error) {
	values := listValues(options)
	if options.SourceID != "" {
		values.Set("source_id", options.SourceID)
	}
	if options.Scope != "" {
		values.Set("scope", options.Scope)
	}
	if options.State != "" {
		values.Set("state", options.State)
	}
	var response protocol.DecisionListResponse
	err := c.do(ctx, http.MethodGet, withQuery("/v1/decisions", values), nil, &response)
	return response, err
}

func (c *Client) AddDecision(ctx context.Context, request protocol.ManualDecisionRequest) (protocol.DecisionView, error) {
	var response protocol.DecisionView
	err := c.do(ctx, http.MethodPost, "/v1/decisions/manual", request, &response)
	return response, err
}

func (c *Client) RevokeDecision(ctx context.Context, id string) (protocol.ActionResponse, error) {
	encodedID, err := resourceID(id)
	if err != nil {
		return protocol.ActionResponse{}, err
	}
	var response protocol.ActionResponse
	err = c.do(ctx, http.MethodPost, "/v1/decisions/"+encodedID+"/revoke", nil, &response)
	return response, err
}

func (c *Client) ListAllowlist(ctx context.Context, options ListOptions) (protocol.AllowlistListResponse, error) {
	var response protocol.AllowlistListResponse
	err := c.do(ctx, http.MethodGet, withQuery("/v1/allowlist", listValues(options)), nil, &response)
	return response, err
}

func (c *Client) AddAllowlist(ctx context.Context, request protocol.AllowlistCreateRequest) (protocol.AllowlistView, error) {
	var response protocol.AllowlistView
	err := c.do(ctx, http.MethodPost, "/v1/allowlist", request, &response)
	return response, err
}

func (c *Client) RemoveAllowlist(ctx context.Context, id string) (protocol.ActionResponse, error) {
	encodedID, err := resourceID(id)
	if err != nil {
		return protocol.ActionResponse{}, err
	}
	var response protocol.ActionResponse
	err = c.do(ctx, http.MethodDelete, "/v1/allowlist/"+encodedID, nil, &response)
	return response, err
}

func (c *Client) ListAudit(ctx context.Context, options ListOptions) (protocol.AuditListResponse, error) {
	var response protocol.AuditListResponse
	err := c.do(ctx, http.MethodGet, withQuery("/v1/audit", listValues(options)), nil, &response)
	return response, err
}

func (c *Client) ReconcileNFT(ctx context.Context) (protocol.ActionResponse, error) {
	var response protocol.ActionResponse
	err := c.do(ctx, http.MethodPost, "/v1/nft/reconcile", nil, &response)
	return response, err
}

func (c *Client) do(ctx context.Context, method, requestPath string, input, output any) error {
	if c == nil || c.httpClient == nil || strings.TrimSpace(c.socketPath) == "" {
		return fmt.Errorf("%w: control socket path is required", ErrUnavailable)
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+requestPath, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 1<<20)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var payload protocol.ErrorResponse
		_ = json.NewDecoder(limited).Decode(&payload)
		return &APIError{StatusCode: response.StatusCode, Code: payload.Code, Message: payload.Message, RequestID: payload.RequestID}
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func listValues(options ListOptions) url.Values {
	values := make(url.Values)
	if options.Limit > 0 {
		values.Set("limit", strconv.Itoa(options.Limit))
	}
	if options.Cursor != "" {
		values.Set("cursor", options.Cursor)
	}
	return values
}

func withQuery(requestPath string, values url.Values) string {
	if len(values) == 0 {
		return requestPath
	}
	return requestPath + "?" + values.Encode()
}

func resourceID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "/\\") {
		return "", fmt.Errorf("resource ID must contain 1 to 128 non-path characters")
	}
	return url.PathEscape(value), nil
}
