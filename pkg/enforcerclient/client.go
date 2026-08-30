package enforcerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

var (
	ErrUnavailable      = errors.New("enforcer unavailable")
	ErrPermissionDenied = errors.New("enforcer permission denied")
	ErrRejected         = errors.New("enforcer rejected request")
)

type Client struct {
	socketPath string
	http       *http.Client
}

func New(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		MaxIdleConns:       2,
		IdleConnTimeout:    30 * time.Second,
	}
	return &Client{socketPath: socketPath, http: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
}

func (c *Client) CloseIdleConnections() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

func (c *Client) Ensure(ctx context.Context, requestID string) error {
	var response enforcerprotocol.ActionResponse
	if err := c.do(ctx, http.MethodPost, "/v1/ensure", enforcerprotocol.EnsureRequest{RequestID: requestID, SchemaVersion: enforcerprotocol.SchemaVersion}, &response); err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("%w: ensure returned ok=false", ErrRejected)
	}
	return nil
}

func (c *Client) Add(ctx context.Context, requestID string, entry enforcerprotocol.Entry) error {
	var response enforcerprotocol.ActionResponse
	if err := c.do(ctx, http.MethodPost, "/v1/add", enforcerprotocol.MutationRequest{RequestID: requestID, Entry: entry}, &response); err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("%w: add returned ok=false", ErrRejected)
	}
	return nil
}

func (c *Client) Remove(ctx context.Context, requestID string, key enforcerprotocol.Key) error {
	var response enforcerprotocol.ActionResponse
	if err := c.do(ctx, http.MethodPost, "/v1/remove", enforcerprotocol.RemoveRequest{RequestID: requestID, Key: key}, &response); err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("%w: remove returned ok=false", ErrRejected)
	}
	return nil
}

func (c *Client) List(ctx context.Context) (enforcerprotocol.ListResponse, error) {
	var response enforcerprotocol.ListResponse
	err := c.do(ctx, http.MethodGet, "/v1/list", nil, &response)
	return response, err
}

func (c *Client) Reconcile(ctx context.Context, requestID string, entries []enforcerprotocol.Entry) (enforcerprotocol.ReconcileResponse, error) {
	var response enforcerprotocol.ReconcileResponse
	err := c.do(ctx, http.MethodPost, "/v1/reconcile", enforcerprotocol.ReconcileRequest{RequestID: requestID, Entries: entries}, &response)
	return response, err
}

func (c *Client) do(ctx context.Context, method, path string, input, output any) error {
	if c == nil || c.http == nil || strings.TrimSpace(c.socketPath) == "" {
		return ErrUnavailable
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode enforcer request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, body)
	if err != nil {
		return fmt.Errorf("create enforcer request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, sanitize(err.Error(), c.socketPath))
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 1<<20)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var remote enforcerprotocol.ErrorResponse
		_ = json.NewDecoder(limited).Decode(&remote)
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%w: %s", ErrPermissionDenied, safeRemote(remote))
		}
		return fmt.Errorf("%w: HTTP %d: %s", ErrRejected, response.StatusCode, safeRemote(remote))
	}
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode enforcer response: %w", err)
	}
	return nil
}

func safeRemote(response enforcerprotocol.ErrorResponse) string {
	code := strings.TrimSpace(response.Code)
	if code == "" {
		return "request failed"
	}
	return code
}

func sanitize(message, secret string) string {
	if secret == "" {
		return message
	}
	return strings.ReplaceAll(message, secret, "<socket>")
}
