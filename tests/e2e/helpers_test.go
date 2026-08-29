//go:build linux && cgo

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func unixHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

func postEvent(t *testing.T, socketPath string, request protocol.EventRequest) (protocol.EventResponse, int) {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(http.MethodPost, "http://unix/v1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := unixHTTPClient(socketPath).Do(httpRequest)
	if err != nil {
		t.Fatalf("post event: %v", err)
	}
	defer response.Body.Close()
	var decoded protocol.EventResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode event response: %v", err)
	}
	return decoded, response.StatusCode
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Unix socket did not appear: %s", path)
}

func waitForHealth(t *testing.T, service *client.Client) client.HealthResponse {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		response, err := service.Health(context.Background())
		if err == nil && response.Status == "healthy" {
			return response
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("health did not become ready: %v", last)
	return client.HealthResponse{}
}

func awaitRunResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("application did not stop")
		return fmt.Errorf("unreachable")
	}
}
