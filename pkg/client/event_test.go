package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestClientSubmitEventUsesEventsRoute(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "events.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/events" {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		var event protocol.EventRequest
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.EventID != "ssh-journal-test" || event.Scope != "ssh" || event.IP != "192.0.2.10" {
			t.Fatalf("event=%+v", event)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("{\"accepted\":true,\"decision_id\":\"decision-1\",\"request_id\":\"request-1\"}"))
	})}
	go server.Serve(listener)
	defer server.Close()

	response, err := New(socketPath).SubmitEvent(context.Background(), protocol.EventRequest{
		EventID: "ssh-journal-test", EventType: "auth.failed", Scope: "ssh", IP: "192.0.2.10", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Accepted || response.DecisionID != "decision-1" || response.RequestID != "request-1" {
		t.Fatalf("response=%+v", response)
	}
}
