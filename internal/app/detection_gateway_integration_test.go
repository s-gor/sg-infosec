//go:build linux && cgo

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/detection"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/store"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func TestAutonomousPanelDetectionIsVisibleToGatewayDecisionCheck(t *testing.T) {
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	records := make([]detection.JournalRecord, 0, 5)
	for index := 0; index < 5; index++ {
		records = append(records, detection.JournalRecord{
			Unit:       "sg-gateway.service",
			Identifier: "sg-gateway",
			Message:    `{"event_type":"auth.failed","ip":"203.0.113.88","route":"/admin/login"}`,
			Cursor:     string(rune('a' + index)),
			OccurredAt: base.Add(time.Duration(index) * time.Second),
		})
	}

	cfg := testConfig(t)
	cfg.Sources[0].ID = detection.GatewayDecisionSourceID
	fakeClock := &clock.Fake{Current: base.Add(time.Minute)}
	application, err := New(cfg, Dependencies{
		Clock:             fakeClock,
		UID:               uint32(os.Getuid()),
		EnforcerInterval:  time.Hour,
		EnforcerClient:    &detectorIntegrationEnforcer{},
		DetectorSource:    scriptedDetectorSource{records: records},
		RetentionInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("application shutdown: %v", err)
		}
	}()
	waitSocket(t, cfg.ControlSocket)

	address := netip.MustParseAddr("203.0.113.88")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		page, listErr := application.store.ListDecisions(context.Background(), store.DecisionFilter{
			SourceID: detection.GatewayDecisionSourceID,
			Scope:    model.ScopeAdminLogin,
			State:    model.DecisionActive,
			Limit:    10,
		})
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(page.Items) == 1 && page.Items[0].IP == address {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	requestBody, err := json.Marshal(protocol.DecisionCheckRequest{
		Scope:   string(model.ScopeAdminLogin),
		IP:      address.String(),
		RouteID: "admin.login",
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", cfg.ControlSocket)
		},
	}}
	request, err := http.NewRequest(http.MethodPost, "http://unix/v1/decisions/check", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var result protocol.DecisionCheckResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.Blocked || result.DecisionID == "" {
		t.Fatalf("decision check = %#v", result)
	}
}
