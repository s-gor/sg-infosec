package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/retention"
)

type fakeDatabase struct {
	pingErr  error
	count    int64
	bytes    int64
	bytesErr error
}

func (f fakeDatabase) Ping(context.Context) error { return f.pingErr }
func (f fakeDatabase) CountActiveDecisions(context.Context, time.Time) (int64, error) {
	if f.pingErr != nil {
		return 0, f.pingErr
	}
	return f.count, nil
}
func (f fakeDatabase) DatabaseBytes() (int64, error) { return f.bytes, f.bytesErr }

type fakeRetention struct{ status retention.Status }

func (f fakeRetention) Status() retention.Status { return f.status }

func TestHealthReportsDatabaseFailureWithoutPanicking(t *testing.T) {
	service := New(fakeDatabase{pingErr: errors.New("database offline")}, fakeRetention{}, func() time.Time {
		return time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC)
	})
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "database offline") {
		t.Fatalf("internal error leaked: %s", response.Body.String())
	}
}

func TestHealthReportsDegradedRetentionAsHTTP200(t *testing.T) {
	at := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	service := New(fakeDatabase{count: 2, bytes: 4096}, fakeRetention{status: retention.Status{LastSuccessAt: &at, LastError: "cleanup failed"}}, func() time.Time {
		return at.Add(time.Hour)
	})
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"status":"degraded"`) {
		t.Fatalf("body=%s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "/var/lib") {
		t.Fatalf("path leaked: %s", response.Body.String())
	}
}
