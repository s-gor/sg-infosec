package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/retention"
)

type Database interface {
	Ping(context.Context) error
	CountActiveDecisions(context.Context, time.Time) (int64, error)
	DatabaseBytes() (int64, error)
}

type Retention interface {
	Status() retention.Status
}

type Service struct {
	database  Database
	retention Retention
	now       func() time.Time
}

type Response struct {
	Status          string             `json:"status"`
	Database        string             `json:"database"`
	ProtocolVersion string             `json:"protocol_version"`
	Build           buildinfo.Metadata `json:"build"`
	ActiveDecisions int64              `json:"active_decisions"`
	DatabaseBytes   int64              `json:"database_bytes"`
	LastRetentionAt *time.Time         `json:"last_retention_at,omitempty"`
}

func New(database Database, retentionStatus Retention, now func() time.Time) *Service {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{database: database, retention: retentionStatus, now: now}
}

func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Service) serveHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		write(w, http.StatusMethodNotAllowed, map[string]string{"code": "method_not_allowed"})
		return
	}
	if request.URL.Path != "/v1/health" {
		write(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		return
	}
	response, status := s.snapshot(request.Context())
	write(w, status, response)
}

func (s *Service) snapshot(ctx context.Context) (Response, int) {
	response := Response{Status: "healthy", Database: "ok", ProtocolVersion: buildinfo.ProtocolVersion, Build: buildinfo.Info()}
	if s == nil || s.database == nil || s.retention == nil {
		response.Status = "unhealthy"
		response.Database = "unavailable"
		return response, http.StatusServiceUnavailable
	}
	if err := s.database.Ping(ctx); err != nil {
		response.Status = "unhealthy"
		response.Database = "unavailable"
		return response, http.StatusServiceUnavailable
	}
	count, err := s.database.CountActiveDecisions(ctx, s.now().UTC())
	if err != nil {
		response.Status = "unhealthy"
		response.Database = "unavailable"
		return response, http.StatusServiceUnavailable
	}
	response.ActiveDecisions = count
	bytes, err := s.database.DatabaseBytes()
	if err != nil {
		response.Status = "degraded"
	} else {
		response.DatabaseBytes = bytes
	}
	retentionStatus := s.retention.Status()
	response.LastRetentionAt = retentionStatus.LastSuccessAt
	if retentionStatus.LastError != "" {
		response.Status = "degraded"
	}
	return response, http.StatusOK
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
