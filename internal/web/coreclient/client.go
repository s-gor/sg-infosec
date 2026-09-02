package coreclient

import (
	"context"

	baseclient "github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type ListOptions = baseclient.ListOptions
type HealthResponse = baseclient.HealthResponse

type Service interface {
	Health(context.Context) (baseclient.HealthResponse, error)
	ListDecisions(context.Context, baseclient.ListOptions) (protocol.DecisionListResponse, error)
	AddDecision(context.Context, protocol.ManualDecisionRequest) (protocol.DecisionView, error)
	RevokeDecision(context.Context, string) (protocol.ActionResponse, error)
	ListAllowlist(context.Context, baseclient.ListOptions) (protocol.AllowlistListResponse, error)
	AddAllowlist(context.Context, protocol.AllowlistCreateRequest) (protocol.AllowlistView, error)
	RemoveAllowlist(context.Context, string) (protocol.ActionResponse, error)
	ListAudit(context.Context, baseclient.ListOptions) (protocol.AuditListResponse, error)
}

type service struct {
	client *baseclient.Client
}

func New(socketPath string) Service {
	return &service{client: baseclient.New(socketPath)}
}

func (s *service) Health(ctx context.Context) (baseclient.HealthResponse, error) {
	return s.client.Health(ctx)
}

func (s *service) ListDecisions(ctx context.Context, options baseclient.ListOptions) (protocol.DecisionListResponse, error) {
	return s.client.ListDecisions(ctx, options)
}

func (s *service) AddDecision(ctx context.Context, request protocol.ManualDecisionRequest) (protocol.DecisionView, error) {
	return s.client.AddDecision(ctx, request)
}

func (s *service) RevokeDecision(ctx context.Context, id string) (protocol.ActionResponse, error) {
	return s.client.RevokeDecision(ctx, id)
}

func (s *service) ListAllowlist(ctx context.Context, options baseclient.ListOptions) (protocol.AllowlistListResponse, error) {
	return s.client.ListAllowlist(ctx, options)
}

func (s *service) AddAllowlist(ctx context.Context, request protocol.AllowlistCreateRequest) (protocol.AllowlistView, error) {
	return s.client.AddAllowlist(ctx, request)
}

func (s *service) RemoveAllowlist(ctx context.Context, id string) (protocol.ActionResponse, error) {
	return s.client.RemoveAllowlist(ctx, id)
}

func (s *service) ListAudit(ctx context.Context, options baseclient.ListOptions) (protocol.AuditListResponse, error) {
	return s.client.ListAudit(ctx, options)
}
