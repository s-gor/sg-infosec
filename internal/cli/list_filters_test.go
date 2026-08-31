package cli

import (
	"context"
	"io"
	"testing"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type recordingListService struct {
	fakeService
	options client.ListOptions
}

func (s *recordingListService) ListDecisions(_ context.Context, options client.ListOptions) (protocol.DecisionListResponse, error) {
	s.options = options
	return protocol.DecisionListResponse{}, nil
}

func TestCLIDecisionsListForwardsParsedFilters(t *testing.T) {
	service := &recordingListService{}
	code := Run([]string{
		"decisions", "list",
		"--limit", "7",
		"--cursor", "cursor-1",
		"--source", "local-admin",
		"--scope", "ssh",
		"--state", "active",
	}, io.Discard, io.Discard, testDependencies(service))
	if code != ExitSuccess {
		t.Fatalf("code = %d, want %d", code, ExitSuccess)
	}
	want := client.ListOptions{
		Limit:    7,
		Cursor:   "cursor-1",
		SourceID: "local-admin",
		Scope:    "ssh",
		State:    "active",
	}
	if service.options != want {
		t.Fatalf("options = %#v, want %#v", service.options, want)
	}
}
