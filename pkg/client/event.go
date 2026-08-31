package client

import (
	"context"
	"net/http"

	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func (c *Client) SubmitEvent(ctx context.Context, request protocol.EventRequest) (protocol.EventResponse, error) {
	var response protocol.EventResponse
	err := c.do(ctx, http.MethodPost, "/v1/events", request, &response)
	return response, err
}
