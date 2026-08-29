//go:build linux

package nftnetlink

import (
	"context"
	"fmt"
)

type RawTransport interface {
	Exchange(context.Context, [][]byte) ([][]byte, error)
}

type Client struct {
	raw RawTransport
}

func NewClient(raw RawTransport) *Client {
	return &Client{raw: raw}
}

func (c *Client) Exchange(ctx context.Context, request []Message) ([]Message, error) {
	if c == nil || c.raw == nil {
		return nil, ErrTransportMissing
	}
	frames := make([][]byte, 0, len(request))
	for index, message := range request {
		encoded, err := Encode(message)
		if err != nil {
			return nil, fmt.Errorf("encode request %d: %w", index, err)
		}
		frames = append(frames, encoded)
	}
	responseFrames, err := c.raw.Exchange(ctx, cloneFrames(frames))
	if err != nil {
		return nil, fmt.Errorf("raw netlink exchange: %w", err)
	}
	response := make([]Message, 0, len(responseFrames))
	for index, frame := range responseFrames {
		messages, err := DecodeMany(frame)
		if err != nil {
			return nil, fmt.Errorf("decode response %d: %w", index, err)
		}
		response = append(response, messages...)
	}
	return response, nil
}

func cloneFrames(frames [][]byte) [][]byte {
	result := make([][]byte, len(frames))
	for index, frame := range frames {
		result[index] = append([]byte(nil), frame...)
	}
	return result
}
