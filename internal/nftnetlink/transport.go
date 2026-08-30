//go:build linux

package nftnetlink

import (
	"bytes"
	"context"
	"fmt"
)

type RawTransport interface {
	Exchange(context.Context, []byte) ([]byte, error)
}

type Client struct{ raw RawTransport }

func NewClient(raw RawTransport) *Client { return &Client{raw: raw} }

func (c *Client) Exchange(ctx context.Context, request []Message) ([]Message, error) {
	if c == nil || c.raw == nil {
		return nil, ErrTransportMissing
	}
	var datagram bytes.Buffer
	for index, message := range request {
		encoded, err := Encode(message)
		if err != nil {
			return nil, fmt.Errorf("encode request %d: %w", index, err)
		}
		datagram.Write(encoded)
	}
	responseDatagram, err := c.raw.Exchange(ctx, append([]byte(nil), datagram.Bytes()...))
	if err != nil {
		return nil, fmt.Errorf("raw netlink exchange: %w", err)
	}
	if len(responseDatagram) == 0 {
		return nil, nil
	}
	response, err := DecodeMany(responseDatagram)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return response, nil
}
