//go:build linux

package nftnetlink

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestBatchBeginMatchesLinuxUAPIFixture(t *testing.T) {
	message := BatchBegin(0x11223344)
	encoded, err := Encode(message)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x14, 0x00, 0x00, 0x00,
		0x10, 0x00,
		0x01, 0x00,
		0x44, 0x33, 0x22, 0x11,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0a,
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded=% x\nwant   =% x", encoded, want)
	}
}

func TestBatchEndMatchesLinuxUAPIFixture(t *testing.T) {
	encoded, err := Encode(BatchEnd(9))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x14, 0x00, 0x00, 0x00,
		0x11, 0x00,
		0x01, 0x00,
		0x09, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0a,
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded=% x\nwant   =% x", encoded, want)
	}
}

func TestNFTablesMessageTypeAndAttributeAlignment(t *testing.T) {
	message := Message{
		Header: Header{
			Type:  NFTablesType(MessageGetTable),
			Flags: FlagRequest | FlagDump,
			Seq:   7,
		},
		Family:     FamilyIPv4,
		Attributes: []Attribute{{Type: 1, Data: []byte{'a', 'b', 'c'}}},
	}
	encoded, err := Encode(message)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x1c, 0x00, 0x00, 0x00,
		0x01, 0x0a,
		0x01, 0x03,
		0x07, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x01, 0x00,
		'a', 'b', 'c', 0x00,
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded=% x\nwant   =% x", encoded, want)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.Type != NFTablesType(MessageGetTable) || decoded.Family != FamilyIPv4 {
		t.Fatalf("decoded=%+v", decoded)
	}
	if len(decoded.Attributes) != 1 || decoded.Attributes[0].Type != 1 || string(decoded.Attributes[0].Data) != "abc" {
		t.Fatalf("attributes=%+v", decoded.Attributes)
	}
}

func TestDecodeRejectsTrailingFrameBytes(t *testing.T) {
	encoded, err := Encode(BatchBegin(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append(encoded, 0, 0, 0, 0)); err == nil {
		t.Fatal("single-frame decoder accepted trailing bytes")
	}
}

func TestDecodeManyHonorsNetlinkAlignment(t *testing.T) {
	first, err := Encode(Message{Header: Header{Type: NFTablesType(MessageGetSet), Flags: FlagRequest, Seq: 1}, Family: FamilyIPv6})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encode(BatchEnd(2))
	if err != nil {
		t.Fatal(err)
	}
	messages, err := DecodeMany(append(first, second...))
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Header.Seq != 1 || messages[1].Header.Type != TypeBatchEnd {
		t.Fatalf("messages=%+v", messages)
	}
}

func TestDecoderRejectsMalformedLengthsAndAttributes(t *testing.T) {
	cases := [][]byte{
		make([]byte, HeaderLength-1),
		{0x0f, 0, 0, 0, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x18, 0, 0, 0, 0x01, 0x0a, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 1, 0},
	}
	for index, input := range cases {
		if _, err := Decode(input); err == nil {
			t.Fatalf("case %d accepted: % x", index, input)
		}
	}
}

func TestClientSendsWholeBatchAsOneDatagram(t *testing.T) {
	raw := &recordingRawTransport{}
	client := NewClient(raw)
	request := []Message{BatchBegin(10), {
		Header: Header{Type: NFTablesType(MessageGetTable), Flags: FlagRequest | FlagDump, Seq: 11},
		Family: FamilyUnspecified,
	}, BatchEnd(12)}
	response, err := client.Exchange(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if raw.calls != 1 || len(response) != 3 {
		t.Fatalf("calls=%d response=%d", raw.calls, len(response))
	}
	messages, err := DecodeMany(raw.request)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 || messages[0].Header.Type != TypeBatchBegin || messages[2].Header.Type != TypeBatchEnd {
		t.Fatalf("messages=%+v", messages)
	}
}

func TestClientFailsClosedOnTransportOrDecodeError(t *testing.T) {
	client := NewClient(rawTransportFunc(func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("netlink unavailable")
	}))
	if _, err := client.Exchange(context.Background(), []Message{BatchBegin(1)}); err == nil {
		t.Fatal("transport error was ignored")
	}
	client = NewClient(rawTransportFunc(func(context.Context, []byte) ([]byte, error) {
		return []byte{0x01}, nil
	}))
	if _, err := client.Exchange(context.Background(), []Message{BatchBegin(1)}); err == nil {
		t.Fatal("decode error was ignored")
	}
}

type recordingRawTransport struct {
	calls   int
	request []byte
}

func (r *recordingRawTransport) Exchange(_ context.Context, request []byte) ([]byte, error) {
	r.calls++
	r.request = append([]byte(nil), request...)
	return append([]byte(nil), request...), nil
}

type rawTransportFunc func(context.Context, []byte) ([]byte, error)

func (f rawTransportFunc) Exchange(ctx context.Context, request []byte) ([]byte, error) {
	return f(ctx, request)
}
