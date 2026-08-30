//go:build linux

package nftnetlink

import (
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestDecodeNetlinkErrorIdentifiesRejectedRequest(t *testing.T) {
	frame := make([]byte, HeaderLength+4+HeaderLength)
	binary.NativeEndian.PutUint32(frame[0:4], uint32(len(frame)))
	binary.NativeEndian.PutUint16(frame[4:6], nlmsgError)
	code := int32(-int32(syscall.EINVAL))
	binary.NativeEndian.PutUint32(frame[HeaderLength:HeaderLength+4], uint32(code))
	original := frame[HeaderLength+4:]
	binary.NativeEndian.PutUint32(original[0:4], HeaderLength+NFGenLength)
	binary.NativeEndian.PutUint16(original[4:6], NFTablesType(MessageNewSet))
	binary.NativeEndian.PutUint32(original[8:12], 42)

	err := decodeNetlinkError(frame, len(frame))
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("error=%v", err)
	}
	if !strings.Contains(err.Error(), "type 0xa09") || !strings.Contains(err.Error(), "sequence 42") {
		t.Fatalf("error lacks request context: %v", err)
	}
}
