//go:build linux

package nftnetlink

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"
)

const (
	netlinkNetfilter = 12
	nlmsgNoop        = 1
	nlmsgError       = 2
	nlmsgDone        = 3
)

type SocketTransport struct{}

func NewSocketTransport() *SocketTransport { return &SocketTransport{} }

func (s *SocketTransport) Exchange(ctx context.Context, datagram []byte) ([]byte, error) {
	if len(datagram) == 0 {
		return nil, fmt.Errorf("empty netlink datagram")
	}
	pending, dumpExpected, err := expectedResponses(datagram)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("open NETLINK_NETFILTER socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("bind NETLINK_NETFILTER socket: %w", err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set NETLINK_NETFILTER nonblocking: %w", err)
	}
	if err := syscall.Sendto(fd, datagram, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("send NETLINK_NETFILTER batch: %w", err)
	}
	if len(pending) == 0 && !dumpExpected {
		return nil, nil
	}
	var output []byte
	dumpDone := !dumpExpected
	buffer := make([]byte, 1<<20)
	for len(pending) > 0 || !dumpDone {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, recvErr := syscall.Recvfrom(fd, buffer, 0)
		if recvErr != nil {
			if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EWOULDBLOCK) || errors.Is(recvErr, syscall.EINTR) {
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, ctx.Err()
				case <-timer.C:
				}
				continue
			}
			return nil, fmt.Errorf("receive NETLINK_NETFILTER response: %w", recvErr)
		}
		for offset := 0; offset < n; {
			if n-offset < HeaderLength {
				return nil, ErrMalformedMessage
			}
			length := int(binary.NativeEndian.Uint32(buffer[offset : offset+4]))
			if length < HeaderLength || offset+align(length) > n {
				return nil, ErrMalformedMessage
			}
			frame := buffer[offset : offset+align(length)]
			typeValue := binary.NativeEndian.Uint16(frame[4:6])
			seq := binary.NativeEndian.Uint32(frame[8:12])
			switch typeValue {
			case nlmsgNoop:
			case nlmsgDone:
				dumpDone = true
			case nlmsgError:
				if err := decodeNetlinkError(frame, length); err != nil {
					return nil, err
				}
				delete(pending, seq)
			default:
				if length < HeaderLength+NFGenLength {
					return nil, ErrMalformedMessage
				}
				output = append(output, frame...)
			}
			offset += align(length)
		}
	}
	return output, nil
}

func expectedResponses(datagram []byte) (map[uint32]struct{}, bool, error) {
	pending := map[uint32]struct{}{}
	dump := false
	for len(datagram) > 0 {
		if len(datagram) < HeaderLength {
			return nil, false, ErrMalformedMessage
		}
		length := int(binary.NativeEndian.Uint32(datagram[:4]))
		if length < HeaderLength || align(length) > len(datagram) {
			return nil, false, ErrMalformedMessage
		}
		flags := binary.NativeEndian.Uint16(datagram[6:8])
		seq := binary.NativeEndian.Uint32(datagram[8:12])
		if flags&FlagAck != 0 {
			pending[seq] = struct{}{}
		}
		if flags&FlagDump == FlagDump {
			dump = true
		}
		datagram = datagram[align(length):]
	}
	return pending, dump, nil
}

func decodeNetlinkError(frame []byte, length int) error {
	if length < HeaderLength+4 || length > len(frame) {
		return ErrMalformedMessage
	}
	code := int32(binary.NativeEndian.Uint32(frame[HeaderLength : HeaderLength+4]))
	if code == 0 {
		return nil
	}
	errno := syscall.Errno(-code)
	if length < HeaderLength+4+HeaderLength {
		return errno
	}
	original := frame[HeaderLength+4 : HeaderLength+4+HeaderLength]
	typeValue := binary.NativeEndian.Uint16(original[4:6])
	sequence := binary.NativeEndian.Uint32(original[8:12])
	return fmt.Errorf("netlink request type %#x sequence %d: %w", typeValue, sequence, errno)
}
