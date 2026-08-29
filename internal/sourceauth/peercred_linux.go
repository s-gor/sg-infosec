//go:build linux

package sourceauth

import (
	"fmt"
	"net"
	"syscall"
)

func PeerCredentials(conn *net.UnixConn) (Credentials, error) {
	if conn == nil {
		return Credentials{}, fmt.Errorf("Unix connection is nil")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return Credentials{}, fmt.Errorf("access Unix connection: %w", err)
	}
	var credentials Credentials
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		credentials = Credentials{PID: int(ucred.Pid), UID: ucred.Uid, GID: ucred.Gid}
	}); err != nil {
		return Credentials{}, fmt.Errorf("inspect Unix connection: %w", err)
	}
	if controlErr != nil {
		return Credentials{}, fmt.Errorf("read Unix peer credentials: %w", controlErr)
	}
	return credentials, nil
}
