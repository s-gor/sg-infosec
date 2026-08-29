//go:build linux

package unixhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/s-gor/sg-infosec/internal/sourceauth"
)

type Config struct {
	SocketPath       string
	Mode             os.FileMode
	ExpectedOwnerUID uint32
}

type Server struct {
	config   Config
	listener *net.UnixListener
	http     *http.Server
	closeMu  sync.Mutex
	closed   bool
}

func New(config Config, handler http.Handler, resolver *sourceauth.Resolver) (*Server, error) {
	if config.SocketPath == "" {
		return nil, fmt.Errorf("Unix socket path is required")
	}
	if config.Mode == 0 {
		return nil, fmt.Errorf("Unix socket mode is required")
	}
	if handler == nil {
		return nil, fmt.Errorf("HTTP handler is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("source resolver is required")
	}
	if err := prepareSocketPath(config.SocketPath, config.ExpectedOwnerUID); err != nil {
		return nil, err
	}
	address, err := net.ResolveUnixAddr("unix", config.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("resolve Unix socket: %w", err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, fmt.Errorf("listen on Unix socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	boundInfo, err := os.Lstat(config.SocketPath)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("inspect bound Unix socket: %w", err)
	}
	boundOwner, err := ownerUID(boundInfo)
	if err != nil {
		listener.Close()
		_ = removeSocketIfSame(config.SocketPath, boundInfo)
		return nil, err
	}
	if boundOwner != config.ExpectedOwnerUID {
		listener.Close()
		_ = removeSocketIfSame(config.SocketPath, boundInfo)
		return nil, fmt.Errorf("bound Unix socket is owned by UID %d, expected %d", boundOwner, config.ExpectedOwnerUID)
	}
	if err := os.Chmod(config.SocketPath, config.Mode.Perm()); err != nil {
		listener.Close()
		_ = removeSocketIfSame(config.SocketPath, boundInfo)
		return nil, fmt.Errorf("set Unix socket mode: %w", err)
	}

	guardedHandler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if _, ok := sourceauth.IdentityFromContext(request.Context()); !ok {
			http.Error(w, "unauthorized local source", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, request)
	})
	httpServer := &http.Server{
		Handler:           guardedHandler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			unixConn, ok := conn.(*net.UnixConn)
			if !ok {
				return sourceauth.WithAuthenticationError(ctx, fmt.Errorf("connection is not Unix"))
			}
			credentials, err := sourceauth.PeerCredentials(unixConn)
			if err != nil {
				return sourceauth.WithAuthenticationError(ctx, err)
			}
			identity, err := resolver.Resolve(credentials)
			if err != nil {
				return sourceauth.WithAuthenticationError(ctx, err)
			}
			return sourceauth.WithIdentity(ctx, identity)
		},
	}
	return &Server{config: config, listener: listener, http: httpServer}, nil
}

func (s *Server) Serve() error {
	if s == nil || s.listener == nil || s.http == nil {
		return fmt.Errorf("Unix HTTP server is not initialized")
	}
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	shutdownErr := s.http.Shutdown(ctx)
	removeErr := removeOwnedSocket(s.config.SocketPath, s.config.ExpectedOwnerUID)
	return errors.Join(shutdownErr, removeErr)
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	closeErr := s.http.Close()
	removeErr := removeOwnedSocket(s.config.SocketPath, s.config.ExpectedOwnerUID)
	return errors.Join(closeErr, removeErr)
}

func removeSocketIfSame(path string, original os.FileInfo) error {
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSocket == 0 || !os.SameFile(original, current) {
		return fmt.Errorf("refusing to remove replacement at Unix socket path %q", path)
	}
	return os.Remove(path)
}

func prepareSocketPath(path string, expectedUID uint32) error {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("Unix socket parent directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("Unix socket parent %q is not a directory", parent)
	}
	info, err = os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Unix socket path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Unix socket path %q is a symlink", path)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("Unix socket path %q is not a Unix socket", path)
	}
	owner, err := ownerUID(info)
	if err != nil {
		return err
	}
	if owner != expectedUID {
		return fmt.Errorf("Unix socket path %q is owned by UID %d, expected %d", path, owner, expectedUID)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale Unix socket: %w", err)
	}
	return nil
}

func removeOwnedSocket(path string, expectedUID uint32) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Unix socket during cleanup: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove replacement at Unix socket path %q", path)
	}
	owner, err := ownerUID(info)
	if err != nil {
		return err
	}
	if owner != expectedUID {
		return fmt.Errorf("refusing to remove Unix socket owned by UID %d", owner)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove Unix socket: %w", err)
	}
	return nil
}

func ownerUID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("Unix socket ownership metadata is unavailable")
	}
	return stat.Uid, nil
}
