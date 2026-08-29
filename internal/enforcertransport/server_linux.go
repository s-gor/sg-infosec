//go:build linux

package enforcertransport

import (
	"context"
	"encoding/json"
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
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

type Config struct {
	SocketPath string
	Mode       os.FileMode
	OwnerUID   uint32
	OwnerGID   uint32
	ServiceUID uint32
}

type Server struct {
	config   Config
	listener *net.UnixListener
	http     *http.Server
	closeMu  sync.Mutex
	closed   bool
}

type credentialsContextKey struct{}

func New(config Config, handler http.Handler) (*Server, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if handler == nil {
		return nil, fmt.Errorf("HTTP handler is required")
	}
	if err := prepareSocketPath(config.SocketPath, config.OwnerUID); err != nil {
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
	cleanup := func() {
		_ = listener.Close()
		_ = removeSocketIfSame(config.SocketPath, boundInfo)
	}
	if err := os.Chown(config.SocketPath, int(config.OwnerUID), int(config.OwnerGID)); err != nil {
		cleanup()
		return nil, fmt.Errorf("set Unix socket owner: %w", err)
	}
	if err := os.Chmod(config.SocketPath, config.Mode.Perm()); err != nil {
		cleanup()
		return nil, fmt.Errorf("set Unix socket mode: %w", err)
	}
	if err := verifyBoundSocket(config); err != nil {
		cleanup()
		return nil, err
	}

	guarded := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if _, ok := request.Context().Value(credentialsContextKey{}).(sourceauth.Credentials); !ok {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(enforcerprotocol.ErrorResponse{
				Code: "unauthorized_peer", Message: "local peer is not authorized",
			})
			return
		}
		handler.ServeHTTP(w, request)
	})

	httpServer := &http.Server{
		Handler:           guarded,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			unixConnection, ok := connection.(*net.UnixConn)
			if !ok {
				return ctx
			}
			credentials, err := sourceauth.PeerCredentials(unixConnection)
			if err != nil || !authorizeUID(credentials.UID, config.ServiceUID) {
				return ctx
			}
			return context.WithValue(ctx, credentialsContextKey{}, credentials)
		},
	}
	return &Server{config: config, listener: listener, http: httpServer}, nil
}

func validateConfig(config Config) error {
	if config.SocketPath == "" || !filepath.IsAbs(config.SocketPath) {
		return fmt.Errorf("absolute Unix socket path is required")
	}
	if config.Mode.Perm() != 0o600 && config.Mode.Perm() != 0o660 {
		return fmt.Errorf("Unix socket mode must be 0600 or 0660")
	}
	if config.ServiceUID == 0 {
		return fmt.Errorf("non-root sg-infosec UID is required")
	}
	return nil
}

func authorizeUID(peerUID, serviceUID uint32) bool {
	return peerUID == 0 || peerUID == serviceUID
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
	return errors.Join(s.http.Shutdown(ctx), removeOwnedSocket(s.config.SocketPath, s.config.OwnerUID))
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
	return errors.Join(s.http.Close(), removeOwnedSocket(s.config.SocketPath, s.config.OwnerUID))
}

func prepareSocketPath(path string, expectedUID uint32) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("Unix socket parent directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("Unix socket parent %q must be a real directory", parent)
	}
	info, err = os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Unix socket path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("Unix socket path %q is not an owned Unix socket", path)
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

func verifyBoundSocket(config Config) error {
	info, err := os.Lstat(config.SocketPath)
	if err != nil {
		return fmt.Errorf("inspect bound Unix socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != config.Mode.Perm() {
		return fmt.Errorf("bound Unix socket has unexpected type or mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("Unix socket ownership metadata is unavailable")
	}
	if stat.Uid != config.OwnerUID || stat.Gid != config.OwnerGID {
		return fmt.Errorf("bound Unix socket is owned by %d:%d, expected %d:%d", stat.Uid, stat.Gid, config.OwnerUID, config.OwnerGID)
	}
	return nil
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
