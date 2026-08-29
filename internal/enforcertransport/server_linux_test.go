//go:build linux

package enforcertransport

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestUnixServerAuthorizesExactPeerUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enforcer.sock")
	server, err := New(Config{
		SocketPath: path,
		Mode:       0o600,
		OwnerUID:   uint32(os.Getuid()),
		OwnerGID:   uint32(os.Getgid()),
		ServiceUID: testServiceUID(),
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-serveErr; err != nil {
			t.Fatal(err)
		}
	}()

	response := unixRequest(t, path)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	response.Body.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
		t.Fatalf("owner=%d:%d", stat.Uid, stat.Gid)
	}
}

func TestPeerAuthorizationAcceptsOnlyRootAndServiceUID(t *testing.T) {
	serviceUID := uint32(4242)
	for _, uid := range []uint32{0, serviceUID} {
		if !authorizeUID(uid, serviceUID) {
			t.Fatalf("UID %d was rejected", uid)
		}
	}
	for _, uid := range []uint32{1, 4241, 4243, ^uint32(0)} {
		if authorizeUID(uid, serviceUID) {
			t.Fatalf("UID %d was accepted", uid)
		}
	}
}

func TestConfigRejectsUnsafeConfiguration(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	base := Config{
		SocketPath: filepath.Join(t.TempDir(), "s"),
		Mode:       0o600,
		OwnerUID:   uint32(os.Getuid()),
		OwnerGID:   uint32(os.Getgid()),
		ServiceUID: testServiceUID(),
	}
	cases := []Config{
		func() Config { c := base; c.SocketPath = "relative.sock"; return c }(),
		func() Config { c := base; c.ServiceUID = 0; return c }(),
		func() Config { c := base; c.Mode = 0o666; return c }(),
	}
	for index, config := range cases {
		if server, err := New(config, handler); err == nil {
			server.Close()
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestUnixServerRejectsSymlinkParent(t *testing.T) {
	realParent := t.TempDir()
	linkParent := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		SocketPath: filepath.Join(linkParent, "enforcer.sock"),
		Mode:       0o600,
		OwnerUID:   uint32(os.Getuid()),
		OwnerGID:   uint32(os.Getgid()),
		ServiceUID: testServiceUID(),
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err == nil {
		t.Fatal("symlink parent was accepted")
	}
}

func testServiceUID() uint32 {
	uid := uint32(os.Getuid())
	if uid == 0 {
		return 4242
	}
	return uid
}

func unixRequest(t *testing.T, path string) *http.Response {
	t.Helper()
	transport := &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.DialTimeout("unix", path, time.Second)
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("http://unix/v1/list")
	if err != nil {
		t.Fatal(err)
	}
	return response
}
