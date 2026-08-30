//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/internal/enforcerapi"
	"github.com/s-gor/sg-infosec/internal/enforcertransport"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/nftbackend"
	"github.com/s-gor/sg-infosec/internal/nftkernel"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sg-infosec-enforcerd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "/run/sg-infosec/enforcer.sock", "Unix socket")
	serviceUser := flags.String("service-user", "sg-infosec", "authorized non-root user")
	purge := flags.Bool("purge-owned-table", false, "delete validated owned nftables table and exit")
	version := flags.Bool("version", false, "print version")
	var panelPorts uint16List
	flags.Var(&panelPorts, "panel-port", "dedicated TCP panel port (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if *version {
		if err := json.NewEncoder(stdout).Encode(buildinfo.Info()); err != nil {
			return 1
		}
		return 0
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "sg-infosec-enforcerd must run as root")
		return 1
	}
	driver := nftkernel.NewSocketDriver()
	if *purge {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := driver.PurgeOwnedTable(ctx); err != nil {
			fmt.Fprintf(stderr, "purge owned table: %v\n", err)
			return 1
		}
		return 0
	}
	uid, gid, err := resolveIdentity(*serviceUser)
	if err != nil {
		fmt.Fprintf(stderr, "resolve service identity: %v\n", err)
		return 2
	}
	targets := []enforcer.AllowedTarget{{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22}}
	seen := map[uint16]struct{}{}
	for _, port := range panelPorts {
		if port == 0 || port == 585 || port == 586 || port == 587 {
			fmt.Fprintf(stderr, "panel port %d is not allowed\n", port)
			return 2
		}
		if _, ok := seen[port]; ok {
			fmt.Fprintf(stderr, "duplicate panel port %d\n", port)
			return 2
		}
		seen[port] = struct{}{}
		targets = append(targets, enforcer.AllowedTarget{Scope: model.ScopePanelPort, Protocol: enforcer.ProtocolTCP, Port: port})
	}
	policy, err := enforcer.NewPolicy(targets, 7*24*time.Hour, 10000)
	if err != nil {
		fmt.Fprintf(stderr, "policy: %v\n", err)
		return 2
	}
	backend := nftbackend.New(driver, clock.Real{})
	service := enforcer.NewService(backend, policy, clock.Real{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := service.Ensure(ctx, "startup-ensure"); err != nil {
		cancel()
		fmt.Fprintf(stderr, "ensure nftables schema: %v\n", err)
		return 1
	}
	cancel()
	handler := enforcerapi.New(service, 64*1024)
	server, err := enforcertransport.New(enforcertransport.Config{SocketPath: *socket, Mode: 0660, OwnerUID: 0, OwnerGID: gid, ServiceUID: uid}, handler)
	if err != nil {
		fmt.Fprintf(stderr, "initialize enforcer socket: %v\n", err)
		return 1
	}
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintf(stderr, "serve enforcer: %v\n", err)
			return 1
		}
	case <-runCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "shutdown enforcer: %v\n", err)
			return 1
		}
	}
	return 0
}

type uint16List []uint16

func (v *uint16List) String() string { return fmt.Sprint([]uint16(*v)) }
func (v *uint16List) Set(value string) error {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return fmt.Errorf("invalid port %q", value)
	}
	*v = append(*v, uint16(parsed))
	return nil
}
func resolveIdentity(name string) (uint32, uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return 0, 0, err
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("service user must be non-root")
	}
	return uint32(uid), uint32(gid), nil
}
