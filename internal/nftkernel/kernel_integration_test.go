//go:build linux

package nftkernel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/nftbackend"
	"github.com/s-gor/sg-infosec/internal/nftnetlink"
)

func TestKernelSmoke(t *testing.T) {
	if os.Getenv("SG_INFOSEC_KERNEL_SMOKE") != "1" {
		t.Skip("kernel smoke disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	driver := NewSocketDriver()
	if err := createForeignTable(ctx, driver, "sg_gateway_awg_test"); err != nil {
		t.Fatal(err)
	}
	defer driver.PurgeOwnedTable(context.Background())
	backend := nftbackend.New(driver, clock.Real{})
	if err := backend.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	assertOwnedSchema(t, ctx, driver)
	assertForeignTableExists(t, ctx, driver, "sg_gateway_awg_test")

	ipv4Listener := startTCPListener(t, "tcp4", "203.0.113.1:22")
	defer ipv4Listener.Close()
	ipv6Listener := startTCPListener(t, "tcp6", "[2001:db8::1]:22")
	defer ipv6Listener.Close()
	panelListener := startTCPListener(t, "tcp6", "[2001:db8::1]:63443")
	defer panelListener.Close()

	ipv4 := enforcer.Entry{Key: enforcer.Key{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22, IP: netip.MustParseAddr("203.0.113.7")}, ExpiresAt: time.Now().UTC().Add(5 * time.Second)}
	ipv6 := enforcer.Entry{Key: enforcer.Key{Scope: model.ScopeSSH, Protocol: enforcer.ProtocolTCP, Port: 22, IP: netip.MustParseAddr("2001:db8::7")}, ExpiresAt: time.Now().UTC().Add(5 * time.Second)}
	panel := enforcer.Entry{Key: enforcer.Key{Scope: model.ScopePanelPort, Protocol: enforcer.ProtocolTCP, Port: 63443, IP: netip.MustParseAddr("2001:db8::7")}, ExpiresAt: time.Now().UTC().Add(5 * time.Second)}

	requireConnect(t, "tcp4", "203.0.113.7:0", "203.0.113.1:22")
	requireConnect(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:22")
	requireConnect(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:63443")

	for _, entry := range []enforcer.Entry{ipv4, ipv6, panel} {
		if err := backend.Add(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	requireBlocked(t, "tcp4", "203.0.113.7:0", "203.0.113.1:22")
	requireBlocked(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:22")
	requireBlocked(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:63443")

	if err := backend.Remove(ctx, ipv4.Key); err != nil {
		t.Fatal(err)
	}
	requireEventuallyConnect(t, "tcp4", "203.0.113.7:0", "203.0.113.1:22")

	expiring := ipv4
	expiring.ExpiresAt = time.Now().UTC().Add(750 * time.Millisecond)
	if err := backend.Add(ctx, expiring); err != nil {
		t.Fatal(err)
	}
	requireBlocked(t, "tcp4", "203.0.113.7:0", "203.0.113.1:22")
	requireEventuallyConnect(t, "tcp4", "203.0.113.7:0", "203.0.113.1:22")

	if err := driver.PurgeOwnedTable(ctx); err != nil {
		t.Fatal(err)
	}
	assertForeignTableExists(t, ctx, driver, "sg_gateway_awg_test")
	report, err := backend.Reconcile(ctx, []enforcer.Entry{ipv6, panel})
	if err != nil {
		t.Fatal(err)
	}
	if report.Created != 2 {
		t.Fatalf("restart reconciliation report=%+v", report)
	}
	assertOwnedSchema(t, ctx, driver)
	requireBlocked(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:22")
	requireBlocked(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:63443")

	listed, err := backend.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("listed=%+v", listed)
	}
	for _, entry := range []enforcer.Entry{ipv6, panel} {
		if err := backend.Remove(ctx, entry.Key); err != nil {
			t.Fatal(err)
		}
	}
	requireEventuallyConnect(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:22")
	requireEventuallyConnect(t, "tcp6", "[2001:db8::7]:0", "[2001:db8::1]:63443")
}

func createForeignTable(ctx context.Context, driver *Driver, name string) error {
	messages := []nftnetlink.Message{
		nftnetlink.BatchBegin(driver.next()),
		mutationType(driver.next(), nftnetlink.MessageNewTable, nftnetlink.FlagRequest|nftnetlink.FlagAck|nftnetlink.FlagCreate|nftnetlink.FlagExclusive, []nftnetlink.Attribute{strAttr(nftaTableName, name)}),
		nftnetlink.BatchEnd(driver.next()),
	}
	_, err := driver.client.Exchange(ctx, messages)
	return err
}

func assertOwnedSchema(t *testing.T, ctx context.Context, driver *Driver) {
	t.Helper()
	snapshot, err := driver.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tables) != 1 || len(snapshot.Tables[0].Chains) != 1 || len(snapshot.Tables[0].Sets) != 4 || len(snapshot.Tables[0].Rules) != 4 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func assertForeignTableExists(t *testing.T, ctx context.Context, driver *Driver, name string) {
	t.Helper()
	messages, err := driver.dump(ctx, nftnetlink.MessageGetTable, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range messages {
		if stringAttr(message.Attributes, nftaTableName) == name {
			return
		}
	}
	t.Fatalf("foreign table %q was removed", name)
}

func startTCPListener(t *testing.T, network, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	return listener
}

func requireConnect(t *testing.T, network, local, remote string) {
	t.Helper()
	if err := dialTCP(network, local, remote, 500*time.Millisecond); err != nil {
		t.Fatalf("expected connection %s -> %s: %v", local, remote, err)
	}
}

func requireBlocked(t *testing.T, network, local, remote string) {
	t.Helper()
	if err := dialTCP(network, local, remote, 400*time.Millisecond); err == nil {
		t.Fatalf("blocked connection unexpectedly succeeded: %s -> %s", local, remote)
	}
}

func requireEventuallyConnect(t *testing.T, network, local, remote string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = dialTCP(network, local, remote, 250*time.Millisecond)
		if last == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("connection did not recover %s -> %s: %v", local, remote, last)
}

func dialTCP(network, local, remote string, timeout time.Duration) error {
	localAddress, err := net.ResolveTCPAddr(network, local)
	if err != nil {
		return fmt.Errorf("resolve local address: %w", err)
	}
	dialer := net.Dialer{Timeout: timeout, LocalAddr: localAddress}
	connection, err := dialer.Dial(network, remote)
	if err != nil {
		return err
	}
	return connection.Close()
}
