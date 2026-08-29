package enforcer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

func TestDefaultPolicyAcceptsOnlySSHAndCanonicalizesIP(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	entry, err := policy.NormalizeEntry(now, enforcerprotocol.Entry{
		Scope: "ssh", Protocol: "tcp", Port: 22,
		IP: "::ffff:203.0.113.7", ExpiresAt: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.Scope != model.ScopeSSH || entry.Protocol != ProtocolTCP || entry.Port != 22 {
		t.Fatalf("unexpected target: %+v", entry)
	}
	if got := entry.IP.String(); got != "203.0.113.7" {
		t.Fatalf("canonical IP = %q", got)
	}
	if entry.Family() != FamilyIPv4 {
		t.Fatalf("family = %q", entry.Family())
	}
}

func TestPolicyRejectsUnknownOrDangerousTargets(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	cases := []enforcerprotocol.Entry{
		{Scope: "admin-login", Protocol: "tcp", Port: 443, IP: "203.0.113.7", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "udp", Port: 22, IP: "203.0.113.7", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 443, IP: "203.0.113.7", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "0.0.0.0", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "ff02::1", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "fe80::1%eth0", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.7", ExpiresAt: now},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.7", ExpiresAt: now.Add(8 * 24 * time.Hour)},
	}
	for index, input := range cases {
		if _, err := policy.NormalizeEntry(now, input); err == nil {
			t.Fatalf("case %d accepted: %+v", index, input)
		}
	}
}

func TestPanelPortRequiresExplicitAllowlist(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	input := enforcerprotocol.Entry{
		Scope: "panel-port", Protocol: "tcp", Port: 8443,
		IP: "2001:db8::7", ExpiresAt: now.Add(time.Hour),
	}
	if _, err := DefaultPolicy().NormalizeEntry(now, input); err == nil {
		t.Fatal("default policy accepted panel port")
	}
	policy, err := NewPolicy([]AllowedTarget{
		{Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22},
		{Scope: model.ScopePanelPort, Protocol: ProtocolTCP, Port: 8443},
	}, 7*24*time.Hour, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NormalizeEntry(now, input); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileRejectsCanonicalDuplicatesAtomically(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	backend := &recordingBackend{}
	service := NewService(backend, DefaultPolicy(), &clock.Fake{Current: now})
	_, err := service.Reconcile(context.Background(), "req.1", []enforcerprotocol.Entry{
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.7", ExpiresAt: now.Add(time.Hour)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "::ffff:203.0.113.7", ExpiresAt: now.Add(2 * time.Hour)},
	})
	if !errors.Is(err, ErrDuplicateEntry) {
		t.Fatalf("error = %v", err)
	}
	if backend.reconcileCalls != 0 {
		t.Fatal("backend was called for invalid reconcile")
	}
}

func TestServiceRejectsInvalidRequestIDBeforeBackend(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	backend := &recordingBackend{}
	service := NewService(backend, DefaultPolicy(), &clock.Fake{Current: now})
	err := service.Add(context.Background(), "contains space", enforcerprotocol.Entry{
		Scope: "ssh", Protocol: "tcp", Port: 22,
		IP: "203.0.113.7", ExpiresAt: now.Add(time.Hour),
	})
	if !errors.Is(err, ErrInvalidRequestID) {
		t.Fatalf("error = %v", err)
	}
	if backend.addCalls != 0 {
		t.Fatal("backend was called")
	}
}

func TestNewPolicyRejectsInvalidConfiguration(t *testing.T) {
	cases := []struct {
		targets    []AllowedTarget
		maxTTL     time.Duration
		maxEntries int
	}{
		{nil, time.Hour, 1},
		{[]AllowedTarget{{Scope: model.ScopeAdminLogin, Protocol: ProtocolTCP, Port: 443}}, time.Hour, 1},
		{[]AllowedTarget{{Scope: model.ScopeSSH, Protocol: "udp", Port: 22}}, time.Hour, 1},
		{[]AllowedTarget{{Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 0}}, time.Hour, 1},
		{[]AllowedTarget{{Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22}, {Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22}}, time.Hour, 1},
		{[]AllowedTarget{{Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22}}, 31 * 24 * time.Hour, 1},
		{[]AllowedTarget{{Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22}}, time.Hour, 100_001},
	}
	for index, input := range cases {
		if _, err := NewPolicy(input.targets, input.maxTTL, input.maxEntries); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestNormalizeEntriesEnforcesLimitAndSorts(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	policy, err := NewPolicy([]AllowedTarget{{Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22}}, time.Hour, 2)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := policy.NormalizeEntries(now, []enforcerprotocol.Entry{
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.9", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.2", ExpiresAt: now.Add(time.Minute)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].IP.String() != "203.0.113.2" || entries[1].IP.String() != "203.0.113.9" {
		t.Fatalf("entries are not sorted: %+v", entries)
	}
	_, err = policy.NormalizeEntries(now, append([]enforcerprotocol.Entry{
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.1", ExpiresAt: now.Add(time.Minute)},
	}, []enforcerprotocol.Entry{
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.2", ExpiresAt: now.Add(time.Minute)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.3", ExpiresAt: now.Add(time.Minute)},
	}...))
	if !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("limit error = %v", err)
	}
}

func TestReconcilePassesOnlyCanonicalSortedEntries(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	backend := &recordingBackend{report: ReconcileReport{Created: 2}}
	service := NewService(backend, DefaultPolicy(), &clock.Fake{Current: now})
	report, err := service.Reconcile(context.Background(), "req.reconcile", []enforcerprotocol.Entry{
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "203.0.113.9", ExpiresAt: now.Add(time.Hour)},
		{Scope: "ssh", Protocol: "tcp", Port: 22, IP: "::ffff:203.0.113.2", ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Created != 2 || len(backend.reconciled) != 2 {
		t.Fatalf("report=%+v entries=%+v", report, backend.reconciled)
	}
	if backend.reconciled[0].IP.String() != "203.0.113.2" || backend.reconciled[1].IP.String() != "203.0.113.9" {
		t.Fatalf("backend entries are not canonical and sorted: %+v", backend.reconciled)
	}
}

func TestServiceSerializesBackendOperations(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	backend := &recordingBackend{delay: 20 * time.Millisecond}
	service := NewService(backend, DefaultPolicy(), &clock.Fake{Current: now})
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			ip := "203.0.113." + string(rune('1'+index))
			if err := service.Add(context.Background(), "req."+string(rune('a'+index)), enforcerprotocol.Entry{
				Scope: "ssh", Protocol: "tcp", Port: 22,
				IP: ip, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Errorf("add %d: %v", index, err)
			}
		}(index)
	}
	wait.Wait()
	if got := atomic.LoadInt32(&backend.maxInFlight); got != 1 {
		t.Fatalf("maximum concurrent backend calls = %d", got)
	}
}

type recordingBackend struct {
	addCalls       int
	reconcileCalls int
	delay          time.Duration
	inFlight       int32
	maxInFlight    int32
	reconciled     []Entry
	report         ReconcileReport
}

func (b *recordingBackend) enter() func() {
	current := atomic.AddInt32(&b.inFlight, 1)
	for {
		maximum := atomic.LoadInt32(&b.maxInFlight)
		if current <= maximum || atomic.CompareAndSwapInt32(&b.maxInFlight, maximum, current) {
			break
		}
	}
	if b.delay > 0 {
		time.Sleep(b.delay)
	}
	return func() { atomic.AddInt32(&b.inFlight, -1) }
}

func (b *recordingBackend) Ensure(context.Context) error { defer b.enter()(); return nil }
func (b *recordingBackend) Add(_ context.Context, _ Entry) error {
	defer b.enter()()
	b.addCalls++
	return nil
}
func (b *recordingBackend) Remove(context.Context, Key) error { defer b.enter()(); return nil }
func (b *recordingBackend) List(context.Context) ([]Entry, error) {
	defer b.enter()()
	return nil, nil
}
func (b *recordingBackend) Reconcile(_ context.Context, entries []Entry) (ReconcileReport, error) {
	defer b.enter()()
	b.reconcileCalls++
	b.reconciled = append([]Entry(nil), entries...)
	return b.report, nil
}
