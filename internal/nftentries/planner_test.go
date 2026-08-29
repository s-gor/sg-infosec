//go:build linux

package nftentries

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/internal/model"
)

func TestEncodeMapsEntriesToFixedTimeoutSets(t *testing.T) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	cases := []struct {
		entry   enforcer.Entry
		setName string
		keyHex  string
	}{
		{entry: entry(model.ScopeSSH, "203.0.113.7", 22, now.Add(30*time.Minute)), setName: "ssh_v4", keyHex: "cb007107"},
		{entry: entry(model.ScopeSSH, "2001:db8::7", 22, now.Add(30*time.Minute)), setName: "ssh_v6", keyHex: "20010db8000000000000000000000007"},
		{entry: entry(model.ScopePanelPort, "203.0.113.7", 63443, now.Add(time.Hour)), setName: "panel_v4", keyHex: "cb007107f7d3"},
		{entry: entry(model.ScopePanelPort, "2001:db8::7", 63443, now.Add(time.Hour)), setName: "panel_v6", keyHex: "20010db8000000000000000000000007f7d3"},
	}
	for _, item := range cases {
		element, err := Encode(now, item.entry)
		if err != nil {
			t.Fatal(err)
		}
		if element.SetName != item.setName || hex.EncodeToString(element.Key) != item.keyHex {
			t.Fatalf("element=%+v key=%x", element, element.Key)
		}
		if element.Timeout != item.entry.ExpiresAt.Sub(now) {
			t.Fatalf("timeout=%s", element.Timeout)
		}
	}
}

func TestEncodeRejectsExpiredUnknownAndReservedTargets(t *testing.T) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	cases := []enforcer.Entry{
		entry(model.ScopeAdminLogin, "203.0.113.7", 443, now.Add(time.Hour)),
		entry(model.ScopeSSH, "203.0.113.7", 23, now.Add(time.Hour)),
		entry(model.ScopePanelPort, "203.0.113.7", 585, now.Add(time.Hour)),
		entry(model.ScopePanelPort, "203.0.113.7", 586, now.Add(time.Hour)),
		entry(model.ScopePanelPort, "203.0.113.7", 587, now.Add(time.Hour)),
		entry(model.ScopeSSH, "203.0.113.7", 22, now),
	}
	for index, input := range cases {
		if _, err := Encode(now, input); err == nil {
			t.Fatalf("case %d accepted: %+v", index, input)
		}
	}
}

func TestEncodeRoundsTimeoutUpToKernelMillisecond(t *testing.T) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	element, err := Encode(now, entry(model.ScopeSSH, "203.0.113.7", 22, now.Add(time.Millisecond+time.Nanosecond)))
	if err != nil {
		t.Fatal(err)
	}
	if element.Timeout != 2*time.Millisecond {
		t.Fatalf("timeout=%s", element.Timeout)
	}
}

func TestPlanReconcileToleratesClockDrift(t *testing.T) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	current := mustEncode(t, now, entry(model.ScopeSSH, "203.0.113.1", 22, now.Add(time.Hour)))
	desired := current
	desired.Timeout += 900 * time.Millisecond
	plan, err := PlanReconcile([]Element{current}, []Element{desired})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unchanged != 1 || len(plan.Update) != 0 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestPlanReconcileIsAtomicDeterministicAndClassifiesChanges(t *testing.T) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	keep := mustEncode(t, now, entry(model.ScopeSSH, "203.0.113.1", 22, now.Add(time.Hour)))
	updateCurrent := mustEncode(t, now, entry(model.ScopeSSH, "203.0.113.2", 22, now.Add(30*time.Minute)))
	updateDesired := mustEncode(t, now, entry(model.ScopeSSH, "203.0.113.2", 22, now.Add(2*time.Hour)))
	remove := mustEncode(t, now, entry(model.ScopeSSH, "203.0.113.3", 22, now.Add(time.Hour)))
	add := mustEncode(t, now, entry(model.ScopePanelPort, "2001:db8::9", 63443, now.Add(time.Hour)))

	plan, err := PlanReconcile([]Element{remove, updateCurrent, keep}, []Element{add, keep, updateDesired})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ids(plan.Add), []string{add.StableID()}) ||
		!reflect.DeepEqual(ids(plan.Update), []string{updateDesired.StableID()}) ||
		!reflect.DeepEqual(ids(plan.Remove), []string{remove.StableID()}) || plan.Unchanged != 1 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestPlanReconcileRejectsDuplicateOrUnknownKernelStateWithoutPartialPlan(t *testing.T) {
	now := time.Date(2026, 8, 29, 18, 0, 0, 0, time.UTC)
	valid := mustEncode(t, now, entry(model.ScopeSSH, "203.0.113.1", 22, now.Add(time.Hour)))
	unknown := valid
	unknown.SetName = "foreign"
	loopback := valid
	loopback.Key = []byte{127, 0, 0, 1}
	for index, current := range [][]Element{{valid, valid}, {unknown}, {loopback}} {
		plan, err := PlanReconcile(current, []Element{valid})
		if !errors.Is(err, ErrStateConflict) || len(plan.Add)+len(plan.Update)+len(plan.Remove)+plan.Unchanged != 0 {
			t.Fatalf("case %d plan=%+v err=%v", index, plan, err)
		}
	}
}

func entry(scope model.Scope, ip string, port uint16, expires time.Time) enforcer.Entry {
	return enforcer.Entry{Key: enforcer.Key{Scope: scope, Protocol: enforcer.ProtocolTCP, Port: port, IP: netip.MustParseAddr(ip)}, ExpiresAt: expires}
}

func mustEncode(t *testing.T, now time.Time, input enforcer.Entry) Element {
	t.Helper()
	element, err := Encode(now, input)
	if err != nil {
		t.Fatal(err)
	}
	return element
}

func ids(elements []Element) []string {
	result := make([]string, len(elements))
	for index, element := range elements {
		result[index] = element.StableID()
	}
	return result
}

func TestDecodeRestoresTypedEntry(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	input := Element{SetName: "panel_v6", Key: append(netip.MustParseAddr("2001:db8::7").AsSlice(), 0xf7, 0xd3), Timeout: time.Hour}
	entry, err := Decode(now, input)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Scope != model.ScopePanelPort || entry.Port != 63443 || entry.IP.String() != "2001:db8::7" || !entry.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("entry=%+v", entry)
	}
}

func TestEncodeKeyMatchesElementStableID(t *testing.T) {
	now := time.Date(2026, 8, 29, 19, 0, 0, 0, time.UTC)
	input := entry(model.ScopeSSH, "203.0.113.7", 22, now.Add(time.Hour))
	element, err := Encode(now, input)
	if err != nil {
		t.Fatal(err)
	}
	key, err := EncodeKey(input.Key)
	if err != nil {
		t.Fatal(err)
	}
	if key.StableID() != element.StableID() {
		t.Fatalf("key=%+v element=%+v", key, element)
	}
}
