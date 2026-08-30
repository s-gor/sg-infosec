//go:build linux

package nftentries

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/s-gor/sg-infosec/internal/enforcer"
	"github.com/s-gor/sg-infosec/internal/model"
)

const timeoutTolerance = time.Second

var (
	ErrInvalidElement = errors.New("invalid nftables set element")
	ErrStateConflict  = errors.New("nftables set state conflict")
)

type ElementKey struct {
	SetName string
	Key     []byte
}

func (k ElementKey) StableID() string {
	return k.SetName + "/" + hex.EncodeToString(k.Key)
}

type Element struct {
	SetName string
	Key     []byte
	Timeout time.Duration
}

func (e Element) StableID() string {
	return ElementKey{SetName: e.SetName, Key: e.Key}.StableID()
}

func (e Element) ElementKey() ElementKey {
	return ElementKey{SetName: e.SetName, Key: append([]byte(nil), e.Key...)}
}

type Plan struct {
	Add       []Element
	Update    []Element
	Remove    []Element
	Unchanged int
}

func EncodeKey(key enforcer.Key) (ElementKey, error) {
	if key.Protocol != enforcer.ProtocolTCP || !key.IP.IsValid() || key.IP.IsUnspecified() ||
		key.IP.IsMulticast() || key.IP.IsLoopback() || key.IP.Zone() != "" {
		return ElementKey{}, ErrInvalidElement
	}
	address := key.IP.Unmap()
	var setName string
	var encoded []byte
	switch key.Scope {
	case model.ScopeSSH:
		if key.Port != 22 {
			return ElementKey{}, ErrInvalidElement
		}
		if address.Is4() {
			value := address.As4()
			setName, encoded = "ssh_v4", append([]byte(nil), value[:]...)
		} else {
			value := address.As16()
			setName, encoded = "ssh_v6", append([]byte(nil), value[:]...)
		}
	case model.ScopePanelPort:
		if key.Port == 0 || reservedVPNPort(key.Port) {
			return ElementKey{}, ErrInvalidElement
		}
		if address.Is4() {
			value := address.As4()
			setName, encoded = "panel_v4", append([]byte(nil), value[:]...)
		} else {
			value := address.As16()
			setName, encoded = "panel_v6", append([]byte(nil), value[:]...)
		}
		port := make([]byte, 4)
		binary.BigEndian.PutUint16(port[:2], key.Port)
		encoded = append(encoded, port...)
	default:
		return ElementKey{}, ErrInvalidElement
	}
	result := ElementKey{SetName: setName, Key: encoded}
	if err := validateKey(result); err != nil {
		return ElementKey{}, err
	}
	return result, nil
}

func Encode(now time.Time, entry enforcer.Entry) (Element, error) {
	now = now.UTC()
	if !entry.ExpiresAt.After(now) {
		return Element{}, ErrInvalidElement
	}
	key, err := EncodeKey(entry.Key)
	if err != nil {
		return Element{}, err
	}
	return Element{SetName: key.SetName, Key: key.Key, Timeout: ceilMillisecond(entry.ExpiresAt.UTC().Sub(now))}, nil
}

func Decode(now time.Time, element Element) (enforcer.Entry, error) {
	if err := validateElement(element); err != nil {
		return enforcer.Entry{}, err
	}
	now = now.UTC()
	key, err := decodeKey(element.ElementKey())
	if err != nil {
		return enforcer.Entry{}, err
	}
	return enforcer.Entry{Key: key, ExpiresAt: now.Add(element.Timeout).UTC()}, nil
}

func decodeKey(element ElementKey) (enforcer.Key, error) {
	if err := validateKey(element); err != nil {
		return enforcer.Key{}, err
	}
	var scope model.Scope
	var port uint16
	addressLength := len(element.Key)
	switch element.SetName {
	case "ssh_v4", "ssh_v6":
		scope, port = model.ScopeSSH, 22
	case "panel_v4":
		scope, addressLength = model.ScopePanelPort, 4
		port = binary.BigEndian.Uint16(element.Key[addressLength : addressLength+2])
	case "panel_v6":
		scope, addressLength = model.ScopePanelPort, 16
		port = binary.BigEndian.Uint16(element.Key[addressLength : addressLength+2])
	default:
		return enforcer.Key{}, ErrInvalidElement
	}
	var address netip.Addr
	if addressLength == 4 {
		var raw [4]byte
		copy(raw[:], element.Key[:addressLength])
		address = netip.AddrFrom4(raw)
	} else {
		var raw [16]byte
		copy(raw[:], element.Key[:addressLength])
		address = netip.AddrFrom16(raw)
	}
	return enforcer.Key{Scope: scope, Protocol: enforcer.ProtocolTCP, Port: port, IP: address}, nil
}

func PlanReconcile(current, desired []Element) (Plan, error) {
	currentMap, err := index(current, true)
	if err != nil {
		return Plan{}, err
	}
	desiredMap, err := index(desired, false)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{}
	for id, wanted := range desiredMap {
		existing, ok := currentMap[id]
		if !ok {
			plan.Add = append(plan.Add, cloneElement(wanted))
			continue
		}
		if durationDelta(existing.Timeout, wanted.Timeout) <= timeoutTolerance {
			plan.Unchanged++
		} else {
			plan.Update = append(plan.Update, cloneElement(wanted))
		}
	}
	for id, existing := range currentMap {
		if _, ok := desiredMap[id]; !ok {
			plan.Remove = append(plan.Remove, cloneElement(existing))
		}
	}
	sortElements(plan.Add)
	sortElements(plan.Update)
	sortElements(plan.Remove)
	return plan, nil
}

func index(elements []Element, kernelState bool) (map[string]Element, error) {
	result := make(map[string]Element, len(elements))
	for _, element := range elements {
		if err := validateElement(element); err != nil {
			if kernelState {
				return nil, fmt.Errorf("%w: %v", ErrStateConflict, err)
			}
			return nil, err
		}
		id := element.StableID()
		if _, exists := result[id]; exists {
			return nil, fmt.Errorf("%w: duplicate %s", ErrStateConflict, id)
		}
		result[id] = cloneElement(element)
	}
	return result, nil
}

func validateElement(element Element) error {
	if element.Timeout <= 0 {
		return ErrInvalidElement
	}
	return validateKey(element.ElementKey())
}

func validateKey(element ElementKey) error {
	lengths := map[string]int{"ssh_v4": 4, "ssh_v6": 16, "panel_v4": 8, "panel_v6": 20}
	length, ok := lengths[element.SetName]
	if !ok || len(element.Key) != length {
		return ErrInvalidElement
	}
	addressLength := length
	switch element.SetName {
	case "panel_v4":
		addressLength = 4
	case "panel_v6":
		addressLength = 16
	}
	if addressLength != length {
		port := binary.BigEndian.Uint16(element.Key[addressLength : addressLength+2])
		if port == 0 || reservedVPNPort(port) || element.Key[addressLength+2] != 0 || element.Key[addressLength+3] != 0 {
			return ErrInvalidElement
		}
	}
	var address netip.Addr
	if addressLength == 4 {
		var raw [4]byte
		copy(raw[:], element.Key[:addressLength])
		address = netip.AddrFrom4(raw)
	} else {
		var raw [16]byte
		copy(raw[:], element.Key[:addressLength])
		address = netip.AddrFrom16(raw)
	}
	if address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return ErrInvalidElement
	}
	return nil
}

func cloneElement(element Element) Element {
	element.Key = append([]byte(nil), element.Key...)
	return element
}

func sortElements(elements []Element) {
	sort.Slice(elements, func(left, right int) bool { return elements[left].StableID() < elements[right].StableID() })
}

func ceilMillisecond(value time.Duration) time.Duration {
	if value%time.Millisecond == 0 {
		return value
	}
	return (value/time.Millisecond + 1) * time.Millisecond
}

func durationDelta(left, right time.Duration) time.Duration {
	if left > right {
		return left - right
	}
	return right - left
}

func reservedVPNPort(port uint16) bool {
	return port == 585 || port == 586 || port == 587
}
