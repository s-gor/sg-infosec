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

type Element struct {
	SetName string
	Key     []byte
	Timeout time.Duration
}

func (e Element) StableID() string {
	return e.SetName + "/" + hex.EncodeToString(e.Key)
}

type Plan struct {
	Add       []Element
	Update    []Element
	Remove    []Element
	Unchanged int
}

func Encode(now time.Time, entry enforcer.Entry) (Element, error) {
	now = now.UTC()
	if entry.Protocol != enforcer.ProtocolTCP || !entry.ExpiresAt.After(now) ||
		!entry.IP.IsValid() || entry.IP.IsUnspecified() || entry.IP.IsMulticast() || entry.IP.IsLoopback() || entry.IP.Zone() != "" {
		return Element{}, ErrInvalidElement
	}
	address := entry.IP.Unmap()
	var setName string
	var key []byte
	switch entry.Scope {
	case model.ScopeSSH:
		if entry.Port != 22 {
			return Element{}, ErrInvalidElement
		}
		if address.Is4() {
			value := address.As4()
			setName, key = "ssh_v4", append([]byte(nil), value[:]...)
		} else {
			value := address.As16()
			setName, key = "ssh_v6", append([]byte(nil), value[:]...)
		}
	case model.ScopePanelPort:
		if entry.Port == 0 || reservedVPNPort(entry.Port) {
			return Element{}, ErrInvalidElement
		}
		if address.Is4() {
			value := address.As4()
			setName, key = "panel_v4", append([]byte(nil), value[:]...)
		} else {
			value := address.As16()
			setName, key = "panel_v6", append([]byte(nil), value[:]...)
		}
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, entry.Port)
		key = append(key, port...)
	default:
		return Element{}, ErrInvalidElement
	}
	return Element{SetName: setName, Key: key, Timeout: ceilMillisecond(entry.ExpiresAt.UTC().Sub(now))}, nil
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
	lengths := map[string]int{"ssh_v4": 4, "ssh_v6": 16, "panel_v4": 6, "panel_v6": 18}
	length, ok := lengths[element.SetName]
	if !ok || len(element.Key) != length || element.Timeout <= 0 {
		return ErrInvalidElement
	}
	addressLength := length
	if element.SetName == "panel_v4" || element.SetName == "panel_v6" {
		addressLength -= 2
		if reservedVPNPort(binary.BigEndian.Uint16(element.Key[addressLength:])) {
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
