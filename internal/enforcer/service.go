package enforcer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s-gor/sg-infosec/internal/clock"
	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
)

const (
	ProtocolTCP = enforcerprotocol.ProtocolTCP
	FamilyIPv4  = Family("ipv4")
	FamilyIPv6  = Family("ipv6")

	defaultMaxTTL      = 7 * 24 * time.Hour
	defaultMaxEntries  = 10_000
	absoluteMaxTTL     = 30 * 24 * time.Hour
	absoluteMaxEntries = 100_000
)

var (
	ErrInvalidPolicy     = errors.New("invalid enforcer policy")
	ErrUnsupportedTarget = errors.New("unsupported enforcer target")
	ErrInvalidEntry      = errors.New("invalid enforcer entry")
	ErrInvalidRequestID  = errors.New("invalid request ID")
	ErrDuplicateEntry    = errors.New("duplicate enforcer entry")
)

type Family string

type AllowedTarget struct {
	Scope    model.Scope
	Protocol enforcerprotocol.Protocol
	Port     uint16
}

type Key struct {
	Scope    model.Scope
	Protocol enforcerprotocol.Protocol
	Port     uint16
	IP       netip.Addr
}

func (k Key) Family() Family {
	if k.IP.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

func (k Key) StableID() string {
	return fmt.Sprintf("%s/%s/%d/%s", k.Scope, k.Protocol, k.Port, k.IP)
}

type Entry struct {
	Key
	ExpiresAt time.Time
}

type ReconcileReport struct {
	Created   int
	Updated   int
	Removed   int
	Unchanged int
}

type Backend interface {
	Ensure(context.Context) error
	Add(context.Context, Entry) error
	Remove(context.Context, Key) error
	List(context.Context) ([]Entry, error)
	Reconcile(context.Context, []Entry) (ReconcileReport, error)
}

type Policy struct {
	allowed    map[string]struct{}
	maxTTL     time.Duration
	maxEntries int
}

func DefaultPolicy() Policy {
	policy, err := NewPolicy([]AllowedTarget{{
		Scope: model.ScopeSSH, Protocol: ProtocolTCP, Port: 22,
	}}, defaultMaxTTL, defaultMaxEntries)
	if err != nil {
		panic(err)
	}
	return policy
}

func NewPolicy(targets []AllowedTarget, maxTTL time.Duration, maxEntries int) (Policy, error) {
	if len(targets) == 0 || maxTTL <= 0 || maxTTL > absoluteMaxTTL || maxEntries <= 0 || maxEntries > absoluteMaxEntries {
		return Policy{}, ErrInvalidPolicy
	}
	policy := Policy{
		allowed: make(map[string]struct{}, len(targets)),
		maxTTL:  maxTTL, maxEntries: maxEntries,
	}
	for _, target := range targets {
		if !isEnforcerScope(target.Scope) || target.Protocol != ProtocolTCP || target.Port == 0 ||
			(target.Scope == model.ScopePanelPort && isReservedVPNPort(target.Port)) {
			return Policy{}, ErrInvalidPolicy
		}
		key := targetID(target.Scope, target.Protocol, target.Port)
		if _, exists := policy.allowed[key]; exists {
			return Policy{}, ErrInvalidPolicy
		}
		policy.allowed[key] = struct{}{}
	}
	return policy, nil
}

func (p Policy) NormalizeKey(input enforcerprotocol.Key) (Key, error) {
	scope, err := model.ParseScope(strings.TrimSpace(input.Scope))
	if err != nil || !isEnforcerScope(scope) {
		return Key{}, ErrUnsupportedTarget
	}
	protocol := enforcerprotocol.Protocol(strings.TrimSpace(string(input.Protocol)))
	if protocol != ProtocolTCP || input.Port == 0 {
		return Key{}, ErrUnsupportedTarget
	}
	if _, ok := p.allowed[targetID(scope, protocol, input.Port)]; !ok {
		return Key{}, ErrUnsupportedTarget
	}
	address, err := netip.ParseAddr(strings.TrimSpace(input.IP))
	if err != nil || address.Zone() != "" {
		return Key{}, ErrInvalidEntry
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return Key{}, ErrInvalidEntry
	}
	return Key{Scope: scope, Protocol: protocol, Port: input.Port, IP: address}, nil
}

func (p Policy) NormalizeEntry(now time.Time, input enforcerprotocol.Entry) (Entry, error) {
	key, err := p.NormalizeKey(enforcerprotocol.Key{
		Scope: input.Scope, Protocol: input.Protocol, Port: input.Port, IP: input.IP,
	})
	if err != nil {
		return Entry{}, err
	}
	now = now.UTC()
	expiresAt := input.ExpiresAt.UTC()
	if expiresAt.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) > p.maxTTL {
		return Entry{}, ErrInvalidEntry
	}
	return Entry{Key: key, ExpiresAt: expiresAt}, nil
}

func (p Policy) NormalizeEntries(now time.Time, inputs []enforcerprotocol.Entry) ([]Entry, error) {
	if len(inputs) > p.maxEntries {
		return nil, ErrInvalidEntry
	}
	entries := make([]Entry, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		entry, err := p.NormalizeEntry(now, input)
		if err != nil {
			return nil, err
		}
		id := entry.StableID()
		if _, exists := seen[id]; exists {
			return nil, ErrDuplicateEntry
		}
		seen[id] = struct{}{}
		entries = append(entries, entry)
	}
	sortEntries(entries)
	return entries, nil
}

func isEnforcerScope(scope model.Scope) bool {
	return scope == model.ScopeSSH || scope == model.ScopePanelPort
}

func isReservedVPNPort(port uint16) bool {
	return port == 585 || port == 586 || port == 587
}

func targetID(scope model.Scope, protocol enforcerprotocol.Protocol, port uint16) string {
	return fmt.Sprintf("%s/%s/%d", scope, protocol, port)
}

func validateRequestID(value string) error {
	if len(value) == 0 || len(value) > 128 {
		return ErrInvalidRequestID
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character) {
			continue
		}
		return ErrInvalidRequestID
	}
	return nil
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].StableID() < entries[right].StableID()
	})
}

type Service struct {
	backend Backend
	policy  Policy
	clock   clock.Clock
	mu      sync.Mutex
}

func NewService(backend Backend, policy Policy, sourceClock clock.Clock) *Service {
	return &Service{backend: backend, policy: policy, clock: sourceClock}
}

func (s *Service) validate() error {
	if s == nil || s.backend == nil || s.clock == nil || len(s.policy.allowed) == 0 {
		return fmt.Errorf("enforcer service is not initialized")
	}
	return nil
}

func (s *Service) Ensure(ctx context.Context, requestID string) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := validateRequestID(requestID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.Ensure(ctx)
}

func (s *Service) Add(ctx context.Context, requestID string, input enforcerprotocol.Entry) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := validateRequestID(requestID); err != nil {
		return err
	}
	entry, err := s.policy.NormalizeEntry(s.clock.Now(), input)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.Add(ctx, entry)
}

func (s *Service) Remove(ctx context.Context, requestID string, input enforcerprotocol.Key) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := validateRequestID(requestID); err != nil {
		return err
	}
	key, err := s.policy.NormalizeKey(input)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.Remove(ctx, key)
}

func (s *Service) List(ctx context.Context) ([]Entry, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.backend.List(ctx)
	if err != nil {
		return nil, err
	}
	result := append([]Entry(nil), entries...)
	sortEntries(result)
	return result, nil
}

func (s *Service) Reconcile(ctx context.Context, requestID string, inputs []enforcerprotocol.Entry) (ReconcileReport, error) {
	if err := s.validate(); err != nil {
		return ReconcileReport{}, err
	}
	if err := validateRequestID(requestID); err != nil {
		return ReconcileReport{}, err
	}
	entries, err := s.policy.NormalizeEntries(s.clock.Now(), inputs)
	if err != nil {
		return ReconcileReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend.Reconcile(ctx, entries)
}
