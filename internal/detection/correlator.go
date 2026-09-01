package detection

import (
	"net/netip"
	"sort"
	"time"
)

type Correlator struct {
	config CorrelatorConfig
	states map[netip.Addr]*correlationState
}

type correlationState struct {
	lastSeen time.Time
	findings []Finding
	cooldown map[string]time.Time
}

func NewCorrelator(config CorrelatorConfig) *Correlator {
	if config.MaxStates <= 0 {
		config.MaxStates = 4096
	}
	if config.StateTTL <= 0 {
		config.StateTTL = 60 * time.Minute
	}
	if config.Cooldown <= 0 {
		config.Cooldown = 10 * time.Minute
	}
	if config.CrossWindow <= 0 {
		config.CrossWindow = 15 * time.Minute
	}
	if config.CrossThreshold <= 0 {
		config.CrossThreshold = 100
	}
	return &Correlator{config: config, states: make(map[netip.Addr]*correlationState)}
}

func (c *Correlator) Observe(finding Finding) []Signal {
	if c == nil || !finding.IP.IsValid() || finding.Category == "" || finding.Service == "" {
		return nil
	}
	now := finding.OccurredAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
		finding.OccurredAt = now
	}
	c.expire(now)
	address := finding.IP.Unmap()
	state := c.states[address]
	if state == nil {
		if len(c.states) >= c.config.MaxStates {
			c.evictOldest()
		}
		state = &correlationState{cooldown: make(map[string]time.Time)}
		c.states[address] = state
	}
	if now.After(state.lastSeen) {
		state.lastSeen = now
	}
	state.findings = append(state.findings, finding)
	state.prune(state.lastSeen.Add(-c.config.StateTTL))

	var signals []Signal
	if countCategories(state.findings, now.Add(-10*time.Minute), CategorySSHAuthFailed, CategorySSHInvalidUser) >= 5 {
		signals = c.emit(signals, state, "ssh-burst", address, "auth.failed", "ssh", "ssh-burst", 5, now)
	}
	if countCategories(state.findings, now.Add(-60*time.Minute), CategorySSHAuthFailed, CategorySSHInvalidUser) >= 12 {
		signals = c.emit(signals, state, "ssh-slow", address, "auth.failed", "ssh", "ssh-slow", 12, now)
	}
	if distinctSubjects(state.findings, now.Add(-15*time.Minute), CategorySSHInvalidUser) >= 6 {
		signals = c.emit(signals, state, "ssh-enumeration", address, "auth.failed", "ssh", "username-enumeration", 6, now)
	}
	if countCategories(state.findings, now.Add(-5*time.Minute), CategoryHTTPAdminProbe) >= 6 {
		signals = c.emit(signals, state, "http-scan", address, "api.auth_failed", "admin-api", "administrative-path-scan", 6, now)
	}
	if countCategories(state.findings, now.Add(-10*time.Minute), CategoryGatewayAuthFailed) >= 5 {
		signals = c.emit(signals, state, "gateway-auth", address, "auth.failed", "admin-login", "panel-authentication-failures", 5, now)
	}
	if countCategories(state.findings, now.Add(-10*time.Minute), CategoryGatewayAPIAuthFailed) >= 10 {
		signals = c.emit(signals, state, "gateway-api", address, "api.auth_failed", "admin-api", "api-authentication-failures", 10, now)
	}
	signals = append(signals, c.crossServiceSignals(state, address, now)...)
	return strongestSignalsByScope(signals)
}

func (c *Correlator) StateCount() int {
	if c == nil {
		return 0
	}
	return len(c.states)
}

func (c *Correlator) emit(signals []Signal, state *correlationState, key string, ip netip.Addr, eventType, scope, reason string, evidence int, now time.Time) []Signal {
	if until, ok := state.cooldown[key]; ok && now.Before(until) {
		return signals
	}
	state.cooldown[key] = now.Add(c.config.Cooldown)
	return append(signals, Signal{EventType: eventType, Scope: scope, IP: ip.Unmap(), Reason: reason, Evidence: evidence, OccurredAt: now})
}

func (c *Correlator) crossServiceSignals(state *correlationState, ip netip.Addr, now time.Time) []Signal {
	cutoff := now.Add(-c.config.CrossWindow)
	score := 0
	services := make(map[Service]struct{})
	hasSSH := false
	hasAdmin := false
	hasAPI := false
	for _, finding := range state.findings {
		if finding.OccurredAt.Before(cutoff) {
			continue
		}
		services[finding.Service] = struct{}{}
		switch finding.Category {
		case CategorySSHAuthFailed:
			score += 15
			hasSSH = true
		case CategorySSHInvalidUser:
			score += 20
			hasSSH = true
		case CategoryHTTPAdminProbe:
			score += 20
			hasAPI = true
		case CategoryGatewayAuthFailed:
			score += 25
			hasAdmin = true
		case CategoryGatewayAPIAuthFailed:
			score += 20
			hasAPI = true
		}
	}
	if score < c.config.CrossThreshold || len(services) < 2 {
		return nil
	}
	var signals []Signal
	if hasSSH {
		signals = c.emit(signals, state, "cross:ssh", ip, "auth.failed", "ssh", "cross-service", score, now)
	}
	if hasAdmin {
		signals = c.emit(signals, state, "cross:admin", ip, "auth.failed", "admin-login", "cross-service", score, now)
	}
	if hasAPI {
		signals = c.emit(signals, state, "cross:admin-api", ip, "api.auth_failed", "admin-api", "cross-service", score, now)
	}
	return signals
}

func strongestSignalsByScope(signals []Signal) []Signal {
	type signalKey struct {
		eventType string
		scope     string
	}
	indexes := make(map[signalKey]int, len(signals))
	result := make([]Signal, 0, len(signals))
	for _, signal := range signals {
		key := signalKey{eventType: signal.EventType, scope: signal.Scope}
		index, exists := indexes[key]
		if !exists {
			indexes[key] = len(result)
			result = append(result, signal)
			continue
		}
		if signal.Evidence > result[index].Evidence {
			result[index] = signal
		}
	}
	return result
}

func (c *Correlator) expire(now time.Time) {
	cutoff := now.Add(-c.config.StateTTL)
	for address, state := range c.states {
		if state.lastSeen.Before(cutoff) {
			delete(c.states, address)
		}
	}
}

func (c *Correlator) evictOldest() {
	if len(c.states) == 0 {
		return
	}
	type candidate struct {
		address netip.Addr
		seen    time.Time
	}
	items := make([]candidate, 0, len(c.states))
	for address, state := range c.states {
		items = append(items, candidate{address: address, seen: state.lastSeen})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].seen.Equal(items[j].seen) {
			return items[i].address.Less(items[j].address)
		}
		return items[i].seen.Before(items[j].seen)
	})
	delete(c.states, items[0].address)
}

func (s *correlationState) prune(cutoff time.Time) {
	kept := s.findings[:0]
	for _, finding := range s.findings {
		if !finding.OccurredAt.Before(cutoff) {
			kept = append(kept, finding)
		}
	}
	s.findings = kept
	if len(s.findings) > 256 {
		s.findings = append([]Finding(nil), s.findings[len(s.findings)-256:]...)
	}
}

func countCategories(findings []Finding, cutoff time.Time, categories ...Category) int {
	allowed := make(map[Category]struct{}, len(categories))
	for _, category := range categories {
		allowed[category] = struct{}{}
	}
	count := 0
	for _, finding := range findings {
		if finding.OccurredAt.Before(cutoff) {
			continue
		}
		if _, ok := allowed[finding.Category]; ok {
			count++
		}
	}
	return count
}

func distinctSubjects(findings []Finding, cutoff time.Time, category Category) int {
	subjects := make(map[string]struct{})
	for _, finding := range findings {
		if finding.OccurredAt.Before(cutoff) || finding.Category != category || finding.SubjectHash == "" {
			continue
		}
		subjects[finding.SubjectHash] = struct{}{}
	}
	return len(subjects)
}
