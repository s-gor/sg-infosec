package config

import (
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/model"
	"github.com/s-gor/sg-infosec/internal/yamlmini"
)

type Lookup interface {
	User(name string) (uint32, error)
	Group(name string) (uint32, error)
}

type Options struct{ Lookup Lookup }

type osLookup struct{}

func (osLookup) User(name string) (uint32, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(entry.Uid, 10, 32)
	return uint32(value), err
}

func (osLookup) Group(name string) (uint32, error) {
	entry, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(entry.Gid, 10, 32)
	return uint32(value), err
}

func Load(path string) (Config, error) {
	return LoadWithOptions(path, Options{Lookup: osLookup{}})
}

func LoadWithOptions(path string, options Options) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("configuration path is required")
	}
	if options.Lookup == nil {
		options.Lookup = osLookup{}
	}
	root, err := parseFile(path)
	if err != nil {
		return Config{}, err
	}
	fields, err := strictMap(root, "main configuration", []string{
		"database_path", "events_socket", "control_socket", "event_body_limit",
		"sources_dir", "policies_dir", "retention", "allowlist",
	})
	if err != nil {
		return Config{}, err
	}
	base := filepath.Dir(path)
	var cfg Config
	if cfg.DatabasePath, err = requiredPath(fields, "database_path", base); err != nil {
		return Config{}, err
	}
	if cfg.EventsSocket, err = requiredPath(fields, "events_socket", base); err != nil {
		return Config{}, err
	}
	if cfg.ControlSocket, err = requiredPath(fields, "control_socket", base); err != nil {
		return Config{}, err
	}
	if cfg.EventsSocket == cfg.ControlSocket {
		return Config{}, fmt.Errorf("events_socket and control_socket must be different")
	}
	if cfg.EventBodyLimit, err = requiredInt64(fields, "event_body_limit"); err != nil {
		return Config{}, err
	}
	if cfg.EventBodyLimit < 1024 || cfg.EventBodyLimit > 1<<20 {
		return Config{}, fmt.Errorf("event_body_limit must be between 1024 and 1048576")
	}
	if cfg.Retention, err = parseRetention(fields["retention"]); err != nil {
		return Config{}, err
	}
	if cfg.Allowlist, err = parseAllowlist(fields["allowlist"]); err != nil {
		return Config{}, err
	}
	sourcesDir, err := requiredPath(fields, "sources_dir", base)
	if err != nil {
		return Config{}, err
	}
	policiesDir, err := requiredPath(fields, "policies_dir", base)
	if err != nil {
		return Config{}, err
	}
	if cfg.Sources, err = loadSources(sourcesDir, options.Lookup); err != nil {
		return Config{}, err
	}
	if cfg.Policies, err = loadPolicies(policiesDir); err != nil {
		return Config{}, err
	}
	if err := validatePolicySources(cfg.Sources, cfg.Policies); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseFile(path string) (*yamlmini.Node, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	node, err := yamlmini.Parse(file)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return node, nil
}

func loadSources(dir string, lookup Lookup) ([]Source, error) {
	files, err := fragmentFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("sources: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("sources: no YAML fragments in %s", dir)
	}
	seen := make(map[string]struct{})
	uidOwners := make(map[uint32]string)
	result := make([]Source, 0, len(files))
	for _, path := range files {
		node, err := parseFile(path)
		if err != nil {
			return nil, err
		}
		fields, err := strictMap(node, "source", []string{"source_id", "user", "group", "allowed_events", "allowed_scopes", "permissions"})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		id, err := requiredScalar(fields, "source_id")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if !validIdentifier(id) {
			return nil, fmt.Errorf("source_id %q contains unsupported characters", id)
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("duplicate source_id %q", id)
		}
		seen[id] = struct{}{}
		userName, err := requiredScalar(fields, "user")
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", id, err)
		}
		uid, err := lookup.User(userName)
		if err != nil {
			return nil, fmt.Errorf("source %q user %q: %w", id, userName, err)
		}
		if owner, exists := uidOwners[uid]; exists {
			return nil, fmt.Errorf("sources %q and %q resolve to the same UID %d", owner, id, uid)
		}
		uidOwners[uid] = id
		source := Source{ID: id, User: userName, UID: uid}
		if groupNode, ok := fields["group"]; ok {
			groupName, err := scalar(groupNode, "group")
			if err != nil {
				return nil, fmt.Errorf("source %q: %w", id, err)
			}
			gid, err := lookup.Group(groupName)
			if err != nil {
				return nil, fmt.Errorf("source %q group %q: %w", id, groupName, err)
			}
			source.Group, source.GID = groupName, &gid
		}
		events, err := requiredSequence(fields, "allowed_events")
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", id, err)
		}
		source.AllowedEvents = make(map[model.EventType]struct{}, len(events))
		for _, value := range events {
			eventType, err := model.ParseEventType(value)
			if err != nil {
				return nil, fmt.Errorf("source %q: %w", id, err)
			}
			source.AllowedEvents[eventType] = struct{}{}
		}
		scopes, err := requiredSequence(fields, "allowed_scopes")
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", id, err)
		}
		source.AllowedScopes = make(map[model.Scope]struct{}, len(scopes))
		for _, value := range scopes {
			scope, err := model.ParseScope(value)
			if err != nil {
				return nil, fmt.Errorf("source %q: %w", id, err)
			}
			source.AllowedScopes[scope] = struct{}{}
		}
		permissions, err := optionalSequence(fields, "permissions")
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", id, err)
		}
		source.Permissions = make(map[Permission]struct{}, len(permissions))
		for _, value := range permissions {
			permission := Permission(value)
			switch permission {
			case PermissionCheckDecisions, PermissionReadAdmin, PermissionWriteAdmin:
				source.Permissions[permission] = struct{}{}
			default:
				return nil, fmt.Errorf("source %q: unsupported permission %q", id, value)
			}
		}
		result = append(result, source)
	}
	return result, nil
}

func loadPolicies(dir string) ([]model.Policy, error) {
	files, err := fragmentFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	seen := make(map[string]struct{})
	result := make([]model.Policy, 0, len(files))
	for _, path := range files {
		node, err := parseFile(path)
		if err != nil {
			return nil, err
		}
		fields, err := strictMap(node, "policy", []string{
			"policy_id", "enabled", "event_type", "scope", "source_id", "threshold", "window",
			"base_duration", "escalation_factor", "max_duration", "reset_interval", "backend",
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var policy model.Policy
		if policy.ID, err = requiredScalar(fields, "policy_id"); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if !validIdentifier(policy.ID) {
			return nil, fmt.Errorf("policy_id %q contains unsupported characters", policy.ID)
		}
		if _, exists := seen[policy.ID]; exists {
			return nil, fmt.Errorf("duplicate policy_id %q", policy.ID)
		}
		seen[policy.ID] = struct{}{}
		if policy.Enabled, err = requiredBool(fields, "enabled"); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		eventValue, err := requiredScalar(fields, "event_type")
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.EventType, err = model.ParseEventType(eventValue); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		scopeValue, err := requiredScalar(fields, "scope")
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.Scope, err = model.ParseScope(scopeValue); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.SourceID, err = optionalScalar(fields, "source_id"); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.SourceID != "" && !validIdentifier(policy.SourceID) {
			return nil, fmt.Errorf("policy %q source_id %q contains unsupported characters", policy.ID, policy.SourceID)
		}
		threshold, err := requiredUint32(fields, "threshold")
		if err != nil || threshold == 0 {
			return nil, fmt.Errorf("policy %q threshold must be greater than zero", policy.ID)
		}
		policy.Threshold = threshold
		if policy.Window, err = requiredDuration(fields, "window"); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.BaseDuration, err = requiredDuration(fields, "base_duration"); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.EscalationFactor, err = requiredUint32(fields, "escalation_factor"); err != nil || policy.EscalationFactor == 0 {
			return nil, fmt.Errorf("policy %q escalation_factor must be greater than zero", policy.ID)
		}
		if policy.MaxDuration, err = requiredDuration(fields, "max_duration"); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.ResetInterval, err = requiredDuration(fields, "reset_interval"); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		backendValue, err := requiredScalar(fields, "backend")
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if policy.Backend, err = model.ParseBackend(backendValue); err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.ID, err)
		}
		if err := validatePolicyBackend(policy); err != nil {
			return nil, err
		}
		if policy.Window <= 0 || policy.BaseDuration <= 0 || policy.MaxDuration <= 0 || policy.ResetInterval <= 0 {
			return nil, fmt.Errorf("policy %q durations must be greater than zero", policy.ID)
		}
		if policy.BaseDuration > policy.MaxDuration {
			return nil, fmt.Errorf("policy %q base_duration exceeds max_duration", policy.ID)
		}
		result = append(result, policy)
	}
	return result, nil
}

func validatePolicySources(sources []Source, policies []model.Policy) error {
	byID := make(map[string]Source, len(sources))
	for _, source := range sources {
		byID[source.ID] = source
	}
	for _, policy := range policies {
		if policy.SourceID == "" {
			continue
		}
		source, ok := byID[policy.SourceID]
		if !ok {
			return fmt.Errorf("policy %q references unknown source_id %q", policy.ID, policy.SourceID)
		}
		if _, ok := source.AllowedEvents[policy.EventType]; !ok {
			return fmt.Errorf("policy %q source %q does not allow event type %q", policy.ID, source.ID, policy.EventType)
		}
		if _, ok := source.AllowedScopes[policy.Scope]; !ok {
			return fmt.Errorf("policy %q source %q does not allow scope %q", policy.ID, source.ID, policy.Scope)
		}
	}
	return nil
}

func parseRetention(node *yamlmini.Node) (EventRetention, error) {
	fields, err := strictMap(node, "retention", []string{"events", "audit"})
	if err != nil {
		return EventRetention{}, err
	}
	events, err := requiredDuration(fields, "events")
	if err != nil {
		return EventRetention{}, err
	}
	audit, err := requiredDuration(fields, "audit")
	if err != nil {
		return EventRetention{}, err
	}
	if events <= 0 || audit <= 0 {
		return EventRetention{}, fmt.Errorf("retention durations must be greater than zero")
	}
	return EventRetention{Events: events, Audit: audit}, nil
}

func parseAllowlist(node *yamlmini.Node) ([]model.AllowlistEntry, error) {
	if node == nil {
		return nil, nil
	}
	values, err := sequence(node, "allowlist")
	if err != nil {
		return nil, err
	}
	result := make([]model.AllowlistEntry, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		prefix, err := parsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("allowlist %q: %w", value, err)
		}
		key := prefix.String()
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("allowlist contains duplicate prefix %q", key)
		}
		seen[key] = struct{}{}
		result = append(result, model.AllowlistEntry{ID: "config:" + key, Prefix: prefix, Description: "configured allowlist", CreatedBy: "configuration"})
	}
	return result, nil
}

func parsePrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		addr := prefix.Addr().Unmap()
		if addr.Is4() && prefix.Bits() > 32 {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 prefix length")
		}
		if addr.Is4() {
			prefix = netip.PrefixFrom(addr, prefix.Bits()).Masked()
		} else {
			prefix = netip.PrefixFrom(addr, prefix.Bits()).Masked()
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("zones are not supported")
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func fragmentFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func strictMap(node *yamlmini.Node, context string, allowed []string) (map[string]*yamlmini.Node, error) {
	if node == nil || node.Kind != yamlmini.Mapping {
		return nil, fmt.Errorf("%s must be a mapping", context)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	result := make(map[string]*yamlmini.Node, len(node.Pairs))
	for _, pair := range node.Pairs {
		if _, ok := allowedSet[pair.Key]; !ok {
			return nil, fmt.Errorf("%s: unknown field %q", context, pair.Key)
		}
		if _, duplicate := result[pair.Key]; duplicate {
			return nil, fmt.Errorf("%s: duplicate field %q", context, pair.Key)
		}
		result[pair.Key] = pair.Value
	}
	return result, nil
}

func requiredScalar(fields map[string]*yamlmini.Node, key string) (string, error) {
	node, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("missing required field %q", key)
	}
	return scalar(node, key)
}

func optionalScalar(fields map[string]*yamlmini.Node, key string) (string, error) {
	node, ok := fields[key]
	if !ok {
		return "", nil
	}
	return scalar(node, key)
}

func scalar(node *yamlmini.Node, key string) (string, error) {
	if node == nil || node.Kind != yamlmini.Scalar || strings.TrimSpace(node.Value) == "" {
		return "", fmt.Errorf("field %q must be a non-empty scalar", key)
	}
	return strings.TrimSpace(node.Value), nil
}

func requiredPath(fields map[string]*yamlmini.Node, key, base string) (string, error) {
	value, err := requiredScalar(fields, key)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("field %q contains NUL", key)
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	return filepath.Clean(filepath.Join(base, value)), nil
}

func requiredInt64(fields map[string]*yamlmini.Node, key string) (int64, error) {
	value, err := requiredScalar(fields, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("field %q must be an integer", key)
	}
	return parsed, nil
}

func requiredUint32(fields map[string]*yamlmini.Node, key string) (uint32, error) {
	value, err := requiredScalar(fields, key)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("field %q must be a non-negative integer", key)
	}
	return uint32(parsed), nil
}

func requiredBool(fields map[string]*yamlmini.Node, key string) (bool, error) {
	value, err := requiredScalar(fields, key)
	if err != nil {
		return false, err
	}
	if value != "true" && value != "false" {
		return false, fmt.Errorf("field %q must be true or false", key)
	}
	return value == "true", nil
}

func requiredDuration(fields map[string]*yamlmini.Node, key string) (time.Duration, error) {
	value, err := requiredScalar(fields, key)
	if err != nil {
		return 0, err
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("field %q must be a duration: %w", key, err)
	}
	return parsed, nil
}

func requiredSequence(fields map[string]*yamlmini.Node, key string) ([]string, error) {
	node, ok := fields[key]
	if !ok {
		return nil, fmt.Errorf("missing required field %q", key)
	}
	return sequence(node, key)
}

func optionalSequence(fields map[string]*yamlmini.Node, key string) ([]string, error) {
	node, ok := fields[key]
	if !ok {
		return nil, nil
	}
	return sequence(node, key)
}

func sequence(node *yamlmini.Node, key string) ([]string, error) {
	if node == nil || node.Kind != yamlmini.Sequence {
		return nil, fmt.Errorf("field %q must be a scalar sequence", key)
	}
	result := make([]string, 0, len(node.Values))
	seen := make(map[string]struct{}, len(node.Values))
	for _, item := range node.Values {
		value, err := scalar(item, key)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("field %q contains duplicate value %q", key, value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("field %q must not be empty", key)
	}
	return result, nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}
