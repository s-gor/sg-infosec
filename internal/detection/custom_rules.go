package detection

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

const (
	maxCustomRules   = 256
	maxPatternLength = 1024
	maxRuleFileBytes = 1024 * 1024
)

type customRuleFile struct {
	Rules []customRuleConfig `json:"rules"`
}

type customRuleConfig struct {
	ID                string `json:"id"`
	UnitPattern       string `json:"unit_pattern"`
	IdentifierPattern string `json:"identifier_pattern"`
	MessagePattern    string `json:"message_pattern"`
	Category          string `json:"category"`
	Service           string `json:"service"`
}

type compiledRule struct {
	id         string
	unit       *regexp.Regexp
	identifier *regexp.Regexp
	message    *regexp.Regexp
	ipIndex    int
	subjectIdx int
	category   Category
	service    Service
}

type RuleSet struct {
	rules []compiledRule
}

func LoadRuleSet(path string) (*RuleSet, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &RuleSet{}, nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &RuleSet{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat custom detection rules: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("custom detection rules must be a regular file")
	}
	if info.Size() > maxRuleFileBytes {
		return nil, fmt.Errorf("custom detection rules exceed %d bytes", maxRuleFileBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custom detection rules: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var file customRuleFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode custom detection rules: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode custom detection rules: trailing JSON value")
		}
		return nil, fmt.Errorf("decode custom detection rules: %w", err)
	}
	if len(file.Rules) > maxCustomRules {
		return nil, fmt.Errorf("custom detection rules exceed %d", maxCustomRules)
	}
	seen := make(map[string]struct{}, len(file.Rules))
	compiled := make([]compiledRule, 0, len(file.Rules))
	for index, config := range file.Rules {
		rule, err := compileRule(config)
		if err != nil {
			return nil, fmt.Errorf("custom detection rule %d: %w", index+1, err)
		}
		if _, exists := seen[rule.id]; exists {
			return nil, fmt.Errorf("duplicate custom detection rule ID %q", rule.id)
		}
		seen[rule.id] = struct{}{}
		compiled = append(compiled, rule)
	}
	return &RuleSet{rules: compiled}, nil
}

func compileRule(config customRuleConfig) (compiledRule, error) {
	id := strings.TrimSpace(config.ID)
	if id == "" || len(id) > 128 {
		return compiledRule{}, fmt.Errorf("id must contain 1 to 128 bytes")
	}
	for _, character := range id {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character)) {
			return compiledRule{}, fmt.Errorf("id %q contains unsupported characters", id)
		}
	}
	if strings.TrimSpace(config.MessagePattern) == "" {
		return compiledRule{}, fmt.Errorf("message_pattern is required")
	}
	if len(config.MessagePattern) > maxPatternLength ||
		len(config.UnitPattern) > maxPatternLength ||
		len(config.IdentifierPattern) > maxPatternLength {
		return compiledRule{}, fmt.Errorf("regular expression exceeds %d bytes", maxPatternLength)
	}
	message, err := regexp.Compile(config.MessagePattern)
	if err != nil {
		return compiledRule{}, fmt.Errorf("compile message_pattern: %w", err)
	}
	ipIndex := message.SubexpIndex("ip")
	if ipIndex < 1 {
		return compiledRule{}, fmt.Errorf("message_pattern must contain named capture ip")
	}
	subjectIndex := message.SubexpIndex("subject")
	unit, err := optionalRegexp(config.UnitPattern)
	if err != nil {
		return compiledRule{}, fmt.Errorf("compile unit_pattern: %w", err)
	}
	identifier, err := optionalRegexp(config.IdentifierPattern)
	if err != nil {
		return compiledRule{}, fmt.Errorf("compile identifier_pattern: %w", err)
	}
	category, err := parseCustomCategory(config.Category)
	if err != nil {
		return compiledRule{}, err
	}
	service, err := parseCustomService(config.Service)
	if err != nil {
		return compiledRule{}, err
	}
	return compiledRule{
		id:         id,
		unit:       unit,
		identifier: identifier,
		message:    message,
		ipIndex:    ipIndex,
		subjectIdx: subjectIndex,
		category:   category,
		service:    service,
	}, nil
}

func optionalRegexp(value string) (*regexp.Regexp, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	return regexp.Compile(value)
}

func parseCustomCategory(value string) (Category, error) {
	switch Category(strings.TrimSpace(value)) {
	case CategorySSHAuthFailed,
		CategorySSHInvalidUser,
		CategoryHTTPAdminProbe,
		CategoryGatewayAuthFailed,
		CategoryGatewayAPIAuthFailed:
		return Category(strings.TrimSpace(value)), nil
	default:
		return "", fmt.Errorf("unsupported category %q", value)
	}
}

func parseCustomService(value string) (Service, error) {
	switch Service(strings.TrimSpace(value)) {
	case ServiceSSH, ServiceHTTP, ServiceGateway:
		return Service(strings.TrimSpace(value)), nil
	default:
		return "", fmt.Errorf("unsupported service %q", value)
	}
}

func (set *RuleSet) Count() int {
	if set == nil {
		return 0
	}
	return len(set.rules)
}

func (set *RuleSet) Parse(record JournalRecord) []Finding {
	if set == nil || len(set.rules) == 0 {
		return nil
	}
	findings := make([]Finding, 0, 2)
	for _, rule := range set.rules {
		if rule.unit != nil && !rule.unit.MatchString(record.Unit) {
			continue
		}
		if rule.identifier != nil && !rule.identifier.MatchString(record.Identifier) {
			continue
		}
		matches := rule.message.FindStringSubmatch(record.Message)
		if matches == nil || rule.ipIndex >= len(matches) {
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(matches[rule.ipIndex], "[](),;"))
		if err != nil {
			continue
		}
		subjectHash := ""
		if rule.subjectIdx > 0 && rule.subjectIdx < len(matches) {
			subjectHash = hashSubject(matches[rule.subjectIdx])
		}
		findings = append(findings, Finding{
			IP:          address.Unmap(),
			Category:    rule.category,
			Service:     rule.service,
			OccurredAt:  record.OccurredAt.UTC(),
			SubjectHash: subjectHash,
			Metadata: map[string]any{
				"rule_id": rule.id,
			},
		})
	}
	return findings
}

func mergeUniqueFindings(groups ...[]Finding) []Finding {
	type key struct {
		ip       netip.Addr
		category Category
		service  Service
		subject  string
	}
	seen := make(map[key]struct{})
	var result []Finding
	for _, findings := range groups {
		for _, finding := range findings {
			itemKey := key{
				ip:       finding.IP.Unmap(),
				category: finding.Category,
				service:  finding.Service,
				subject:  finding.SubjectHash,
			}
			if _, exists := seen[itemKey]; exists {
				continue
			}
			seen[itemKey] = struct{}{}
			result = append(result, finding)
		}
	}
	return result
}
