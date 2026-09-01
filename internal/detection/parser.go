package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

var (
	sshFailedPattern  = regexp.MustCompile(`(?i)Failed (?:password|publickey) for (?:invalid user )?([^ ]+) from ([^ ]+)`)
	sshInvalidPattern = regexp.MustCompile(`(?i)Invalid user ([^ ]+) from ([^ ]+)`)
	sshRHostPattern   = regexp.MustCompile(`(?:^|[ ;])rhost=([^ ]+)`)
	sshUserPattern    = regexp.MustCompile(`(?:^|[ ;])user=([^ ]+)`)
	httpAccessPattern = regexp.MustCompile(`^(\S+)\s+.*?"([A-Z]+)\s+(\S+)\s+HTTP/[0-9.]+"`)
)

var suspiciousPaths = []string{
	"/.env",
	"/.git/",
	"/.git/config",
	"/wp-admin",
	"/wp-login.php",
	"/phpmyadmin",
	"/server-status",
	"/actuator/env",
	"/actuator/configprops",
	"/cgi-bin/",
	"/vendor/phpunit/",
	"../",
	"%2e%2e",
	"%252e%252e",
}

func Parse(record JournalRecord) []Finding {
	switch {
	case isSSHRecord(record):
		return parseSSH(record)
	case isHTTPRecord(record):
		return parseHTTP(record)
	case isGatewayRecord(record):
		return parseGateway(record)
	default:
		return nil
	}
}

func isSSHRecord(record JournalRecord) bool {
	unit := strings.ToLower(strings.TrimSpace(record.Unit))
	identifier := strings.ToLower(strings.TrimSpace(record.Identifier))
	return unit == "ssh.service" || unit == "sshd.service" || identifier == "sshd"
}

func isHTTPRecord(record JournalRecord) bool {
	unit := strings.ToLower(strings.TrimSpace(record.Unit))
	identifier := strings.ToLower(strings.TrimSpace(record.Identifier))
	return unit == "nginx.service" || identifier == "nginx"
}

func isGatewayRecord(record JournalRecord) bool {
	unit := strings.ToLower(strings.TrimSpace(record.Unit))
	identifier := strings.ToLower(strings.TrimSpace(record.Identifier))
	return unit == "sg-gateway.service" || identifier == "sg-gateway"
}

func parseSSH(record JournalRecord) []Finding {
	if matches := sshInvalidPattern.FindStringSubmatch(record.Message); len(matches) == 3 {
		return oneFinding(record, matches[2], CategorySSHInvalidUser, ServiceSSH, hashSubject(matches[1]), map[string]any{"kind": "invalid_user"})
	}
	if matches := sshFailedPattern.FindStringSubmatch(record.Message); len(matches) == 3 {
		return oneFinding(record, matches[2], CategorySSHAuthFailed, ServiceSSH, hashSubject(matches[1]), map[string]any{"kind": "authentication_failure"})
	}
	if matches := sshRHostPattern.FindStringSubmatch(record.Message); len(matches) == 2 && strings.Contains(strings.ToLower(record.Message), "authentication failure") {
		subject := ""
		if user := sshUserPattern.FindStringSubmatch(record.Message); len(user) == 2 {
			subject = hashSubject(user[1])
		}
		return oneFinding(record, matches[1], CategorySSHAuthFailed, ServiceSSH, subject, map[string]any{"kind": "pam_authentication_failure"})
	}
	return nil
}

func parseHTTP(record JournalRecord) []Finding {
	matches := httpAccessPattern.FindStringSubmatch(record.Message)
	if len(matches) != 4 {
		return nil
	}
	path := stripQuery(matches[3])
	if !isSuspiciousPath(path) {
		return nil
	}
	return oneFinding(record, matches[1], CategoryHTTPAdminProbe, ServiceHTTP, "", map[string]any{
		"method": matches[2],
		"path":   path,
	})
}

func parseGateway(record JournalRecord) []Finding {
	var payload struct {
		EventType string `json:"event_type"`
		Event     string `json:"event"`
		IP        string `json:"ip"`
		Route     string `json:"route"`
	}
	if err := json.Unmarshal([]byte(record.Message), &payload); err != nil {
		return nil
	}
	eventType := payload.EventType
	if eventType == "" {
		eventType = payload.Event
	}
	metadata := map[string]any{"kind": eventType}
	if route := stripQuery(payload.Route); route != "" {
		metadata["route"] = route
	}
	switch eventType {
	case "auth.failed":
		return oneFinding(record, payload.IP, CategoryGatewayAuthFailed, ServiceGateway, "", metadata)
	case "api.auth_failed":
		return oneFinding(record, payload.IP, CategoryGatewayAPIAuthFailed, ServiceGateway, "", metadata)
	default:
		return nil
	}
}

func oneFinding(record JournalRecord, rawIP string, category Category, service Service, subjectHash string, metadata map[string]any) []Finding {
	address, err := netip.ParseAddr(strings.Trim(rawIP, "[](),;"))
	if err != nil {
		return nil
	}
	return []Finding{{
		IP:          address.Unmap(),
		Category:    category,
		Service:     service,
		OccurredAt:  record.OccurredAt.UTC(),
		SubjectHash: subjectHash,
		Metadata:    metadata,
	}}
}

func hashSubject(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func stripQuery(value string) string {
	value = strings.TrimSpace(value)
	if before, _, found := strings.Cut(value, "?"); found {
		return before
	}
	return value
}

func isSuspiciousPath(path string) bool {
	normalized := strings.ToLower(path)
	for _, candidate := range suspiciousPaths {
		if strings.Contains(normalized, candidate) {
			return true
		}
	}
	return false
}
