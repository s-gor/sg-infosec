package sshjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/pkg/protocol"
)

var (
	failedAuthPattern = regexp.MustCompile(`^Failed ([A-Za-z0-9_-]+) for (?:invalid user )?([^ ]+) from ([^ ]+) port [0-9]+(?: |$)`)
	pamFailurePattern = regexp.MustCompile(`^PAM: Authentication failure for (?:illegal user )?([^ ]+) from ([^ ]+)(?: |$)`)
)

type journalRecord struct {
	Message                 string `json:"MESSAGE"`
	Cursor                  string `json:"__CURSOR"`
	RealtimeTimestamp       string `json:"__REALTIME_TIMESTAMP"`
	SourceRealtimeTimestamp string `json:"_SOURCE_REALTIME_TIMESTAMP"`
	SystemdUnit             string `json:"_SYSTEMD_UNIT"`
}

func ParseRecord(encoded []byte) (protocol.EventRequest, bool) {
	var record journalRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return protocol.EventRequest{}, false
	}
	if record.SystemdUnit != "ssh.service" && record.SystemdUnit != "sshd.service" {
		return protocol.EventRequest{}, false
	}

	method, subject, rawIP, ok := parseFailure(record.Message)
	if !ok {
		return protocol.EventRequest{}, false
	}
	address, err := netip.ParseAddr(strings.Trim(rawIP, "[]"))
	if err != nil {
		return protocol.EventRequest{}, false
	}
	address = address.Unmap()

	occurredAt := parseJournalTime(record.SourceRealtimeTimestamp)
	if occurredAt.IsZero() {
		occurredAt = parseJournalTime(record.RealtimeTimestamp)
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	identity := record.Cursor
	if identity == "" {
		identity = record.SystemdUnit + "\x00" + record.SourceRealtimeTimestamp + "\x00" + record.RealtimeTimestamp + "\x00" + record.Message
	}
	digest := sha256.Sum256([]byte(identity))

	return protocol.EventRequest{
		EventID:    "ssh-journal-" + hex.EncodeToString(digest[:16]),
		EventType:  "auth.failed",
		Scope:      "ssh",
		IP:         address.String(),
		Subject:    sanitizeSubject(subject),
		OccurredAt: occurredAt,
		Metadata: map[string]any{
			"method": method,
			"reason": "invalid_credentials",
			"unit":   record.SystemdUnit,
		},
	}, true
}

func parseFailure(message string) (method, subject, ip string, ok bool) {
	if matches := failedAuthPattern.FindStringSubmatch(message); len(matches) == 4 {
		return strings.ToLower(matches[1]), matches[2], matches[3], true
	}
	if matches := pamFailurePattern.FindStringSubmatch(message); len(matches) == 3 {
		return "pam", matches[1], matches[2], true
	}
	return "", "", "", false
}

func parseJournalTime(value string) time.Time {
	microseconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || microseconds <= 0 {
		return time.Time{}
	}
	return time.Unix(0, microseconds*int64(time.Microsecond)).UTC()
}

func sanitizeSubject(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}
