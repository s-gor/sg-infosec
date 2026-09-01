//go:build linux

package journal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/internal/detection"
)

type Config struct {
	Units        []string
	MaxLineBytes int
	RestartMin   time.Duration
	RestartMax   time.Duration
}

type OpenFunc func(context.Context, []string) (io.ReadCloser, func() error, error)
type SleepFunc func(context.Context, time.Duration) error

type Dependencies struct {
	Open  OpenFunc
	Sleep SleepFunc
}

type Collector struct {
	config Config
	open   OpenFunc
	sleep  SleepFunc
}

func DefaultConfig() Config {
	return Config{
		Units: []string{
			"ssh.service",
			"sshd.service",
			"nginx.service",
			"sg-gateway.service",
		},
		MaxLineBytes: 64 * 1024,
		RestartMin:   time.Second,
		RestartMax:   30 * time.Second,
	}
}

func New(config Config) *Collector {
	return NewWithDependencies(config, Dependencies{})
}

func NewWithDependencies(config Config, dependencies Dependencies) *Collector {
	config = normalizeConfig(config)
	if dependencies.Open == nil {
		dependencies.Open = openJournal
	}
	if dependencies.Sleep == nil {
		dependencies.Sleep = sleepContext
	}
	return &Collector{config: config, open: dependencies.Open, sleep: dependencies.Sleep}
}

func (collector *Collector) Run(ctx context.Context, consume func(detection.JournalRecord)) error {
	if collector == nil || collector.open == nil || collector.sleep == nil || consume == nil {
		return fmt.Errorf("journal collector is not initialized")
	}
	backoff := collector.config.RestartMin
	for {
		if ctx.Err() != nil {
			return nil
		}
		_ = collector.runOnce(ctx, consume)
		if ctx.Err() != nil {
			return nil
		}
		if err := collector.sleep(ctx, backoff); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		backoff *= 2
		if backoff > collector.config.RestartMax {
			backoff = collector.config.RestartMax
		}
	}
}

func (collector *Collector) runOnce(ctx context.Context, consume func(detection.JournalRecord)) error {
	stream, wait, err := collector.open(ctx, journalArgs(collector.config.Units))
	if err != nil {
		return err
	}
	if stream == nil || wait == nil {
		return fmt.Errorf("journal stream opener returned incomplete handles")
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	initial := 4096
	if collector.config.MaxLineBytes < initial {
		initial = collector.config.MaxLineBytes
	}
	scanner.Buffer(make([]byte, initial), collector.config.MaxLineBytes)
	for scanner.Scan() {
		record, ok := decodeRecord(scanner.Bytes())
		if !ok {
			continue
		}
		consume(record)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read journal stream: %w", err)
	}
	if err := wait(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("journalctl exited: %w", err)
	}
	return nil
}

func journalArgs(units []string) []string {
	arguments := []string{"--follow", "--lines=0", "--output=json", "--no-pager"}
	seen := make(map[string]struct{}, len(units))
	for _, unit := range units {
		unit = strings.TrimSpace(unit)
		if unit == "" {
			continue
		}
		if _, exists := seen[unit]; exists {
			continue
		}
		seen[unit] = struct{}{}
		arguments = append(arguments, "--unit="+unit)
	}
	return arguments
}

func decodeRecord(raw []byte) (detection.JournalRecord, bool) {
	var payload struct {
		Message    json.RawMessage `json:"MESSAGE"`
		Unit       string          `json:"_SYSTEMD_UNIT"`
		Identifier string          `json:"SYSLOG_IDENTIFIER"`
		Cursor     string          `json:"__CURSOR"`
		Timestamp  string          `json:"__REALTIME_TIMESTAMP"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return detection.JournalRecord{}, false
	}
	message, ok := journalString(payload.Message)
	if !ok || strings.TrimSpace(message) == "" {
		return detection.JournalRecord{}, false
	}
	occurredAt := time.Now().UTC()
	if microseconds, err := strconv.ParseInt(payload.Timestamp, 10, 64); err == nil && microseconds > 0 {
		occurredAt = time.UnixMicro(microseconds).UTC()
	}
	return detection.JournalRecord{
		Unit:       payload.Unit,
		Identifier: payload.Identifier,
		Message:    message,
		Cursor:     payload.Cursor,
		OccurredAt: occurredAt,
	}, true
}

func journalString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	var bytesValue []byte
	if err := json.Unmarshal(raw, &bytesValue); err == nil {
		return string(bytesValue), true
	}
	return "", false
}

func openJournal(ctx context.Context, arguments []string) (io.ReadCloser, func() error, error) {
	command := exec.CommandContext(ctx, "journalctl", arguments...)
	stream, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("open journal stdout: %w", err)
	}
	if err := command.Start(); err != nil {
		_ = stream.Close()
		return nil, nil, fmt.Errorf("start journalctl: %w", err)
	}
	return stream, command.Wait, nil
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func normalizeConfig(config Config) Config {
	defaults := DefaultConfig()
	if len(config.Units) == 0 {
		config.Units = defaults.Units
	}
	if config.MaxLineBytes < 4096 {
		config.MaxLineBytes = defaults.MaxLineBytes
	}
	if config.RestartMin <= 0 {
		config.RestartMin = defaults.RestartMin
	}
	if config.RestartMax < config.RestartMin {
		config.RestartMax = defaults.RestartMax
	}
	return config
}
