//go:build linux

package journal

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/s-gor/sg-infosec/internal/detection"
)

func TestJournalArgsAreFixedUnitScopedAndDoNotReplayHistory(t *testing.T) {
	t.Parallel()
	got := journalArgs([]string{"ssh.service", "nginx.service", "sg-gateway.service"})
	want := []string{
		"--follow",
		"--lines=0",
		"--output=json",
		"--no-pager",
		"--unit=ssh.service",
		"--unit=nginx.service",
		"--unit=sg-gateway.service",
	}
	if len(got) != len(want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("args[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestCollectorDecodesJournalJSONAndSkipsMalformedRecords(t *testing.T) {
	t.Parallel()
	stream := strings.Join([]string{
		`{"MESSAGE":"Failed password for root from 203.0.113.10 port 22 ssh2","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","__CURSOR":"c1","__REALTIME_TIMESTAMP":"1788256800000000"}`,
		`not-json`,
		`{"MESSAGE":"203.0.113.20 - - [01/Sep/2026:10:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"scanner\"","_SYSTEMD_UNIT":"nginx.service","SYSLOG_IDENTIFIER":"nginx","__CURSOR":"c2","__REALTIME_TIMESTAMP":"1788256801000000"}`,
	}, "\n") + "\n"
	var openedArgs []string
	collector := NewWithDependencies(DefaultConfig(), Dependencies{
		Open: func(_ context.Context, args []string) (io.ReadCloser, func() error, error) {
			openedArgs = append([]string(nil), args...)
			return io.NopCloser(strings.NewReader(stream)), func() error { return nil }, nil
		},
	})
	var records []detection.JournalRecord
	if err := collector.runOnce(context.Background(), func(record detection.JournalRecord) {
		records = append(records, record)
	}); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if len(openedArgs) == 0 {
		t.Fatal("journal stream was not opened")
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].Unit != "ssh.service" || records[0].Identifier != "sshd" || records[0].Cursor != "c1" {
		t.Fatalf("first record = %#v", records[0])
	}
	if records[0].OccurredAt != time.UnixMicro(1788256800000000).UTC() {
		t.Fatalf("timestamp = %s", records[0].OccurredAt)
	}
}

func TestCollectorRejectsOversizedJournalLine(t *testing.T) {
	t.Parallel()
	config := DefaultConfig()
	config.MaxLineBytes = 4096
	collector := NewWithDependencies(config, Dependencies{
		Open: func(_ context.Context, _ []string) (io.ReadCloser, func() error, error) {
			return io.NopCloser(strings.NewReader(strings.Repeat("x", 5000) + "\n")), func() error { return nil }, nil
		},
	})
	if err := collector.runOnce(context.Background(), func(detection.JournalRecord) {}); err == nil {
		t.Fatal("oversized line was accepted")
	}
}

func TestCollectorRunRetriesAndStopsOnCancellation(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	collector := NewWithDependencies(Config{
		Units:        []string{"ssh.service"},
		MaxLineBytes: 4096,
		RestartMin:   time.Millisecond,
		RestartMax:   2 * time.Millisecond,
	}, Dependencies{
		Open: func(_ context.Context, _ []string) (io.ReadCloser, func() error, error) {
			attempts++
			if attempts == 2 {
				cancel()
			}
			return nil, nil, errors.New("journal unavailable")
		},
		Sleep: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
	})
	if err := collector.Run(ctx, func(detection.JournalRecord) {}); err != nil {
		t.Fatalf("Run returned error during fail-open retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}
