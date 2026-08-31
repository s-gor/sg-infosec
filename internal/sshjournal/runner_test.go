package sshjournal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type fakeSubmitter struct {
	events []protocol.EventRequest
	fail   int
}

func (f *fakeSubmitter) SubmitEvent(_ context.Context, event protocol.EventRequest) (protocol.EventResponse, error) {
	if f.fail > 0 {
		f.fail--
		return protocol.EventResponse{}, errors.New("temporary unavailable")
	}
	f.events = append(f.events, event)
	return protocol.EventResponse{Accepted: true}, nil
}

func TestRunStreamContinuesAfterMalformedRecordsAndDeliveryFailure(t *testing.T) {
	first, _ := json.Marshal(map[string]string{"MESSAGE": "Failed password for root from 192.0.2.10 port 22 ssh2", "__CURSOR": "one", "_SOURCE_REALTIME_TIMESTAMP": "1788182400000000", "_SYSTEMD_UNIT": "ssh.service"})
	ignored, _ := json.Marshal(map[string]string{"MESSAGE": "Accepted password for root from 192.0.2.11 port 22 ssh2", "__CURSOR": "ignored", "_SOURCE_REALTIME_TIMESTAMP": "1788182400000000", "_SYSTEMD_UNIT": "ssh.service"})
	second, _ := json.Marshal(map[string]string{"MESSAGE": "Failed publickey for admin from 2001:db8::5 port 22 ssh2", "__CURSOR": "two", "_SOURCE_REALTIME_TIMESTAMP": "1788182401000000", "_SYSTEMD_UNIT": "sshd.service"})
	input := strings.Join([]string{"not-json", string(first), string(ignored), string(second)}, "\n")

	submitter := &fakeSubmitter{fail: 1}
	if err := RunStream(context.Background(), strings.NewReader(input), submitter); err != nil {
		t.Fatal(err)
	}
	if len(submitter.events) != 1 || submitter.events[0].IP != "2001:db8::5" {
		t.Fatalf("events=%+v", submitter.events)
	}
}

func TestJournalctlArgumentsFollowOnlySSHUnitsAsJSON(t *testing.T) {
	got := JournalctlArguments()
	joined := strings.Join(got, " ")
	for _, value := range []string{"--follow", "--output=json", "--unit=ssh.service", "--unit=sshd.service", "--since=now", "--no-pager"} {
		if !strings.Contains(joined, value) {
			t.Fatalf("args=%v missing %q", got, value)
		}
	}
}

func TestRunStreamStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	record, _ := json.Marshal(map[string]string{"MESSAGE": "Failed password for root from 192.0.2.10 port 22 ssh2", "__CURSOR": "one", "_SYSTEMD_UNIT": "ssh.service"})
	err := RunStream(ctx, strings.NewReader(string(record)), &fakeSubmitter{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}
