package sshjournal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

const defaultEventsSocket = "/run/sg-infosec/events.sock"

type Submitter interface {
	SubmitEvent(context.Context, protocol.EventRequest) (protocol.EventResponse, error)
}

type Config struct {
	EventsSocket   string
	JournalctlPath string
}

func JournalctlArguments() []string {
	return []string{
		"--follow",
		"--output=json",
		"--unit=ssh.service",
		"--unit=sshd.service",
		"--since=now",
		"--no-pager",
	}
}

func Run(ctx context.Context, configuration Config) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	eventsSocket := strings.TrimSpace(configuration.EventsSocket)
	if eventsSocket == "" {
		eventsSocket = defaultEventsSocket
	}
	journalctlPath := strings.TrimSpace(configuration.JournalctlPath)
	if journalctlPath == "" {
		journalctlPath = "/usr/bin/journalctl"
	}

	command := exec.CommandContext(ctx, journalctlPath, JournalctlArguments()...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open journal stream: %w", err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}

	eventClient := client.New(eventsSocket, client.WithTimeout(500*time.Millisecond))
	streamErr := RunStream(ctx, stdout, eventClient)
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if streamErr != nil {
		return streamErr
	}
	if waitErr != nil {
		return fmt.Errorf("journalctl stopped: %w", waitErr)
	}
	return fmt.Errorf("journalctl stopped unexpectedly")
}

func RunStream(ctx context.Context, reader io.Reader, submitter Submitter) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if reader == nil {
		return fmt.Errorf("journal reader is required")
	}
	if submitter == nil {
		return fmt.Errorf("event submitter is required")
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		event, ok := ParseRecord(scanner.Bytes())
		if !ok {
			continue
		}
		_, _ = submitter.SubmitEvent(ctx, event)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read journal stream: %w", err)
	}
	return nil
}
