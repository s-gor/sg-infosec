package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/sshjournal"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		if err := json.NewEncoder(stdout).Encode(buildinfo.Info()); err != nil {
			fmt.Fprintf(stderr, "encode version: %v\n", err)
			return 1
		}
		return 0
	}
	flags := flag.NewFlagSet("sg-infosec-ssh-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	eventsSocket := flags.String("events-socket", "/run/sg-infosec/events.sock", "events Unix socket")
	journalctlPath := flags.String("journalctl", "/usr/bin/journalctl", "journalctl executable")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: sg-infosec-ssh-agent [--events-socket PATH] [--journalctl PATH]")
		return 2
	}
	if err := sshjournal.Run(ctx, sshjournal.Config{EventsSocket: *eventsSocket, JournalctlPath: *journalctlPath}); err != nil {
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(stderr, "ssh journal agent: %v\n", err)
		return 1
	}
	return 0
}
