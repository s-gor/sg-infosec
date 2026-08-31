package console

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

func Run(ctx context.Context, input io.Reader, output io.Writer, core Core, enforcer Enforcer, probe Probe, paths Paths) error {
	if input == nil || output == nil {
		return fmt.Errorf("console input and output are required")
	}
	reader := bufio.NewReader(input)
	if err := showOverview(ctx, output, core, enforcer, probe, paths); err != nil {
		return err
	}

	for {
		printActions(output)
		choice, err := prompt(reader, output, "Select: ")
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(output, "Goodbye")
				return nil
			}
			return err
		}
		switch strings.ToLower(choice) {
		case "1", "r":
			if err := showOverview(ctx, output, core, enforcer, probe, paths); err != nil {
				fmt.Fprintf(output, "Overview error: %v\n", err)
			}
		case "2":
			runManualBlock(ctx, reader, output, core)
		case "3":
			runRevoke(ctx, reader, output, core)
		case "4":
			runDecisionList(ctx, output, core)
		case "5":
			runAuditList(ctx, output, core)
		case "q", "quit", "exit":
			fmt.Fprintln(output, "Goodbye")
			return nil
		default:
			fmt.Fprintln(output, "Unknown action")
		}
	}
}

func showOverview(ctx context.Context, output io.Writer, core Core, enforcer Enforcer, probe Probe, paths Paths) error {
	snapshot, err := Collect(ctx, core, enforcer, probe, paths)
	if err != nil {
		return err
	}
	RenderOverview(output, snapshot, false)
	return nil
}

func printActions(output io.Writer) {
	fmt.Fprintln(output, "")
	fmt.Fprintln(output, "┌─ Actions ────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(output, "│ [1] Refresh overview       [4] List active decisions                 │")
	fmt.Fprintln(output, "│ [2] Block IP              [5] Recent audit                          │")
	fmt.Fprintln(output, "│ [3] Revoke decision       [R] Refresh       [Q] Quit                 │")
	fmt.Fprintln(output, "└──────────────────────────────────────────────────────────────────────┘")
}

func runManualBlock(ctx context.Context, reader *bufio.Reader, output io.Writer, core Core) {
	ip, err := prompt(reader, output, "IP address: ")
	if err != nil {
		return
	}
	address, err := netip.ParseAddr(ip)
	if err != nil {
		fmt.Fprintln(output, "Invalid IP address")
		return
	}
	address = address.Unmap()

	scope, err := prompt(reader, output, "Scope [ssh]: ")
	if err != nil {
		return
	}
	if scope == "" {
		scope = "ssh"
	}
	backend := "application"
	switch scope {
	case "ssh", "panel-port":
		backend = "nftables"
	case "admin-login", "admin-api":
	default:
		fmt.Fprintln(output, "Unsupported scope")
		return
	}

	durationText, err := prompt(reader, output, "Duration [30m]: ")
	if err != nil {
		return
	}
	if durationText == "" {
		durationText = "30m"
	}
	duration, err := time.ParseDuration(durationText)
	if err != nil || duration <= 0 {
		fmt.Fprintln(output, "Invalid duration")
		return
	}
	reason, err := prompt(reader, output, "Reason: ")
	if err != nil {
		return
	}
	if strings.TrimSpace(reason) == "" {
		fmt.Fprintln(output, "Reason is required")
		return
	}

	decision, err := core.AddDecision(ctx, protocol.ManualDecisionRequest{
		SourceID: "local-admin",
		Scope:    scope,
		Backend:  backend,
		IP:       address.String(),
		Duration: durationText,
		Reason:   reason,
	})
	if err != nil {
		fmt.Fprintf(output, "Decision error: %v\n", err)
		return
	}
	fmt.Fprintf(output, "Decision created: %s (%s %s)\n", decision.ID, scope, address)
}

func runRevoke(ctx context.Context, reader *bufio.Reader, output io.Writer, core Core) {
	id, err := prompt(reader, output, "Decision ID: ")
	if err != nil || strings.TrimSpace(id) == "" {
		return
	}
	response, err := core.RevokeDecision(ctx, id)
	if err != nil {
		fmt.Fprintf(output, "Revoke error: %v\n", err)
		return
	}
	if response.Changed {
		fmt.Fprintln(output, "Decision revoked")
	} else {
		fmt.Fprintln(output, "Decision was already inactive")
	}
}

func runDecisionList(ctx context.Context, output io.Writer, core Core) {
	response, err := core.ListDecisions(ctx, client.ListOptions{Limit: 50, State: "active"})
	if err != nil {
		fmt.Fprintf(output, "Decision list error: %v\n", err)
		return
	}
	if len(response.Items) == 0 {
		fmt.Fprintln(output, "No active decisions")
		return
	}
	for _, item := range response.Items {
		fmt.Fprintf(output, "%s  %-10s %-15s %-39s until %s\n", item.ID, item.Scope, item.SourceID, item.IP, item.ExpiresAt.UTC().Format(time.RFC3339))
	}
}

func runAuditList(ctx context.Context, output io.Writer, core Core) {
	response, err := core.ListAudit(ctx, client.ListOptions{Limit: 25})
	if err != nil {
		fmt.Fprintf(output, "Audit error: %v\n", err)
		return
	}
	if len(response.Items) == 0 {
		fmt.Fprintln(output, "Audit is empty")
		return
	}
	for _, item := range response.Items {
		fmt.Fprintf(output, "%s  %-20s %-22s %s\n", item.OccurredAt.UTC().Format(time.RFC3339), item.Actor, item.Action, item.TargetID)
	}
}

func prompt(reader *bufio.Reader, output io.Writer, label string) (string, error) {
	fmt.Fprint(output, label)
	value, err := reader.ReadString('\n')
	if err != nil && len(value) == 0 {
		return "", err
	}
	return strings.TrimSpace(value), nil
}
