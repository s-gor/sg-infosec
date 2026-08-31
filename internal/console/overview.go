package console

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

type Core interface {
	Health(context.Context) (client.HealthResponse, error)
	ListDecisions(context.Context, client.ListOptions) (protocol.DecisionListResponse, error)
	ListAllowlist(context.Context, client.ListOptions) (protocol.AllowlistListResponse, error)
	ListAudit(context.Context, client.ListOptions) (protocol.AuditListResponse, error)
	AddDecision(context.Context, protocol.ManualDecisionRequest) (protocol.DecisionView, error)
	RevokeDecision(context.Context, string) (protocol.ActionResponse, error)
}

type Enforcer interface {
	Ready(context.Context) error
}

type Probe interface {
	Hostname() string
	Exists(string) bool
}

type OSProbe struct{}

func (OSProbe) Hostname() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "unknown"
	}
	return hostname
}

func (OSProbe) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type Paths struct {
	ControlSocket  string
	EventsSocket   string
	EnforcerSocket string
	SSHUnit        string
	GatewayRoot    string
	GatewayAdapter string
}

func DefaultPaths() Paths {
	return Paths{
		ControlSocket:  "/run/sg-infosec/control.sock",
		EventsSocket:   "/run/sg-infosec/events.sock",
		EnforcerSocket: "/run/sg-infosec/enforcer.sock",
		SSHUnit:        "/etc/systemd/system/sg-infosec-ssh-agent.service",
		GatewayRoot:    "/opt/sg-gateway",
		GatewayAdapter: "/opt/sg-gateway/app/security/sg_infosec.py",
	}
}

type Snapshot struct {
	Hostname          string `json:"hostname"`
	CoreStatus        string `json:"core_status"`
	Database          string `json:"database"`
	Protocol          string `json:"protocol"`
	DatabaseBytes     int64  `json:"database_bytes"`
	ActiveDecisions   int    `json:"active_decisions"`
	AllowlistEntries  int    `json:"allowlist_entries"`
	RecentAuditEvents int    `json:"recent_audit_events"`
	EnforcerReady     bool   `json:"enforcer_ready"`
	ControlConnected  bool   `json:"control_connected"`
	EventsConnected   bool   `json:"events_connected"`
	EnforcerConnected bool   `json:"enforcer_connected"`
	SSHCollector      bool   `json:"ssh_collector"`
	GatewayDetected   bool   `json:"gateway_detected"`
	GatewayAdapter    bool   `json:"gateway_adapter"`
	ControlSocket     string `json:"control_socket"`
	EventsSocket      string `json:"events_socket"`
	EnforcerSocket    string `json:"enforcer_socket"`
}

func Collect(ctx context.Context, core Core, enforcer Enforcer, probe Probe, paths Paths) (Snapshot, error) {
	if core == nil || enforcer == nil || probe == nil {
		return Snapshot{}, fmt.Errorf("console dependencies are required")
	}
	health, err := core.Health(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	decisions, err := core.ListDecisions(ctx, client.ListOptions{Limit: 100, State: "active"})
	if err != nil {
		return Snapshot{}, err
	}
	allowlist, err := core.ListAllowlist(ctx, client.ListOptions{Limit: 100})
	if err != nil {
		return Snapshot{}, err
	}
	audit, err := core.ListAudit(ctx, client.ListOptions{Limit: 100})
	if err != nil {
		return Snapshot{}, err
	}
	enforcerReady := enforcer.Ready(ctx) == nil

	return Snapshot{
		Hostname:          probe.Hostname(),
		CoreStatus:        health.Status,
		Database:          health.Database,
		Protocol:          health.ProtocolVersion,
		DatabaseBytes:     health.DatabaseBytes,
		ActiveDecisions:   len(decisions.Items),
		AllowlistEntries:  len(allowlist.Items),
		RecentAuditEvents: len(audit.Items),
		EnforcerReady:     enforcerReady,
		ControlConnected:  probe.Exists(paths.ControlSocket),
		EventsConnected:   probe.Exists(paths.EventsSocket),
		EnforcerConnected: probe.Exists(paths.EnforcerSocket),
		SSHCollector:      probe.Exists(paths.SSHUnit),
		GatewayDetected:   probe.Exists(paths.GatewayRoot),
		GatewayAdapter:    probe.Exists(paths.GatewayAdapter),
		ControlSocket:     paths.ControlSocket,
		EventsSocket:      paths.EventsSocket,
		EnforcerSocket:    paths.EnforcerSocket,
	}, nil
}

func RenderJSON(writer io.Writer, snapshot Snapshot) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(snapshot)
}

func RenderOverview(writer io.Writer, snapshot Snapshot, color bool) {
	status := strings.ToUpper(snapshot.CoreStatus)
	ready := "NOT READY"
	if snapshot.EnforcerReady {
		ready = "READY"
	}
	connected := func(value bool) string {
		if value {
			return "CONNECTED"
		}
		return "DISCONNECTED"
	}
	gateway := "NOT DETECTED"
	if snapshot.GatewayDetected {
		gateway = "DETECTED"
	}
	if snapshot.GatewayAdapter {
		gateway = "ADAPTER READY"
	}
	ssh := "NOT INSTALLED"
	if snapshot.SSHCollector {
		ssh = "CONNECTED"
	}

	green, reset := "", ""
	if color {
		green, reset = "\x1b[32m", "\x1b[0m"
	}
	fmt.Fprintln(writer, "┌─────────────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(writer, "│                        SG InfoSec Console                            │")
	fmt.Fprintln(writer, "├────────────────────────┬────────────────────────────────────────────┤")
	row(writer, "Server", snapshot.Hostname)
	row(writer, "Core", green+status+reset)
	row(writer, "Database", snapshot.Database)
	row(writer, "Protocol", snapshot.Protocol)
	row(writer, "Database bytes", fmt.Sprintf("%d", snapshot.DatabaseBytes))
	fmt.Fprintln(writer, "├────────────────────────┼───────────────────────────────────────────┤")
	row(writer, "Control API", snapshot.ControlSocket+"  "+connected(snapshot.ControlConnected))
	row(writer, "Events API", snapshot.EventsSocket+"  "+connected(snapshot.EventsConnected))
	row(writer, "Enforcer", snapshot.EnforcerSocket+"  "+ready)
	row(writer, "SSH journal", ssh)
	row(writer, "SG-Gateway", gateway)
	fmt.Fprintln(writer, "├─────────────────────────┼────────────────────────────────────────────┤")
	row(writer, "Active decisions", fmt.Sprintf("%d", snapshot.ActiveDecisions))
	row(writer, "Allowlist", fmt.Sprintf("%d", snapshot.AllowlistEntries))
	row(writer, "Audit records", fmt.Sprintf("%d", snapshot.RecentAuditEvents))
	row(writer, "VPN ports 585/586/587", "excluded")
	fmt.Fprintln(writer, "└─────────────────────────┴────────────────────────────────────────────┘")
}

func row(writer io.Writer, label, value string) {
	fmt.Fprintf(writer, "│ %-23s │ %-42s │\n", truncate(label, 23), truncate(value, 42))
}

func truncate(value string, width int) string {
	characters := []rune(value)
	if len(characters) <= width {
		return value
	}
	if width <= 1 {
		return string(characters[:width])
	}
	return string(characters[:width-1]) + "…"
}
