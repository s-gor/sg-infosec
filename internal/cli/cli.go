package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/enforcerprotocol"
	"github.com/s-gor/sg-infosec/pkg/protocol"
)

const (
	ExitSuccess     = 0
	ExitFailure     = 1
	ExitUsage       = 2
	ExitPermission  = 3
	ExitUnavailable = 4
)

const (
	defaultControlSocket  = "/run/sg-infosec/control.sock"
	defaultEnforcerSocket = "/run/sg-infosec/enforcer.sock"
)

type Service interface {
	Health(context.Context) (client.HealthResponse, error)
	CheckDecision(context.Context, protocol.DecisionCheckRequest) (protocol.DecisionCheckResponse, error)
	ListDecisions(context.Context, client.ListOptions) (protocol.DecisionListResponse, error)
	AddDecision(context.Context, protocol.ManualDecisionRequest) (protocol.DecisionView, error)
	RevokeDecision(context.Context, string) (protocol.ActionResponse, error)
	ListAllowlist(context.Context, client.ListOptions) (protocol.AllowlistListResponse, error)
	AddAllowlist(context.Context, protocol.AllowlistCreateRequest) (protocol.AllowlistView, error)
	RemoveAllowlist(context.Context, string) (protocol.ActionResponse, error)
	ListAudit(context.Context, client.ListOptions) (protocol.AuditListResponse, error)
	ReconcileNFT(context.Context) (protocol.ActionResponse, error)
}

type EnforcerService interface {
	Ensure(context.Context, string) error
	List(context.Context) (enforcerprotocol.ListResponse, error)
}

type Dependencies struct {
	NewClient         func(socketPath string) Service
	NewEnforcerClient func(socketPath string) EnforcerService
	ValidateConfig    func(path string) error
}

type runner struct {
	stdout io.Writer
	stderr io.Writer
	json   bool
	deps   Dependencies
	socket string
}

func Run(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	global := flag.NewFlagSet("sg-infosecctl", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	jsonOutput := global.Bool("json", false, "emit JSON")
	socket := global.String("socket", defaultControlSocket, "control Unix socket")
	enforcerSocket := global.String("enforcer-socket", defaultEnforcerSocket, "enforcer Unix socket")
	if err := global.Parse(args); err != nil {
		fmt.Fprintf(stderr, "usage error: %v\n", err)
		return ExitUsage
	}
	remaining := global.Args()
	if len(remaining) == 0 {
		printUsage(stderr)
		return ExitUsage
	}
	current := &runner{stdout: stdout, stderr: stderr, json: *jsonOutput, deps: dependencies, socket: *socket}
	if remaining[0] == "config" {
		return current.runConfig(remaining[1:])
	}
	if remaining[0] == "nft" {
		if len(remaining) != 2 {
			return current.usage("nft requires one of: status, list, reconcile")
		}
		if remaining[1] == "reconcile" {
			if dependencies.NewClient == nil {
				fmt.Fprintln(stderr, "runtime error: client factory is not configured")
				return ExitFailure
			}
			service := dependencies.NewClient(*socket)
			if service == nil {
				fmt.Fprintln(stderr, "runtime error: client factory returned nil")
				return ExitFailure
			}
			return current.runNFTReconcile(context.Background(), service)
		}
		if dependencies.NewEnforcerClient == nil {
			fmt.Fprintln(stderr, "runtime error: enforcer client factory is not configured")
			return ExitFailure
		}
		service := dependencies.NewEnforcerClient(*enforcerSocket)
		if service == nil {
			fmt.Fprintln(stderr, "runtime error: enforcer client factory returned nil")
			return ExitFailure
		}
		return current.runNFTEnforcer(context.Background(), service, remaining[1])
	}
	if dependencies.NewClient == nil {
		fmt.Fprintln(stderr, "runtime error: client factory is not configured")
		return ExitFailure
	}
	service := dependencies.NewClient(*socket)
	if service == nil {
		fmt.Fprintln(stderr, "runtime error: client factory returned nil")
		return ExitFailure
	}
	return current.runService(context.Background(), service, remaining)
}

func (r *runner) runService(ctx context.Context, service Service, args []string) int {
	switch args[0] {
	case "health", "status":
		if len(args) != 1 {
			return r.usage("health/status accepts no arguments")
		}
		response, err := service.Health(ctx)
		if err != nil {
			return r.failure(err)
		}
		return r.printHealth(response)
	case "decisions":
		return r.runDecisions(ctx, service, args[1:])
	case "allowlist":
		return r.runAllowlist(ctx, service, args[1:])
	case "audit":
		return r.runAudit(ctx, service, args[1:])
	default:
		return r.usage("unknown command " + args[0])
	}
}

func (r *runner) runNFTEnforcer(ctx context.Context, service EnforcerService, command string) int {
	switch command {
	case "status":
		if err := service.Ensure(ctx, requestID("ctl-status")); err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(enforcerprotocol.ActionResponse{OK: true})
		}
		fmt.Fprintln(r.stdout, "nftables enforcer: ready")
		return ExitSuccess
	case "list":
		response, err := service.List(ctx)
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		if len(response.Entries) == 0 {
			fmt.Fprintln(r.stdout, "no nftables entries")
		} else {
			for _, entry := range response.Entries {
				fmt.Fprintf(r.stdout, "%s %s/%d %s until %s\n", entry.Scope, entry.Protocol, entry.Port, entry.IP, entry.ExpiresAt.UTC().Format(time.RFC3339))
			}
		}
		return ExitSuccess
	default:
		return r.usage("unknown nft subcommand " + command)
	}
}

func (r *runner) runNFTReconcile(ctx context.Context, service Service) int {
	response, err := service.ReconcileNFT(ctx)
	if err != nil {
		return r.failure(err)
	}
	if r.json {
		return r.printJSON(response)
	}
	fmt.Fprintln(r.stdout, "nftables reconciled from SQLite")
	return ExitSuccess
}

func requestID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
}

func (r *runner) runDecisions(ctx context.Context, service Service, args []string) int {
	if len(args) == 0 {
		return r.usage("decisions subcommand is required")
	}
	switch args[0] {
	case "list":
		flags := newFlagSet("decisions list")
		options := bindListOptions(flags, true)
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !validLimit(options.Limit) {
			return r.usage("invalid decisions list arguments")
		}
		response, err := service.ListDecisions(ctx, options)
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		if len(response.Items) == 0 {
			fmt.Fprintln(r.stdout, "no decisions")
		} else {
			for _, item := range response.Items {
				fmt.Fprintf(r.stdout, "%s %s %s %s %s until %s\n", item.ID, item.State, item.SourceID, item.Scope, item.IP, item.ExpiresAt.UTC().Format(time.RFC3339))
			}
		}
		if response.NextCursor != "" {
			fmt.Fprintf(r.stdout, "next cursor: %s\n", response.NextCursor)
		}
		return ExitSuccess
	case "add":
		flags := newFlagSet("decisions add")
		var request protocol.ManualDecisionRequest
		flags.StringVar(&request.SourceID, "source", "", "target source")
		flags.StringVar(&request.Scope, "scope", "", "target scope")
		flags.StringVar(&request.Backend, "backend", "", "decision backend")
		flags.StringVar(&request.IP, "ip", "", "target IP")
		flags.StringVar(&request.Duration, "duration", "", "decision duration")
		flags.StringVar(&request.Reason, "reason", "", "reason")
		flags.BoolVar(&request.OverrideAllowlist, "override-allowlist", false, "override allowlist")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || strings.TrimSpace(request.SourceID) == "" || strings.TrimSpace(request.Scope) == "" || strings.TrimSpace(request.IP) == "" || strings.TrimSpace(request.Duration) == "" || strings.TrimSpace(request.Reason) == "" {
			return r.usage("decisions add requires --source, --scope, --ip, --duration, and --reason")
		}
		duration, err := time.ParseDuration(request.Duration)
		if err != nil || duration <= 0 {
			return r.usage("decision duration must be positive")
		}
		response, err := service.AddDecision(ctx, request)
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		fmt.Fprintf(r.stdout, "created decision %s for %s %s\n", response.ID, response.Scope, response.IP)
		return ExitSuccess
	case "revoke":
		if len(args) != 2 || !validResourceID(args[1]) {
			return r.usage("decisions revoke requires one valid decision ID")
		}
		response, err := service.RevokeDecision(ctx, args[1])
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		if response.Changed {
			fmt.Fprintln(r.stdout, "decision revoked")
		} else {
			fmt.Fprintln(r.stdout, "decision was already revoked")
		}
		return ExitSuccess
	default:
		return r.usage("unknown decisions subcommand " + args[0])
	}
}

func (r *runner) runAllowlist(ctx context.Context, service Service, args []string) int {
	if len(args) == 0 {
		return r.usage("allowlist subcommand is required")
	}
	switch args[0] {
	case "list":
		flags := newFlagSet("allowlist list")
		options := bindListOptions(flags, false)
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !validLimit(options.Limit) {
			return r.usage("invalid allowlist list arguments")
		}
		response, err := service.ListAllowlist(ctx, options)
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		if len(response.Items) == 0 {
			fmt.Fprintln(r.stdout, "allowlist is empty")
		} else {
			for _, item := range response.Items {
				fmt.Fprintf(r.stdout, "%s %s %s\n", item.ID, item.Prefix, item.Description)
			}
		}
		return ExitSuccess
	case "add":
		flags := newFlagSet("allowlist add")
		var request protocol.AllowlistCreateRequest
		var expires string
		flags.StringVar(&request.Prefix, "prefix", "", "IP or CIDR")
		flags.StringVar(&request.Scope, "scope", "", "optional scope")
		flags.StringVar(&request.Description, "description", "", "reason")
		flags.StringVar(&expires, "expires-at", "", "RFC3339 expiry")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || strings.TrimSpace(request.Prefix) == "" || strings.TrimSpace(request.Description) == "" {
			return r.usage("allowlist add requires --prefix and --description")
		}
		if expires != "" {
			value, err := time.Parse(time.RFC3339, expires)
			if err != nil {
				return r.usage("expires-at must use RFC3339")
			}
			request.ExpiresAt = &value
		}
		response, err := service.AddAllowlist(ctx, request)
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		fmt.Fprintf(r.stdout, "added allowlist entry %s (%s)\n", response.ID, response.Prefix)
		return ExitSuccess
	case "remove":
		if len(args) != 2 || !validResourceID(args[1]) {
			return r.usage("allowlist remove requires one valid entry ID")
		}
		response, err := service.RemoveAllowlist(ctx, args[1])
		if err != nil {
			return r.failure(err)
		}
		if r.json {
			return r.printJSON(response)
		}
		fmt.Fprintln(r.stdout, "allowlist entry removed")
		return ExitSuccess
	default:
		return r.usage("unknown allowlist subcommand " + args[0])
	}
}

func (r *runner) runAudit(ctx context.Context, service Service, args []string) int {
	if len(args) == 0 || args[0] != "list" {
		return r.usage("audit list is required")
	}
	flags := newFlagSet("audit list")
	options := bindListOptions(flags, false)
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !validLimit(options.Limit) {
		return r.usage("invalid audit list arguments")
	}
	response, err := service.ListAudit(ctx, options)
	if err != nil {
		return r.failure(err)
	}
	if r.json {
		return r.printJSON(response)
	}
	if len(response.Items) == 0 {
		fmt.Fprintln(r.stdout, "audit is empty")
	} else {
		for _, item := range response.Items {
			fmt.Fprintf(r.stdout, "%s %s %s %s\n", item.OccurredAt.UTC().Format(time.RFC3339), item.Actor, item.Action, item.TargetID)
		}
	}
	return ExitSuccess
}

func (r *runner) runConfig(args []string) int {
	if len(args) == 0 || args[0] != "validate" {
		return r.usage("config validate is required")
	}
	flags := newFlagSet("config validate")
	path := flags.String("config", "", "configuration path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || strings.TrimSpace(*path) == "" {
		return r.usage("config validate requires --config")
	}
	if r.deps.ValidateConfig == nil {
		fmt.Fprintln(r.stderr, "runtime error: configuration validator is not configured")
		return ExitFailure
	}
	if err := r.deps.ValidateConfig(*path); err != nil {
		fmt.Fprintf(r.stderr, "configuration error: %v\n", err)
		return ExitUsage
	}
	if r.json {
		return r.printJSON(struct {
			Valid bool   `json:"valid"`
			Path  string `json:"path"`
		}{Valid: true, Path: *path})
	}
	fmt.Fprintf(r.stdout, "configuration is valid: %s\n", *path)
	return ExitSuccess
}

func (r *runner) printHealth(response client.HealthResponse) int {
	if r.json {
		return r.printJSON(response)
	}
	fmt.Fprintf(r.stdout, "status: %s\ndatabase: %s\nprotocol: %s\nactive decisions: %d\ndatabase bytes: %d\n", response.Status, response.Database, response.ProtocolVersion, response.ActiveDecisions, response.DatabaseBytes)
	return ExitSuccess
}

func (r *runner) printJSON(value any) int {
	encoder := json.NewEncoder(r.stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(r.stderr, "output error: %v\n", err)
		return ExitFailure
	}
	return ExitSuccess
}

func (r *runner) failure(err error) int {
	if err == nil {
		return ExitSuccess
	}
	fmt.Fprintf(r.stderr, "error: %v\n", err)
	switch {
	case client.IsPermissionDenied(err):
		return ExitPermission
	case client.IsUnavailable(err):
		return ExitUnavailable
	default:
		return ExitFailure
	}
}

func (r *runner) usage(message string) int {
	fmt.Fprintf(r.stderr, "usage error: %s\n", message)
	return ExitUsage
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func bindListOptions(flags *flag.FlagSet, decisions bool) client.ListOptions {
	var options client.ListOptions
	flags.IntVar(&options.Limit, "limit", 50, "page size")
	flags.StringVar(&options.Cursor, "cursor", "", "page cursor")
	if decisions {
		flags.StringVar(&options.SourceID, "source", "", "source filter")
		flags.StringVar(&options.Scope, "scope", "", "scope filter")
		flags.StringVar(&options.State, "state", "", "state filter")
	}
	return options
}

func validLimit(limit int) bool { return limit >= 1 && limit <= 200 }

func validResourceID(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "/\\")
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: sg-infosecctl [--json] [--socket PATH] [--enforcer-socket PATH] <health|status|decisions|allowlist|audit|nft|config> ...")
}
