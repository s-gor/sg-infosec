package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	consolepkg "github.com/s-gor/sg-infosec/internal/console"
	"github.com/s-gor/sg-infosec/pkg/client"
)

type LocalDependencies struct {
	Dependencies
	Stdin io.Reader
	Probe consolepkg.Probe
	Paths consolepkg.Paths
}

type consoleEnforcer struct{ service EnforcerService }

func (c consoleEnforcer) Ready(ctx context.Context) error {
	return c.service.Ensure(ctx, requestID("console-status"))
}

func RunLocal(args []string, stdin io.Reader, stdout, stderr io.Writer, dependencies LocalDependencies) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if stdin == nil {
		stdin = dependencies.Stdin
	}
	if stdin == nil {
		stdin = io.LimitReader(nilReader{}, 0)
	}

	global := flag.NewFlagSet("sg-infosecctl", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	jsonOutput := global.Bool("json", false, "emit JSON")
	socket := global.String("socket", defaultControlSocket, "control Unix socket")
	enforcerSocket := global.String("enforcer-socket", defaultEnforcerSocket, "enforcer Unix socket")
	if err := global.Parse(args); err != nil {
		return Run(args, stdout, stderr, dependencies.Dependencies)
	}
	remaining := global.Args()
	if len(remaining) == 0 || (remaining[0] != "overview" && remaining[0] != "console") {
		return Run(args, stdout, stderr, dependencies.Dependencies)
	}
	if len(remaining) != 1 {
		fmt.Fprintln(stderr, "usage error: overview/console accepts no arguments")
		return ExitUsage
	}
	if remaining[0] == "console" && *jsonOutput {
		fmt.Fprintln(stderr, "usage error: console does not support --json")
		return ExitUsage
	}
	if dependencies.NewClient == nil || dependencies.NewEnforcerClient == nil {
		fmt.Fprintln(stderr, "runtime error: client factories are not configured")
		return ExitFailure
	}
	core := dependencies.NewClient(*socket)
	enforcerService := dependencies.NewEnforcerClient(*enforcerSocket)
	if core == nil || enforcerService == nil {
		fmt.Fprintln(stderr, "runtime error: client factory returned nil")
		return ExitFailure
	}
	probe := dependencies.Probe
	if probe == nil {
		probe = consolepkg.OSProbe{}
	}
	paths := dependencies.Paths
	if paths.ControlSocket == "" {
		paths = consolepkg.DefaultPaths()
		paths.ControlSocket = *socket
		paths.EnforcerSocket = *enforcerSocket
	}
	enforcer := consoleEnforcer{service: enforcerService}

	ctx := context.Background()
	if remaining[0] == "overview" {
		snapshot, err := consolepkg.Collect(ctx, core, enforcer, probe, paths)
		if err != nil {
			return localFailure(stderr, err)
		}
		if *jsonOutput {
			if err := consolepkg.RenderJSON(stdout, snapshot); err != nil {
				return localFailure(stderr, err)
			}
			return ExitSuccess
		}
		consolepkg.RenderOverview(stdout, snapshot, false)
		return ExitSuccess
	}
	if err := consolepkg.Run(ctx, stdin, stdout, core, enforcer, probe, paths); err != nil {
		return localFailure(stderr, err)
	}
	return ExitSuccess
}

func localFailure(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "runtime error: %v\n", err)
	if client.IsPermissionDenied(err) {
		return ExitPermission
	}
	if client.IsUnavailable(err) {
		return ExitUnavailable
	}
	return ExitFailure
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }
