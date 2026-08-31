package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/cli"
	"github.com/s-gor/sg-infosec/internal/config"
	consolepkg "github.com/s-gor/sg-infosec/internal/console"
	"github.com/s-gor/sg-infosec/pkg/client"
	"github.com/s-gor/sg-infosec/pkg/enforcerclient"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		if err := json.NewEncoder(stdout).Encode(buildinfo.Info()); err != nil {
			fmt.Fprintf(stderr, "encode version: %v\n", err)
			return cli.ExitFailure
		}
		return cli.ExitSuccess
	}
	base := cli.Dependencies{
		NewClient: func(socketPath string) cli.Service {
			return client.New(socketPath)
		},
		NewEnforcerClient: func(socketPath string) cli.EnforcerService {
			return enforcerclient.New(socketPath)
		},
		ValidateConfig: func(path string) error {
			_, err := config.Load(path)
			return err
		},
	}
	return cli.RunLocal(args, os.Stdin, stdout, stderr, cli.LocalDependencies{
		Dependencies: base,
		Stdin:        os.Stdin,
		Probe:        consolepkg.OSProbe{},
		Paths:        consolepkg.DefaultPaths(),
	})
}
