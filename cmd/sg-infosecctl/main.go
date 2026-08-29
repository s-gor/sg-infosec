package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/cli"
	"github.com/s-gor/sg-infosec/internal/config"
	"github.com/s-gor/sg-infosec/pkg/client"
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
	return cli.Run(args, stdout, stderr, cli.Dependencies{
		NewClient: func(socketPath string) cli.Service {
			return client.New(socketPath)
		},
		ValidateConfig: func(path string) error {
			_, err := config.Load(path)
			return err
		},
	})
}
