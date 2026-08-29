//go:build linux

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

	"github.com/s-gor/sg-infosec/internal/app"
	"github.com/s-gor/sg-infosec/internal/buildinfo"
	"github.com/s-gor/sg-infosec/internal/config"
)

type application interface {
	Run(context.Context) error
	Close() error
}

type runtimeDependencies struct {
	loadConfig func(string) (config.Config, error)
	newApp     func(config.Config) (application, error)
	context    func() (context.Context, context.CancelFunc)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, runtimeDependencies{
		loadConfig: config.Load,
		newApp: func(cfg config.Config) (application, error) {
			return app.New(cfg, app.Dependencies{})
		},
		context: func() (context.Context, context.CancelFunc) {
			return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		},
	})
}

func runWith(args []string, stdout, stderr io.Writer, deps runtimeDependencies) int {
	flags := flag.NewFlagSet("sg-infosecd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/sg-infosec/sg-infosec.yaml", "configuration file")
	showVersion := flags.Bool("version", false, "print version")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if *showVersion {
		if err := json.NewEncoder(stdout).Encode(buildinfo.Info()); err != nil {
			fmt.Fprintf(stderr, "encode version: %v\n", err)
			return 1
		}
		return 0
	}
	if deps.loadConfig == nil || deps.newApp == nil || deps.context == nil {
		fmt.Fprintln(stderr, "runtime dependencies are not initialized")
		return 1
	}
	cfg, err := deps.loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration: %v\n", err)
		return 2
	}
	if *checkConfig {
		return 0
	}
	application, err := deps.newApp(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "initialize service: %v\n", err)
		return 1
	}
	defer application.Close()
	ctx, cancel := deps.context()
	defer cancel()
	if err := application.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "run service: %v\n", err)
		return 1
	}
	return 0
}
