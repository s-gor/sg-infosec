package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/s-gor/sg-infosec/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		if err := json.NewEncoder(stdout).Encode(buildinfo.Info()); err != nil {
			fmt.Fprintf(stderr, "encode version: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stderr, "command handling is not implemented")
	return 2
}
