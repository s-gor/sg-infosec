package main

import (
	"os"

	"github.com/s-gor/sg-infosec/internal/web/command"
)

func main() {
	os.Exit(command.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
