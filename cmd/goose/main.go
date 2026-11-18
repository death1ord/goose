// Command goose is a codebase intelligence CLI for Go projects: dead code,
// duplication, complexity, architecture, and a pull-request gate — from one
// graph of the repository.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"goose/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:]))
}
