package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/minh-tg/specht/cmd/specht/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.ExecuteContext(ctx, os.Args[1:], cli.DefaultDeps())
	stop()
	os.Exit(code)
}
