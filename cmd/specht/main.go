package main

import (
	"os"

	"github.com/minh-tg/specht/cmd/specht/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], cli.DefaultDeps()))
}
