package main

import (
	"os"

	"github.com/xMinhx/specht/cmd/specht/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], cli.DefaultDeps()))
}
