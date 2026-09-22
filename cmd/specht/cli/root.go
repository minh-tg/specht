// Package cli implements the specht command-line interface as a Cobra
// command tree. Commands are thin: parse flags, call client.Client,
// format the result to Deps.Out. Exit-code mapping lives in Execute so
// command paths stay testable without os.Exit.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/xMinhx/specht/internal/client"
)

// ErrThresholdBreached signals a breached gate check. Execute maps it to
// exit code 1 without an error message; all other errors map to exit 2.
var ErrThresholdBreached = errors.New("gate threshold breached")

const (
	exitPass    = 0
	exitBreach  = 1
	exitFailure = 2
)

// Deps carries command dependencies. Out and ErrW are injectable so
// commands are testable with buffers.
type Deps struct {
	NewClient func() (*client.Client, error)
	Out       io.Writer
	ErrW      io.Writer
}

// settings holds flag values shared across the tree.
type settings struct {
	format string
}

// DefaultDeps wires the production dependencies from the environment:
// API_URL (default http://localhost:8080) and the required API_KEY.
func DefaultDeps() Deps {
	return Deps{
		NewClient: func() (*client.Client, error) {
			apiURL := os.Getenv("API_URL")
			if apiURL == "" {
				apiURL = "http://localhost:8080"
			}
			token := os.Getenv("API_KEY")
			if token == "" {
				return nil, errors.New("API_KEY environment variable is required")
			}
			return client.New(apiURL, client.WithToken(token)), nil
		},
		Out:  os.Stdout,
		ErrW: os.Stderr,
	}
}

// NewRootCmd builds the command tree. Groups are registered in their own
// files (projects.go, findings.go, ...).
func NewRootCmd(d Deps) *cobra.Command {
	s := &settings{}
	root := &cobra.Command{
		Use:           "specht",
		Short:         "Unified vulnerability management for SCA, SAST, and IaC",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	root.AddCommand(newProjectsCmd(d, s))
	root.AddCommand(newFindingsCmd(d, s))
	root.AddCommand(newGateCmd(d, s))
	root.AddCommand(newStatsCmd(d, s))
	root.AddCommand(newPrCmd(d, s))
	root.AddCommand(newPatchCmd(d, s))
	root.AddCommand(newNotifyCmd(d, s))
	root.AddCommand(newAdminCmd(d, s))
	// TEMP newPolicyCmd
	return root
}

// Execute runs the tree with args and maps the result to a process exit
// code: 0 pass, 1 gate breached, 2 usage or runtime error.
func Execute(args []string, d Deps) int {
	root := NewRootCmd(d)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		if errors.Is(err, ErrThresholdBreached) {
			return exitBreach
		}
		fmt.Fprintf(d.ErrW, "error: %v\n", err)
		return exitFailure
	}
	return exitPass
}
