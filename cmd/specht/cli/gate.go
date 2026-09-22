package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/xMinhx/specht/internal/client"
)

func newGateCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Evaluate project gates",
	}
	cmd.AddCommand(newGateCheckCmd(d, s))
	return cmd
}

func newGateCheckCmd(d Deps, s *settings) *cobra.Command {
	var project, severity, reportID string
	var introducedOnly bool
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check project gate status",
		Args:  cobra.NoArgs,
		// Execute maps RunE errors to exit codes itself (breach → 1,
		// anything else → 2 with "error: ..." on stderr), so Cobra must
		// stay silent: otherwise a breach would also dump "Error:" plus
		// usage text, breaking the CI output contract.
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required for gate check")
			}
			if introducedOnly && reportID == "" {
				return fmt.Errorf("--report-id is required with --introduced-only")
			}
			format := s.format
			if format == "" {
				format = "human"
			}
			if format != "human" && format != "json" {
				return fmt.Errorf("invalid --format %q: want human or json", format)
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			var gs *client.GateStatus
			if introducedOnly {
				gs, err = cl.GetIntroducedGateStatus(project, severity, reportID)
			} else {
				gs, err = cl.GetGateStatus(project, severity)
			}
			if err != nil {
				return err
			}
			out, err := formatGateStatus(gs, format)
			if err != nil {
				return err
			}
			fmt.Fprintln(d.Out, out)
			if gs.ThresholdBreached {
				return ErrThresholdBreached
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project slug")
	cmd.Flags().StringVar(&severity, "severity", "", "severity threshold")
	cmd.Flags().BoolVar(&introducedOnly, "introduced-only", false, "evaluate only findings introduced by a report")
	cmd.Flags().StringVar(&reportID, "report-id", "", "report ID for --introduced-only")
	return cmd
}

// formatGateStatus renders a gate evaluation for CLI output. "human" is the
// concise log-friendly summary; "json" is the machine-readable form for CI
// automation (struct field order, so output is deterministic).
func formatGateStatus(gs *client.GateStatus, format string) (string, error) {
	switch format {
	case "", "human":
		return formatGateHuman(gs), nil
	case "json":
		buf, err := json.Marshal(gs)
		if err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("invalid --format %q: want human or json", format)
	}
}

func formatGateHuman(gs *client.GateStatus) string {
	var b strings.Builder
	if gs.ThresholdBreached {
		fmt.Fprintf(&b, "gate FAILED: %d blocking finding(s)\n", gs.BlockingCount)
		for _, id := range gs.BlockedBy {
			reach := "unknown"
			if r, ok := gs.BlockedByReachability[id]; ok && r != "" {
				reach = r
			}
			fmt.Fprintf(&b, "  blocked by: %s (reachability: %s)\n", id, reach)
		}
	} else {
		b.WriteString("gate PASSED: no blocking findings\n")
	}
	if gs.WaivedCount > 0 {
		fmt.Fprintf(&b, "  waived: %d finding(s) excluded by active waivers\n", gs.WaivedCount)
	}
	return strings.TrimSuffix(b.String(), "\n")
}
