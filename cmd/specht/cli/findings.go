package cli

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func newFindingsCmd(d Deps, _ *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Manage findings",
	}
	cmd.AddCommand(
		newFindingsListCmd(d),
		newFindingsGetCmd(d),
		newFindingsVerifyCmd(d),
		newFindingsReachabilityCmd(d),
	)
	return cmd
}

func newFindingsListCmd(d Deps) *cobra.Command {
	var project, severity, status string
	var limitStr string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "findings list"); err != nil {
				return err
			}
			limit, err := parseLimit(limitStr)
			if err != nil {
				return err
			}
			severities := splitList(severity)
			statuses := splitList(status)
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			findings, err := cl.ListFindings(project, severities, statuses, int32(limit), 0)
			if err != nil {
				return err
			}
			if len(findings) == 0 {
				if _, err := fmt.Fprintln(d.Out, "No findings found."); err != nil {
					return err
				}
				return nil
			}
			for _, f := range findings {
				score := ""
				if f.CurrentScore != nil {
					score = fmt.Sprintf("%.1f", *f.CurrentScore)
				}
				if _, err := fmt.Fprintf(d.Out, "%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.CurrentSeverity, f.CurrentTitle, f.AnalysisState, f.GateEffect, score); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project slug")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity")
	cmd.Flags().StringVar(&status, "status", "", "filter by status")
	cmd.Flags().StringVar(&limitStr, "limit", "", "limit results")
	return cmd
}

func newFindingsGetCmd(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Show one finding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			f, err := cl.GetFinding(args[0])
			if err != nil {
				return err
			}
			score := ""
			if f.CurrentScore != nil {
				score = fmt.Sprintf("%.1f", *f.CurrentScore)
			}
			if _, err := fmt.Fprintf(d.Out, "ID:           %s\nTitle:        %s\nSeverity:     %s\nScore:        %s\nState:        %s\nAnalysis:     %s\nGate Effect:  %s\nFingerprint:  %s\nKind:         %s\n", f.ID, f.CurrentTitle, f.CurrentSeverity, score, f.State, f.AnalysisState, f.GateEffect, f.Fingerprint, f.FindingKind); err != nil {
				return err
			}
			if f.IntroducedCommitSha != nil && *f.IntroducedCommitSha != "" {
				if _, err := fmt.Fprintf(d.Out, "Introduced:   %s\n", *f.IntroducedCommitSha); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintln(d.Out, "Introduced:   unattributed"); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newFindingsVerifyCmd(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "verify <id>",
		Short: "Verify fix against latest rescan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			res, err := cl.VerifyFinding(args[0])
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(d.Out, "finding %s: %s\n", res.FindingID, res.Outcome); err != nil {
				return err
			}
			if res.ReportID != nil {
				if _, err := fmt.Fprintf(d.Out, "report: %s\n", *res.ReportID); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(d.Out, "detail: %s\n", res.Detail); err != nil {
				return err
			}
			return nil
		},
	}
}

func newFindingsReachabilityCmd(d Deps) *cobra.Command {
	var findingID, state, evidence string
	cmd := &cobra.Command{
		Use:   "reachability",
		Short: "List or set reachability assessments",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if findingID == "" {
				return fmt.Errorf("--finding is required for findings reachability")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if state != "" {
				assess, err := cl.UpsertReachability(findingID, state, evidence)
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintf(d.Out, "reachability set: finding=%s state=%s evidence=%q\n", assess.FindingID, assess.State, assess.Evidence); err != nil {
					return err
				}
				return nil
			}
			history, err := cl.ListReachability(findingID)
			if err != nil {
				return err
			}
			if len(history) == 0 {
				if _, err := fmt.Fprintln(d.Out, "no reachability assessments for finding"); err != nil {
					return err
				}
				return nil
			}
			for _, a := range history {
				if _, err := fmt.Fprintf(d.Out, "%s\t%s\t%s\t%s\n", a.CreatedAt, a.State, a.AssessedBy, a.Evidence); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID")
	cmd.Flags().StringVar(&state, "state", "", "reachability state")
	cmd.Flags().StringVar(&evidence, "evidence", "", "reachability evidence")
	return cmd
}

// parseLimit parses the --limit flag: empty means no limit (0).
func parseLimit(limitStr string) (int, error) {
	if limitStr == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(limitStr)
	if err != nil || n < 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("invalid --limit %q: want 0 to %d", limitStr, math.MaxInt32)
	}
	return n, nil
}

// splitList splits a comma-separated flag value; empty means no filter.
func splitList(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}
