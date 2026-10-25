package cli

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newFindingsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Manage findings",
	}
	cmd.AddCommand(
		newFindingsListCmd(d, s),
		newFindingsGetCmd(d, s),
		newFindingsVerifyCmd(d, s),
		newFindingsReachabilityCmd(d, s),
		newFindingsTriageCmd(d, s),
		newFindingsBulkTriageCmd(d, s),
		newFindingsEventsCmd(d, s),
	)
	return cmd
}

func newFindingsListCmd(d Deps, s *settings) *cobra.Command {
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
			findings, err := listAllFindings(cl, project, severities, statuses, limit)
			if err != nil {
				return err
			}
			return emit(d, s, findings, func(w io.Writer) error {
				if len(findings) == 0 {
					_, err := fmt.Fprintln(w, "No findings found.")
					return err
				}
				for _, f := range findings {
					score := ""
					if f.CurrentScore != nil {
						score = fmt.Sprintf("%.1f", *f.CurrentScore)
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.CurrentSeverity, f.CurrentTitle, f.AnalysisState, f.GateEffect, score); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project slug")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity")
	cmd.Flags().StringVar(&status, "status", "", "filter by status")
	cmd.Flags().StringVar(&limitStr, "limit", "", "maximum findings to return (default: all, fetched 500 per request)")
	return cmd
}

// findingsPageSize is the largest page the server returns for one request.
const findingsPageSize = 500

// listAllFindings requests pages of findingsPageSize until a short page, so
// the server's default page of 20 and its 500-row ceiling do not truncate the
// result. A positive limit caps the total; 0 means every finding.
func listAllFindings(cl *client.Client, project string, severities, statuses []string, limit int) ([]client.Finding, error) {
	all := []client.Finding{}
	for {
		size := findingsPageSize
		if limit > 0 {
			size = min(size, limit-len(all))
		}
		// The server's offset is an int32, so paging stops there too.
		if size <= 0 || len(all) > math.MaxInt32-findingsPageSize {
			return all, nil
		}
		page, err := cl.ListFindings(project, severities, statuses, int32(size), int32(len(all)))
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < size {
			return all, nil
		}
	}
}

func newFindingsGetCmd(d Deps, s *settings) *cobra.Command {
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
			return emit(d, s, f, func(w io.Writer) error {
				score := ""
				if f.CurrentScore != nil {
					score = fmt.Sprintf("%.1f", *f.CurrentScore)
				}
				if _, err := fmt.Fprintf(w, "ID:           %s\nTitle:        %s\nSeverity:     %s\nScore:        %s\nState:        %s\nAnalysis:     %s\nGate Effect:  %s\nFingerprint:  %s\nKind:         %s\n", f.ID, f.CurrentTitle, f.CurrentSeverity, score, f.State, f.AnalysisState, f.GateEffect, f.Fingerprint, f.FindingKind); err != nil {
					return err
				}
				introduced := "unattributed"
				if f.IntroducedCommitSha != nil && *f.IntroducedCommitSha != "" {
					introduced = *f.IntroducedCommitSha
				}
				_, err := fmt.Fprintf(w, "Introduced:   %s\n", introduced)
				return err
			})
		},
	}
}

func newFindingsVerifyCmd(d Deps, s *settings) *cobra.Command {
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
			return emit(d, s, res, func(w io.Writer) error {
				if _, err := fmt.Fprintf(w, "finding %s: %s\n", res.FindingID, res.Outcome); err != nil {
					return err
				}
				if res.ReportID != nil {
					if _, err := fmt.Fprintf(w, "report: %s\n", *res.ReportID); err != nil {
						return err
					}
				}
				_, err := fmt.Fprintf(w, "detail: %s\n", res.Detail)
				return err
			})
		},
	}
}

func newFindingsReachabilityCmd(d Deps, s *settings) *cobra.Command {
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
				return emit(d, s, assess, func(w io.Writer) error {
					_, err := fmt.Fprintf(w, "reachability set: finding=%s state=%s evidence=%q\n", assess.FindingID, assess.State, assess.Evidence)
					return err
				})
			}
			history, err := cl.ListReachability(findingID)
			if err != nil {
				return err
			}
			return emit(d, s, history, func(w io.Writer) error {
				if len(history) == 0 {
					_, err := fmt.Fprintln(w, "no reachability assessments for finding")
					return err
				}
				for _, a := range history {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.CreatedAt, a.State, a.AssessedBy, a.Evidence); err != nil {
						return err
					}
				}
				return nil
			})
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
