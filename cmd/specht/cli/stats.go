package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newStatsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show project statistics and aging",
	}
	cmd.AddCommand(newStatsShowCmd(d, s), newStatsAgingCmd(d, s))
	return cmd
}

func newStatsShowCmd(d Deps, s *settings) *cobra.Command {
	return &cobra.Command{
		Use:   "show <slug>",
		Short: "Show project statistics",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			stats, err := cl.GetProjectStats(args[0])
			if err != nil {
				return err
			}
			return emit(d, s, stats, func(w io.Writer) error {
				if _, err := fmt.Fprintf(w, "Project Stats for %s:\n", args[0]); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "  Total Findings:  %d\n", stats.TotalFindings); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "  Blocking:        %d\n", stats.BlockingCount); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "  Active Waivers:  %d\n", stats.WaiverCount); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "  Pending Requests: %d\n", stats.PendingWaiverCount); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "  Reports:         %d\n", stats.ReportCount); err != nil {
					return err
				}
				if _, err := fmt.Fprintln(w, "  By Severity:"); err != nil {
					return err
				}
				for _, sev := range stats.BySeverity {
					if _, err := fmt.Fprintf(w, "    %s: %d total, %d blocking\n", sev.Severity, sev.Count, sev.BlockingCount); err != nil {
						return err
					}
				}
				if stats.LatestReport != nil {
					if _, err := fmt.Fprintf(w, "  Latest Scan:     %s by %s (%s)\n",
						stats.LatestReport.ID, stats.LatestReport.ToolName, stats.LatestReport.Status); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

func newStatsAgingCmd(d Deps, s *settings) *cobra.Command {
	return &cobra.Command{
		Use:   "aging <slug>",
		Short: "Show aging buckets, SLA overdue, reopened",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			aging, err := cl.GetAging(args[0])
			if err != nil {
				return err
			}
			return emit(d, s, aging, func(w io.Writer) error {
				if _, err := fmt.Fprintf(w, "Aging for %s (SLA: critical 7d, high 30d, medium 90d, low 180d):\n", args[0]); err != nil {
					return err
				}
				for _, b := range aging.Buckets {
					if _, err := fmt.Fprintf(w, "  %-6s %4d finding(s), %d overdue\n", b.Bucket, b.Count, b.Overdue); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprintf(w, "  reopened ever: %d\n", aging.Reopened); err != nil {
					return err
				}
				if aging.Truncated {
					if _, err := fmt.Fprintln(w, "  note: more open findings than the report evaluates; these numbers cover the oldest ones"); err != nil {
						return err
					}
				}
				if len(aging.Overdue) > 0 {
					if _, err := fmt.Fprintln(w, "  Oldest overdue:"); err != nil {
						return err
					}
					for _, o := range aging.Overdue {
						if _, err := fmt.Fprintf(w, "    %s [%s] %dd (SLA %dd, due %s)%s\n",
							o.Title, o.Severity, o.AgeDays, o.SLADays,
							o.DueDate.Format("2006-01-02"), reopenedMark(o.Reopened)); err != nil {
							return err
						}
					}
				}
				return nil
			})
		},
	}
}

func reopenedMark(reopened bool) string {
	if reopened {
		return " (reopened)"
	}
	return ""
}
