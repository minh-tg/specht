package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStatsCmd(d Deps, _ *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show project statistics and aging",
	}
	cmd.AddCommand(newStatsShowCmd(d), newStatsAgingCmd(d))
	return cmd
}

func newStatsShowCmd(d Deps) *cobra.Command {
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
			if _, err := fmt.Fprintf(d.Out, "Project Stats for %s:\n", args[0]); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(d.Out, "  Total Findings:  %d\n", stats.TotalFindings); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(d.Out, "  Blocking:        %d\n", stats.BlockingCount); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(d.Out, "  Active Waivers:  %d\n", stats.WaiverCount); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(d.Out, "  Reports:         %d\n", stats.ReportCount); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(d.Out, "  By Severity:"); err != nil {
				return err
			}
			for _, s := range stats.BySeverity {
				if _, err := fmt.Fprintf(d.Out, "    %s: %d total, %d blocking\n", s.Severity, s.Count, s.BlockingCount); err != nil {
					return err
				}
			}
			if stats.LatestReport != nil {
				if _, err := fmt.Fprintf(d.Out, "  Latest Scan:     %s by %s (%s)\n",
					stats.LatestReport.ID, stats.LatestReport.ToolName, stats.LatestReport.Status); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newStatsAgingCmd(d Deps) *cobra.Command {
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
			if _, err := fmt.Fprintf(d.Out, "Aging for %s (SLA: critical 7d, high 30d, medium 90d, low 180d):\n", args[0]); err != nil {
				return err
			}
			for _, b := range aging.Buckets {
				if _, err := fmt.Fprintf(d.Out, "  %-6s %4d finding(s), %d overdue\n", b.Bucket, b.Count, b.Overdue); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(d.Out, "  reopened ever: %d\n", aging.Reopened); err != nil {
				return err
			}
			if len(aging.Overdue) > 0 {
				if _, err := fmt.Fprintln(d.Out, "  Oldest overdue:"); err != nil {
					return err
				}
				for _, o := range aging.Overdue {
					if _, err := fmt.Fprintf(d.Out, "    %s [%s] %dd (SLA %dd, due %s)%s\n",
						o.Title, o.Severity, o.AgeDays, o.SLADays,
						o.DueDate.Format("2006-01-02"), reopenedMark(o.Reopened)); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
}

func reopenedMark(reopened bool) string {
	if reopened {
		return " (reopened)"
	}
	return ""
}
