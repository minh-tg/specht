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
			fmt.Fprintf(d.Out, "Project Stats for %s:\n", args[0])
			fmt.Fprintf(d.Out, "  Total Findings:  %d\n", stats.TotalFindings)
			fmt.Fprintf(d.Out, "  Blocking:        %d\n", stats.BlockingCount)
			fmt.Fprintf(d.Out, "  Active Waivers:  %d\n", stats.WaiverCount)
			fmt.Fprintf(d.Out, "  Reports:         %d\n", stats.ReportCount)
			fmt.Fprintln(d.Out, "  By Severity:")
			for _, s := range stats.BySeverity {
				fmt.Fprintf(d.Out, "    %s: %d total, %d blocking\n", s.Severity, s.Count, s.BlockingCount)
			}
			if stats.LatestReport != nil {
				fmt.Fprintf(d.Out, "  Latest Scan:     %s by %s (%s)\n",
					stats.LatestReport.ID, stats.LatestReport.ToolName, stats.LatestReport.Status)
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
			fmt.Fprintf(d.Out, "Aging for %s (SLA: critical 7d, high 30d, medium 90d, low 180d):\n", args[0])
			for _, b := range aging.Buckets {
				fmt.Fprintf(d.Out, "  %-6s %4d finding(s), %d overdue\n", b.Bucket, b.Count, b.Overdue)
			}
			fmt.Fprintf(d.Out, "  reopened ever: %d\n", aging.Reopened)
			if len(aging.Overdue) > 0 {
				fmt.Fprintln(d.Out, "  Oldest overdue:")
				for _, o := range aging.Overdue {
					fmt.Fprintf(d.Out, "    %s [%s] %dd (SLA %dd, due %s)%s\n",
						o.Title, o.Severity, o.AgeDays, o.SLADays,
						o.DueDate.Format("2006-01-02"), reopenedMark(o.Reopened))
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
