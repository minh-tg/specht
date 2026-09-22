package cli

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

func newAdminCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Platform administration",
	}
	cmd.AddCommand(newAdminStatusCmd(d, s), newAdminRetentionCmd(d, s))
	return cmd
}

func newAdminStatusCmd(d Deps, s *settings) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Platform observability snapshot (admin only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			status, err := cl.GetAdminStatus()
			if err != nil {
				return err
			}
			if format == "json" {
				raw, err := json.MarshalIndent(status, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(d.Out, string(raw))
				return nil
			}
			fmt.Fprintf(d.Out,
				"projects=%d users=%d open_findings=%d reports=%d\n",
				status.Projects, status.Users, status.OpenFindings, status.Reports,
			)
			return nil
		},
	}
}

func newAdminRetentionCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "retention",
		Short: "Manage settled report retention",
	}
	cmd.AddCommand(newAdminRetentionPreviewCmd(d, s), newAdminRetentionPurgeCmd(d, s))
	return cmd
}

func parseRetentionDays(daysStr string) (int, error) {
	days := 0
	if daysStr != "" {
		n, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid --days %q: want a positive integer", daysStr)
		}
		days = n
	}
	if days <= 0 {
		return 0, fmt.Errorf("--days is required for admin retention (positive integer)")
	}
	return days, nil
}

func retentionFormat(s *settings) (string, error) {
	format := s.format
	if format == "" {
		format = "human"
	}
	if format != "human" && format != "json" {
		return "", fmt.Errorf("invalid --format %q: want human or json", format)
	}
	return format, nil
}

func newAdminRetentionPreviewCmd(d Deps, s *settings) *cobra.Command {
	var daysStr string
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Count settled reports a purge would delete",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			days, err := parseRetentionDays(daysStr)
			if err != nil {
				return err
			}
			format, err := retentionFormat(s)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			preview, err := cl.PreviewRetention(days)
			if err != nil {
				return err
			}
			if format == "json" {
				raw, err := json.MarshalIndent(preview, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(d.Out, string(raw))
				return nil
			}
			fmt.Fprintf(d.Out, "%d settled report(s) older than %d day(s) would be deleted\n", preview.StaleReports, preview.OlderThanDays)
			return nil
		},
	}
	cmd.Flags().StringVar(&daysStr, "days", "", "retention window in days")
	return cmd
}

func newAdminRetentionPurgeCmd(d Deps, s *settings) *cobra.Command {
	var daysStr string
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete settled reports older than the window",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			days, err := parseRetentionDays(daysStr)
			if err != nil {
				return err
			}
			format, err := retentionFormat(s)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			result, err := cl.PurgeRetention(days)
			if err != nil {
				return err
			}
			if format == "json" {
				raw, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(d.Out, string(raw))
				return nil
			}
			fmt.Fprintf(d.Out, "deleted %d settled report(s) older than %d day(s)\n", result.DeletedReports, result.OlderThanDays)
			return nil
		},
	}
	cmd.Flags().StringVar(&daysStr, "days", "", "retention window in days")
	return cmd
}
