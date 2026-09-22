package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newPrCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pr",
		Short: "Pull-request checks",
	}
	cmd.AddCommand(newPrPreviewCmd(d, s))
	return cmd
}

func newPrPreviewCmd(d Deps, s *settings) *cobra.Command {
	var project, commit, provider, reportID, severity string
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview pull-request check (dry-run; publishes nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required for pr preview")
			}
			if commit == "" {
				return fmt.Errorf("--commit is required for pr preview")
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
			preview, err := cl.PreviewPRCheck(project, commit, provider, reportID, severity)
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
			fmt.Fprintf(d.Out, "check %s: %s\n%s\n", preview.Conclusion, preview.Title, preview.Summary)
			for _, a := range preview.Annotations {
				fmt.Fprintf(d.Out, "  %s:%d %s\n", a.File, a.StartLine, a.Title)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project slug")
	cmd.Flags().StringVar(&commit, "commit", "", "commit SHA")
	cmd.Flags().StringVar(&provider, "provider", "", "provider name")
	cmd.Flags().StringVar(&reportID, "report-id", "", "report ID")
	cmd.Flags().StringVar(&severity, "severity", "", "severity threshold")
	return cmd
}
