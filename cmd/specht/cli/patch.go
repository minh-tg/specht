package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newPatchCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patch",
		Short: "Preview safe patches",
	}
	cmd.AddCommand(newPatchPreviewCmd(d, s))
	return cmd
}

func newPatchPreviewCmd(d Deps, s *settings) *cobra.Command {
	var findingID string
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview safe patch (dry-run; applies nothing)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if findingID == "" {
				return fmt.Errorf("--finding is required for patch preview")
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
			outcome, err := cl.PreviewPatch(findingID)
			if err != nil {
				return err
			}
			if format == "json" {
				raw, err := json.MarshalIndent(outcome, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(d.Out, string(raw))
				return nil
			}
			if !outcome.Supported || outcome.Proposal == nil {
				fmt.Fprintf(d.Out, "no patch: %s\n", outcome.Reason)
				return nil
			}
			p := outcome.Proposal
			fmt.Fprintf(d.Out, "patch %s (%s, confidence %s)\n%s\n", p.ID, p.Class, p.Confidence, p.Rationale)
			for _, e := range p.Edits {
				fmt.Fprintf(d.Out, "  %s %s %s %s -> %s\n", e.Operation, e.File, e.Package, e.FromVersion, e.ToVersion)
			}
			fmt.Fprintf(d.Out, "verify: %s\n", p.VerifyBy)
			return nil
		},
	}
	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID")
	return cmd
}
