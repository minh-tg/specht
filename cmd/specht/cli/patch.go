package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/xMinhx/specht/internal/client"
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
			if err := requireFlag(findingID, "--finding", "patch preview"); err != nil {
				return err
			}
			format, err := resolveFormat(s)
			if err != nil {
				return err
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
				return writeJSONOut(d.Out, outcome)
			}
			return renderPatchPreview(d.Out, outcome)
		},
	}
	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID")
	return cmd
}

// renderPatchPreview prints the human-readable form of a patch preview.
func renderPatchPreview(out io.Writer, outcome *client.PatchOutcome) error {
	if !outcome.Supported || outcome.Proposal == nil {
		_, err := fmt.Fprintf(out, "no patch: %s\n", outcome.Reason)
		return err
	}
	p := outcome.Proposal
	if _, err := fmt.Fprintf(out, "patch %s (%s, confidence %s)\n%s\n", p.ID, p.Class, p.Confidence, p.Rationale); err != nil {
		return err
	}
	for _, e := range p.Edits {
		if _, err := fmt.Fprintf(out, "  %s %s %s %s -> %s\n", e.Operation, e.File, e.Package, e.FromVersion, e.ToVersion); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(out, "verify: %s\n", p.VerifyBy)
	return err
}
