package cli

import (
	"fmt"
	"io"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newNotifyCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Tracker and messaging actions",
	}
	cmd.AddCommand(newNotifyPreviewCmd(d, s))
	return cmd
}

// notifyPreviewCmd is the subcommand name shared by its flag requirements.
const notifyPreviewCmd = "notify preview"

func newNotifyPreviewCmd(d Deps, s *settings) *cobra.Command {
	var findingID, channel, target string
	var linked bool
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview tracker/messaging action (dry-run; sends nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(findingID, "--finding", notifyPreviewCmd); err != nil {
				return err
			}
			if err := requireFlag(channel, "--channel", notifyPreviewCmd); err != nil {
				return err
			}
			if err := requireFlag(target, "--target", notifyPreviewCmd); err != nil {
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
			notification, err := cl.PreviewNotification(findingID, channel, target, linked)
			if err != nil {
				return err
			}
			if format == "json" {
				return writeJSONOut(d.Out, notification)
			}
			return renderNotifyPreview(d.Out, notification)
		},
	}
	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID")
	cmd.Flags().StringVar(&channel, "channel", "", "channel: issue or message")
	cmd.Flags().StringVar(&target, "target", "", "integration and scope target")
	cmd.Flags().BoolVar(&linked, "linked", false, "include already-linked context")
	return cmd
}

// renderNotifyPreview prints the human-readable form of a notify preview.
func renderNotifyPreview(out io.Writer, notification *client.NotifyOutcome) error {
	if !notification.Supported || notification.Plan == nil {
		_, err := fmt.Fprintf(out, "no notification: %s\n", notification.Reason)
		return err
	}
	plan := notification.Plan
	if _, err := fmt.Fprintf(out, "notify %s (%s -> %s): %s\n%s\n", plan.ID, plan.Channel, plan.Target, plan.Title, plan.Body); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "dedupe: %s\n", plan.DedupeKey)
	return err
}
