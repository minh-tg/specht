package cli

import (
	"encoding/json"
	"fmt"

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

func newNotifyPreviewCmd(d Deps, s *settings) *cobra.Command {
	var findingID, channel, target string
	var linked bool
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview tracker/messaging action (dry-run; sends nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if findingID == "" {
				return fmt.Errorf("--finding is required for notify preview")
			}
			if channel == "" {
				return fmt.Errorf("--channel is required for notify preview")
			}
			if target == "" {
				return fmt.Errorf("--target is required for notify preview")
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
			notification, err := cl.PreviewNotification(findingID, channel, target, linked)
			if err != nil {
				return err
			}
			if format == "json" {
				raw, err := json.MarshalIndent(notification, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(d.Out, string(raw))
				return nil
			}
			if !notification.Supported || notification.Plan == nil {
				fmt.Fprintf(d.Out, "no notification: %s\n", notification.Reason)
				return nil
			}
			plan := notification.Plan
			fmt.Fprintf(d.Out, "notify %s (%s -> %s): %s\n%s\n", plan.ID, plan.Channel, plan.Target, plan.Title, plan.Body)
			fmt.Fprintf(d.Out, "dedupe: %s\n", plan.DedupeKey)
			return nil
		},
	}
	cmd.Flags().StringVar(&findingID, "finding", "", "finding ID")
	cmd.Flags().StringVar(&channel, "channel", "", "channel: issue or message")
	cmd.Flags().StringVar(&target, "target", "", "integration and scope target")
	cmd.Flags().BoolVar(&linked, "linked", false, "include already-linked context")
	return cmd
}
