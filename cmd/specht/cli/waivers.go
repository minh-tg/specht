package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newWaiversCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waivers",
		Short: "Manage waivers",
		Long: "Manage waivers: reviewed exceptions that keep chosen findings out of the gate for a while.\n" +
			"Anyone with access can request one; a project manager or admin approves or creates it.",
	}
	cmd.AddCommand(
		newWaiversListCmd(d, s),
		newWaiversGetCmd(d, s),
		newWaiversCreateCmd(d, s),
		newWaiversRequestCmd(d, s),
		newWaiverDecisionCmd(d, s, "approve", "Approve a waiver request", func(cl *client.Client, project, id, note string) (*client.Waiver, error) {
			return cl.ApproveWaiver(project, id, note)
		}, true),
		newWaiverDecisionCmd(d, s, "reject", "Reject a waiver request", func(cl *client.Client, project, id, note string) (*client.Waiver, error) {
			return cl.RejectWaiver(project, id, note)
		}, true),
		newWaiverDecisionCmd(d, s, "withdraw", "Withdraw your own waiver request", func(cl *client.Client, project, id, _ string) (*client.Waiver, error) {
			return cl.WithdrawWaiver(project, id)
		}, false),
		newWaiverDecisionCmd(d, s, "toggle", "Turn a waiver on or off", func(cl *client.Client, project, id, _ string) (*client.Waiver, error) {
			return cl.ToggleWaiver(project, id)
		}, false),
		newWaiversDeleteCmd(d),
		newWaiversEventsCmd(d, s),
	)
	return cmd
}

const flagWaiverIDUsage = "waiver ID"

// requireProjectAndID reports whichever of --project and --id is missing.
func requireProjectAndID(project, id, subcommand string) error {
	if err := requireFlag(project, "--project", subcommand); err != nil {
		return err
	}
	return requireFlag(id, "--id", subcommand)
}

func expiryText(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func enabledText(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func newWaiversListCmd(d Deps, s *settings) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's waivers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "waivers list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			waivers, err := cl.ListWaivers(project)
			if err != nil {
				return err
			}
			return emit(d, s, waivers, func(w io.Writer) error {
				if len(waivers) == 0 {
					_, err := fmt.Fprintln(w, "No waivers.")
					return err
				}
				for _, wv := range waivers {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", wv.ID, wv.Status, enabledText(wv.Enabled), wv.Name, expiryText(wv.ExpiresAt)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	return cmd
}

func newWaiversGetCmd(d Deps, s *settings) *cobra.Command {
	var project, id string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Show one waiver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectAndID(project, id, "waivers get"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			wv, err := cl.GetWaiver(project, id)
			if err != nil {
				return err
			}
			return emit(d, s, wv, func(w io.Writer) error {
				if _, err := fmt.Fprintf(w, "ID:          %s\nName:        %s\nStatus:      %s (%s)\nExpires:     %s\n",
					wv.ID, wv.Name, wv.Status, enabledText(wv.Enabled), expiryText(wv.ExpiresAt)); err != nil {
					return err
				}
				if wv.Description != "" {
					if _, err := fmt.Fprintf(w, "Description: %s\n", wv.Description); err != nil {
						return err
					}
				}
				if wv.Reason != "" {
					if _, err := fmt.Fprintf(w, "Reason:      %s\n", wv.Reason); err != nil {
						return err
					}
				}
				if wv.DecisionNote != "" {
					if _, err := fmt.Fprintf(w, "Decision:    %s\n", wv.DecisionNote); err != nil {
						return err
					}
				}
				if wv.ScopeAll {
					if _, err := fmt.Fprintln(w, "Covers:      every finding of the project"); err != nil {
						return err
					}
				}
				for _, c := range wv.Conditions {
					if _, err := fmt.Fprintf(w, "Covers:      %s %s %s\n", c.Field, c.Operator, c.Value); err != nil {
						return err
					}
				}
				for _, t := range wv.Targets {
					if _, err := fmt.Fprintf(w, "Covers:      finding %s\n", t.FindingID); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", flagWaiverIDUsage)
	return cmd
}

func newWaiversCreateCmd(d Deps, s *settings) *cobra.Command {
	var project, name, description, scope, expires string
	var findings, conditions []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an approved waiver (project manager or admin)",
		Long: "Create an approved waiver. It covers the findings named with --finding, the findings that match\n" +
			"every --condition (field:operator:value, for example severity:eq:low), or every finding of the\n" +
			"project with --scope all.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "waivers create"); err != nil {
				return err
			}
			if err := requireFlag(name, "--name", "waivers create"); err != nil {
				return err
			}
			req := &client.CreateWaiverRequest{Name: name, Description: description, Scope: scope, TargetIDs: splitIDs(findings)}
			for _, c := range conditions {
				parsed, err := parseCondition(c)
				if err != nil {
					return err
				}
				req.Conditions = append(req.Conditions, parsed)
			}
			if expires != "" {
				when, err := parseWhen("--expires", expires)
				if err != nil {
					return err
				}
				req.ExpiresAt = when.UTC().Format(time.RFC3339)
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			wv, err := cl.CreateWaiver(project, req)
			if err != nil {
				return err
			}
			return writeWaiver(d, s, wv)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&name, "name", "", "waiver name")
	cmd.Flags().StringVar(&description, "description", "", "what it is for")
	cmd.Flags().StringVar(&scope, "scope", "", "all, for a waiver that covers every finding of the project")
	cmd.Flags().StringSliceVar(&findings, "finding", nil, "finding ID to cover; repeat or separate with commas")
	cmd.Flags().StringSliceVar(&conditions, "condition", nil, "field:operator:value a finding must match; repeatable")
	cmd.Flags().StringVar(&expires, "expires", "", "when the waiver lapses: 2026-12-31 or an RFC 3339 time")
	return cmd
}

func newWaiversRequestCmd(d Deps, s *settings) *cobra.Command {
	var project, reason, expires string
	var findings []string
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Ask for a waiver on some findings",
		Long: "Ask for a waiver on the findings named with --finding. A project manager or admin approves or rejects it.\n" +
			"--expires is required and at most 90 days ahead.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "waivers request"); err != nil {
				return err
			}
			ids := splitIDs(findings)
			if len(ids) == 0 {
				return fmt.Errorf("--finding is required for waivers request")
			}
			if err := requireFlag(reason, "--reason", "waivers request"); err != nil {
				return err
			}
			if err := requireFlag(expires, "--expires", "waivers request"); err != nil {
				return err
			}
			when, err := parseWhen("--expires", expires)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			wv, err := cl.RequestWaiver(project, &client.RequestWaiverRequest{
				TargetIDs: ids,
				Reason:    reason,
				ExpiresAt: when.UTC().Format(time.RFC3339),
			})
			if err != nil {
				return err
			}
			return writeWaiver(d, s, wv)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringSliceVar(&findings, "finding", nil, "finding ID to cover; repeat or separate with commas")
	cmd.Flags().StringVar(&reason, "reason", "", "why the findings should be waived")
	cmd.Flags().StringVar(&expires, "expires", "", "when the waiver lapses: 2026-12-31 or an RFC 3339 time")
	return cmd
}

// newWaiverDecisionCmd builds the commands that act on one waiver and return it:
// approve, reject, withdraw and toggle. Only approve and reject take a note.
func newWaiverDecisionCmd(d Deps, s *settings, use, short string, act func(cl *client.Client, project, id, note string) (*client.Waiver, error), takesNote bool) *cobra.Command {
	var project, id, note string
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectAndID(project, id, "waivers "+use); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			wv, err := act(cl, project, id, note)
			if err != nil {
				return err
			}
			return writeWaiver(d, s, wv)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", flagWaiverIDUsage)
	if takesNote {
		cmd.Flags().StringVar(&note, "note", "", "a note for the record")
	}
	return cmd
}

func newWaiversDeleteCmd(d Deps) *cobra.Command {
	var project, id string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a waiver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectAndID(project, id, "waivers delete"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.DeleteWaiver(project, id); err != nil {
				return err
			}
			_, err = fmt.Fprintln(d.Out, "waiver deleted")
			return err
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", flagWaiverIDUsage)
	return cmd
}

func newWaiversEventsCmd(d Deps, s *settings) *cobra.Command {
	var project, id string
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Show a waiver's history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectAndID(project, id, "waivers events"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			events, err := cl.ListWaiverEvents(project, id)
			if err != nil {
				return err
			}
			return emit(d, s, events, func(w io.Writer) error {
				if len(events) == 0 {
					_, err := fmt.Fprintln(w, "No events.")
					return err
				}
				for _, e := range events {
					who := e.ActorName
					if who == "" {
						who = e.ActorID
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", e.CreatedAt, e.EventType, who); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", flagWaiverIDUsage)
	return cmd
}

func writeWaiver(d Deps, s *settings, wv *client.Waiver) error {
	return emit(d, s, wv, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "%s\t%s\t%s\n", wv.ID, wv.Status, wv.Name)
		return err
	})
}

// parseCondition reads field:operator:value. The value may itself contain colons.
func parseCondition(raw string) (client.CreateWaiverCondition, error) {
	parts := strings.SplitN(raw, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return client.CreateWaiverCondition{}, fmt.Errorf("--condition %q is not field:operator:value, for example severity:eq:low", raw)
	}
	return client.CreateWaiverCondition{Field: parts[0], Operator: parts[1], Value: parts[2]}, nil
}
