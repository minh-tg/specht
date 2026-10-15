package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newInvitesCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "invites",
		Short: "Manage a project's invite links (project manager, with a signed-in session)",
		Long: "Invite links add whoever opens them to a project. They need a signed-in session, not a project API key.\n" +
			"Specht sends no email: pass a link on yourself.",
	}
	cmd.AddCommand(newInvitesListCmd(d, s), newInvitesCreateCmd(d, s), newInvitesRevokeCmd(d))
	return cmd
}

func newInvitesListCmd(d Deps, s *settings) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's open invite links",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "invites list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			invites, err := cl.ListInvites(project)
			if err != nil {
				return err
			}
			return emit(d, s, invites, func(w io.Writer) error {
				if len(invites) == 0 {
					_, err := fmt.Fprintln(w, "No open invites.")
					return err
				}
				for _, i := range invites {
					who := i.Email
					if who == "" {
						who = "anyone"
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", i.ID, i.Role, who, i.ExpiresAt); err != nil {
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

func newInvitesCreateCmd(d Deps, s *settings) *cobra.Command {
	var project, role, email string
	var days int
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Make an invite link",
		Long: "Make a link that adds whoever opens it to the project as a member or manager. With --email only that\n" +
			"address can accept it. It lasts 7 days unless --days says otherwise (1 to 30), and is shown only now.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "invites create"); err != nil {
				return err
			}
			if err := requireFlag(role, "--role", "invites create"); err != nil {
				return err
			}
			if days < 0 {
				return fmt.Errorf("--days must not be negative")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			inv, err := cl.CreateInvite(project, role, email, days)
			if err != nil {
				return err
			}
			return emit(d, s, inv, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "%s\nExpires %s. This link is shown once; send it to the person yourself.\n", inv.Link, inv.ExpiresAt)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&role, "role", "", "member or manager")
	cmd.Flags().StringVar(&email, "email", "", "only this address can accept")
	cmd.Flags().IntVar(&days, "days", 0, "days until it expires, 1 to 30 (0 for 7)")
	return cmd
}

func newInvitesRevokeCmd(d Deps) *cobra.Command {
	var project, id string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Stop an invite link from working",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "invites revoke"); err != nil {
				return err
			}
			if err := requireFlag(id, "--id", "invites revoke"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.RevokeInvite(project, id); err != nil {
				return err
			}
			_, err = fmt.Fprintln(d.Out, "invite revoked")
			return err
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", "invite ID")
	return cmd
}
