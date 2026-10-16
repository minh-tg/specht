package cli

import (
	"fmt"
	"io"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newUsersCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage accounts (admin, with a signed-in session)",
		Long:  "Manage accounts. These routes need an admin's session token, not a project API key.",
	}
	cmd.AddCommand(
		newUsersListCmd(d, s),
		newUsersRoleCmd(d, s),
		newUsersResetLinkCmd(d, s),
		newUserSwitchCmd(d, s, "deactivate", "Stop an account from signing in, keeping its history", func(cl *client.Client, id string, force bool) (*client.UserProfile, error) {
			return cl.DeactivateUser(id, force)
		}),
		newUserSwitchCmd(d, s, "reactivate", "Let a deactivated account sign in again", func(cl *client.Client, id string, _ bool) (*client.UserProfile, error) {
			return cl.ReactivateUser(id)
		}),
	)
	return cmd
}

func writeUser(w io.Writer, u client.UserProfile) error {
	state := "active"
	if u.Disabled {
		state = "deactivated"
	}
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.ID, u.Email, u.Role, state)
	return err
}

func newUsersListCmd(d Deps, s *settings) *cobra.Command {
	var email string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List accounts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pageSize, err := limitArg("--limit", limit)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			users, err := cl.ListUsers(email, pageSize, 0)
			if err != nil {
				return err
			}
			return emit(d, s, users, func(w io.Writer) error {
				if len(users) == 0 {
					_, err := fmt.Fprintln(w, "No accounts.")
					return err
				}
				for _, u := range users {
					if err := writeUser(w, u); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "only addresses containing this text")
	cmd.Flags().IntVar(&limit, "limit", 0, "show at most this many accounts (0 for the server's default)")
	return cmd
}

func newUsersRoleCmd(d Deps, s *settings) *cobra.Command {
	var id, role string
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Make an account an admin or a member",
		Long: "Set an account's role to admin or member. The person's open sessions stop and they sign in again to get it.\n" +
			"The last active admin cannot be demoted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(id, "--id", "users role"); err != nil {
				return err
			}
			if err := requireFlag(role, "--role", "users role"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			u, err := cl.ChangeUserRole(id, role)
			if err != nil {
				return err
			}
			return emit(d, s, u, func(w io.Writer) error { return writeUser(w, *u) })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "account ID")
	cmd.Flags().StringVar(&role, "role", "", "admin or member")
	return cmd
}

func newUsersResetLinkCmd(d Deps, s *settings) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "reset-link",
		Short: "Make a one-time link that lets a locked-out person choose a new password",
		Long: "Make a link for a person who cannot sign in. Specht sends no email, so pass the link on yourself.\n" +
			"It works once, a new one retires the earlier ones, and it is shown only now.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(id, "--id", "users reset-link"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			link, err := cl.CreatePasswordResetLink(id)
			if err != nil {
				return err
			}
			return emit(d, s, link, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "%s\nExpires %s. It works once; open it on your Specht server.\n", link.Link, link.ExpiresAt)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "account ID")
	return cmd
}

func newUserSwitchCmd(d Deps, s *settings, use, short string, act func(cl *client.Client, id string, force bool) (*client.UserProfile, error)) *cobra.Command {
	var id string
	var force bool
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(id, "--id", "users "+use); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			u, err := act(cl, id, force)
			if err != nil {
				return err
			}
			return emit(d, s, u, func(w io.Writer) error { return writeUser(w, *u) })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "account ID")
	if use == "deactivate" {
		cmd.Flags().BoolVar(&force, "force", false, "deactivate even if the account is the only active admin of a project")
	}
	return cmd
}
