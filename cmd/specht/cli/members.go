package cli

import (
	"fmt"
	"io"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newMembersCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members",
		Short: "Manage who has access to a project",
	}
	cmd.AddCommand(newMembersListCmd(d, s), newMembersAddCmd(d, s), newMembersRemoveCmd(d))
	return cmd
}

// memberLabel names a member the way the server allows: the address when it is sent, else
// the display name, else the account ID.
func memberLabel(m client.ProjectMember) string {
	switch {
	case m.Email != "":
		return m.Email
	case m.DisplayName != "":
		return m.DisplayName
	}
	return m.UserID
}

func newMembersListCmd(d Deps, s *settings) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's members",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "members list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			members, err := cl.ListProjectMembers(project)
			if err != nil {
				return err
			}
			return emit(d, s, members, func(w io.Writer) error {
				if len(members) == 0 {
					_, err := fmt.Fprintln(w, "No members.")
					return err
				}
				for _, m := range members {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", memberLabel(m), m.UserID, m.Role); err != nil {
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

func newMembersAddCmd(d Deps, s *settings) *cobra.Command {
	var project, user, email, role string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Give a person access to a project (project admin)",
		Long: "Give a person access, or change their role if they already have it. Name them with --email or\n" +
			"--user (an account ID), not both. Roles: admin, manager, member.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "members add"); err != nil {
				return err
			}
			if (user == "") == (email == "") {
				return fmt.Errorf("give --user or --email, and only one, for members add")
			}
			if err := requireFlag(role, "--role", "members add"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			var m *client.ProjectMember
			if email != "" {
				m, err = cl.AddProjectMemberByEmail(project, email, role)
			} else {
				m, err = cl.AddProjectMember(project, user, role)
			}
			if err != nil {
				return err
			}
			return emit(d, s, m, func(w io.Writer) error {
				// The server answers with the membership row only, so name the person by
				// the address that was typed.
				if m.Email == "" {
					m.Email = email
				}
				_, err := fmt.Fprintf(w, "%s\t%s\t%s\n", memberLabel(*m), m.UserID, m.Role)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&user, "user", "", "account ID")
	cmd.Flags().StringVar(&email, "email", "", "the person's email address")
	cmd.Flags().StringVar(&role, "role", "", "admin, manager or member")
	return cmd
}

func newMembersRemoveCmd(d Deps) *cobra.Command {
	var project, user string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Take a person's access to a project away (project admin)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "members remove"); err != nil {
				return err
			}
			if err := requireFlag(user, "--user", "members remove"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.RemoveProjectMember(project, user); err != nil {
				return err
			}
			_, err = fmt.Fprintln(d.Out, "member removed")
			return err
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&user, "user", "", "account ID")
	return cmd
}
