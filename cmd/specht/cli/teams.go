package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newTeamsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "teams",
		Short: "Manage teams",
	}
	cmd.AddCommand(
		newTeamsListCmd(d, s),
		newTeamsCreateCmd(d, s),
		newTeamsDeleteCmd(d),
		newTeamsMembersCmd(d, s),
		newTeamsAddCmd(d, s),
		newTeamsRemoveCmd(d),
	)
	return cmd
}

func newTeamsListCmd(d Deps, s *settings) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List teams",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			teams, err := cl.ListTeams()
			if err != nil {
				return err
			}
			return emit(d, s, teams, func(w io.Writer) error {
				if len(teams) == 0 {
					_, err := fmt.Fprintln(w, "No teams.")
					return err
				}
				for _, team := range teams {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", team.Name, team.ID, team.Description); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
}

func newTeamsCreateCmd(d Deps, s *settings) *cobra.Command {
	var name, description string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a team",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required for teams create")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			team, err := cl.CreateTeam(name, description)
			if err != nil {
				return err
			}
			return emit(d, s, team, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "team %s (%s)\n", team.Name, team.ID)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "team name")
	cmd.Flags().StringVar(&description, "description", "", "team description")
	return cmd
}

func newTeamsDeleteCmd(d Deps) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a team",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return fmt.Errorf("--id is required for teams delete")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.DeleteTeam(id); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(d.Out, "team deleted"); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", flagTeamIDUsage)
	return cmd
}

func newTeamsMembersCmd(d Deps, s *settings) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "members",
		Short: "List team members",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return fmt.Errorf("--id is required for teams members")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			members, err := cl.ListTeamMembers(id)
			if err != nil {
				return err
			}
			return emit(d, s, members, func(w io.Writer) error {
				if len(members) == 0 {
					_, err := fmt.Fprintln(w, "No members.")
					return err
				}
				for _, member := range members {
					// The server withholds addresses from people who do not manage the team.
					label := member.UserEmail
					if label == "" {
						label = member.DisplayName
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\n", label, member.UserID, member.Role); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", flagTeamIDUsage)
	return cmd
}

func newTeamsAddCmd(d Deps, s *settings) *cobra.Command {
	var id, user, role string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a team member",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" || user == "" || role == "" {
				return fmt.Errorf("--id, --user, and --role are required for teams add")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			member, err := cl.AddTeamMember(id, user, role)
			if err != nil {
				return err
			}
			return emit(d, s, member, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "member %s (%s)\n", member.UserID, member.Role)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", flagTeamIDUsage)
	cmd.Flags().StringVar(&user, "user", "", "user ID")
	cmd.Flags().StringVar(&role, "role", "", "team role")
	return cmd
}

func newTeamsRemoveCmd(d Deps) *cobra.Command {
	var id, user string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a team member",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" || user == "" {
				return fmt.Errorf("--id and --user are required for teams remove")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.RemoveTeamMember(id, user); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(d.Out, "member removed"); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", flagTeamIDUsage)
	cmd.Flags().StringVar(&user, "user", "", "user ID")
	return cmd
}
