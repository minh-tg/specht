package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newTeamsCmd(d Deps, _ *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "teams",
		Short: "Manage teams",
	}
	cmd.AddCommand(
		newTeamsListCmd(d),
		newTeamsCreateCmd(d),
		newTeamsDeleteCmd(d),
		newTeamsMembersCmd(d),
		newTeamsAddCmd(d),
		newTeamsRemoveCmd(d),
	)
	return cmd
}

func newTeamsListCmd(d Deps) *cobra.Command {
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
			if len(teams) == 0 {
				fmt.Fprintln(d.Out, "No teams.")
				return nil
			}
			for _, team := range teams {
				fmt.Fprintf(d.Out, "%s\t%s\t%s\n", team.Name, team.ID, team.Description)
			}
			return nil
		},
	}
}

func newTeamsCreateCmd(d Deps) *cobra.Command {
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
			fmt.Fprintf(d.Out, "team %s (%s)\n", team.Name, team.ID)
			return nil
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
			fmt.Fprintln(d.Out, "team deleted")
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "team ID")
	return cmd
}

func newTeamsMembersCmd(d Deps) *cobra.Command {
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
			if len(members) == 0 {
				fmt.Fprintln(d.Out, "No members.")
				return nil
			}
			for _, member := range members {
				fmt.Fprintf(d.Out, "%s\t%s\t%s\n", member.UserEmail, member.UserID, member.Role)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "team ID")
	return cmd
}

func newTeamsAddCmd(d Deps) *cobra.Command {
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
			fmt.Fprintf(d.Out, "member %s (%s)\n", member.UserID, member.Role)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "team ID")
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
			fmt.Fprintln(d.Out, "member removed")
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "team ID")
	cmd.Flags().StringVar(&user, "user", "", "user ID")
	return cmd
}
