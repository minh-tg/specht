package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newProjectTeamsCmd(d Deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project-teams",
		Short: "Manage project team links",
	}
	cmd.AddCommand(
		newProjectTeamsListCmd(d),
		newProjectTeamsLinkCmd(d),
		newProjectTeamsUnlinkCmd(d),
	)
	return cmd
}

func newProjectTeamsListCmd(d Deps) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List teams linked to a project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required for project-teams list")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			links, err := cl.ListProjectTeams(project)
			if err != nil {
				return err
			}
			if len(links) == 0 {
				if _, err := fmt.Fprintln(d.Out, "No linked teams."); err != nil {
					return err
				}
				return nil
			}
			for _, l := range links {
				if _, err := fmt.Fprintf(d.Out, "%s\t%s\t%s\n", l.TeamName, l.TeamID, l.Role); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	return cmd
}

func newProjectTeamsLinkCmd(d Deps) *cobra.Command {
	var project, teamID, role string
	cmd := &cobra.Command{
		Use:   "link",
		Short: "Link a team to a project with a role",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" || teamID == "" || role == "" {
				return fmt.Errorf("--project, --team, and --role are required for project-teams link")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			link, err := cl.LinkProjectTeam(project, teamID, role)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "linked %s as %s\n", link.TeamName, link.Role)
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&teamID, "team", "", "team ID")
	cmd.Flags().StringVar(&role, "role", "", "project role")
	return cmd
}

func newProjectTeamsUnlinkCmd(d Deps) *cobra.Command {
	var project, teamID string
	cmd := &cobra.Command{
		Use:   "unlink",
		Short: "Unlink a team from a project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" || teamID == "" {
				return fmt.Errorf("--project and --team are required for project-teams unlink")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.UnlinkProjectTeam(project, teamID); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(d.Out, "team unlinked"); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&teamID, "team", "", "team ID")
	return cmd
}
