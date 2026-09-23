package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newProjectsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Manage projects",
	}
	cmd.AddCommand(newProjectsListCmd(d), newProjectsGetCmd(d))
	return cmd
}

func newProjectsListCmd(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			projects, err := cl.ListProjects()
			if err != nil {
				return err
			}
			if len(projects) == 0 {
				if _, err := fmt.Fprintln(d.Out, "No projects found."); err != nil {
					return err
				}
				return nil
			}
			for _, p := range projects {
				desc := ""
				if p.Description != nil {
					desc = *p.Description
				}
				if _, err := fmt.Fprintf(d.Out, "%s\t%s\t%s\n", p.Slug, p.Name, desc); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newProjectsGetCmd(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "get <slug>",
		Short: "Show one project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			p, err := cl.GetProject(args[0])
			if err != nil {
				return err
			}
			desc := ""
			if p.Description != nil {
				desc = *p.Description
			}
			if _, err := fmt.Fprintf(d.Out, "Slug:       %s\nName:       %s\nDescription: %s\n", p.Slug, p.Name, desc); err != nil {
				return err
			}
			return nil
		},
	}
}
