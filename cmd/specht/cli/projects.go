package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newProjectsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "projects",
		Short: "Manage projects",
	}
	cmd.AddCommand(newProjectsListCmd(d), newProjectsGetCmd(d), newProjectsCreateCmd(d, s), newProjectsUpdateCmd(d, s), newProjectsDeleteCmd(d))
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

func newProjectsCreateCmd(d Deps, s *settings) *cobra.Command {
	var name, slug, description string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a project (admin)",
		Long: "Create a project. The slug is its short name in URLs: 3 to 48 lowercase letters and digits, with single\n" +
			"hyphens between groups.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(name, "--name", "projects create"); err != nil {
				return err
			}
			if err := requireFlag(slug, "--slug", "projects create"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			p, err := cl.CreateProject(name, slug, description)
			if err != nil {
				return err
			}
			return emit(d, s, p, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "project %s (%s)\n", p.Slug, p.Name)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "project name")
	cmd.Flags().StringVar(&slug, "slug", "", "short name used in URLs")
	cmd.Flags().StringVar(&description, "description", "", "what the project is")
	return cmd
}

func newProjectsUpdateCmd(d Deps, s *settings) *cobra.Command {
	var name, description string
	cmd := &cobra.Command{
		Use:   "update <slug>",
		Short: "Rename a project or change its description (project admin)",
		Long:  "Change a project's name or description. Give only what changes; --description \"\" clears it.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var newName, newDescription *string
			if cmd.Flags().Changed("name") {
				newName = &name
			}
			if cmd.Flags().Changed("description") {
				newDescription = &description
			}
			if newName == nil && newDescription == nil {
				return fmt.Errorf("nothing to change: give --name or --description")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			p, err := cl.UpdateProject(args[0], newName, newDescription)
			if err != nil {
				return err
			}
			return emit(d, s, p, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "project %s (%s)\n", p.Slug, p.Name)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "new name")
	cmd.Flags().StringVar(&description, "description", "", "new description; empty clears it")
	return cmd
}

func newProjectsDeleteCmd(d Deps) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <slug>",
		Short: "Delete a project and everything under it (project admin)",
		Long: "Delete a project with its reports, findings, waivers, members and API keys. This cannot be undone,\n" +
			"so it needs --yes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("deleting project %s removes its reports, findings, waivers, members and keys for good: add --yes to confirm", args[0])
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			p, err := cl.DeleteProject(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(d.Out, "project %s deleted\n", p.Slug)
			return err
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the deletion")
	return cmd
}
