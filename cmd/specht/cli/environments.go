package cli

import (
	"fmt"
	"io"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newEnvironmentsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "environments",
		Short: "List and classify a project's environments",
	}
	cmd.AddCommand(newEnvironmentsListCmd(d, s), newEnvironmentsSetCmd(d, s))
	return cmd
}

func writeEnvironment(w io.Writer, e client.Environment) error {
	exposure := "internal"
	if e.InternetFacing {
		exposure = "internet facing"
	}
	_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.ID, e.Name, e.Tier, exposure, e.DataSensitivity)
	return err
}

func newEnvironmentsListCmd(d Deps, s *settings) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's environments",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "environments list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			envs, err := cl.ListEnvironments(project)
			if err != nil {
				return err
			}
			return emit(d, s, envs, func(w io.Writer) error {
				if len(envs) == 0 {
					_, err := fmt.Fprintln(w, "No environments.")
					return err
				}
				for _, e := range envs {
					if err := writeEnvironment(w, e); err != nil {
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

func newEnvironmentsSetCmd(d Deps, s *settings) *cobra.Command {
	var project, env, tier, sensitivity string
	var internetFacing bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Classify an environment (project admin)",
		Long: "Set how an environment is classified. Name the environment with --env, by name or ID, and give only\n" +
			"the settings to change; the others stay as they are. A scan creates an environment with a tier guessed\n" +
			"from its name and never overwrites what is set here.\n\n" +
			"Tiers: production, staging, development, test. Data sensitivity: public, internal, confidential, restricted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "environments set"); err != nil {
				return err
			}
			if err := requireFlag(env, "--env", "environments set"); err != nil {
				return err
			}
			flags := cmd.Flags()
			if !flags.Changed("tier") && !flags.Changed("internet-facing") && !flags.Changed("data-sensitivity") {
				return fmt.Errorf("nothing to change: give --tier, --internet-facing or --data-sensitivity")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			envs, err := cl.ListEnvironments(project)
			if err != nil {
				return err
			}
			var current *client.Environment
			for i := range envs {
				if envs[i].ID == env || envs[i].Name == env {
					current = &envs[i]
					break
				}
			}
			if current == nil {
				return fmt.Errorf("no environment %q in project %s (run environments list to see them)", env, project)
			}
			settings := client.EnvironmentSettings{Tier: current.Tier, InternetFacing: current.InternetFacing, DataSensitivity: current.DataSensitivity}
			if flags.Changed("tier") {
				settings.Tier = tier
			}
			if flags.Changed("internet-facing") {
				settings.InternetFacing = internetFacing
			}
			if flags.Changed("data-sensitivity") {
				settings.DataSensitivity = sensitivity
			}
			updated, err := cl.UpdateEnvironment(project, current.ID, settings)
			if err != nil {
				return err
			}
			return emit(d, s, updated, func(w io.Writer) error { return writeEnvironment(w, *updated) })
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&env, "env", "", "environment name or ID")
	cmd.Flags().StringVar(&tier, "tier", "", "production, staging, development or test")
	cmd.Flags().BoolVar(&internetFacing, "internet-facing", false, "whether it can be reached from the internet (--internet-facing=false to turn off)")
	cmd.Flags().StringVar(&sensitivity, "data-sensitivity", "", "public, internal, confidential or restricted")
	return cmd
}
