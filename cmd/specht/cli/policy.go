package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newPolicyCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policy baselines",
	}
	cmd.AddCommand(
		newPolicyTemplatesCmd(d),
		newPolicyCreateCmd(d),
		newPolicyUpdateCmd(d),
		newPolicyDeleteCmd(d),
		newPolicyApplyCmd(d),
		newPolicyOverridesCmd(d),
		newPolicyEffectiveCmd(d, s),
	)
	return cmd
}

func newPolicyTemplatesCmd(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "templates",
		Short: "List policy baselines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			templates, err := cl.ListPolicyTemplates()
			if err != nil {
				return err
			}
			if len(templates) == 0 {
				fmt.Fprintln(d.Out, "No policy templates.")
				return nil
			}
			for _, t := range templates {
				fmt.Fprintf(d.Out, "%s\t%s\tv%d\n", t.Name, t.ID, t.Version)
			}
			return nil
		},
	}
}

func newPolicyCreateCmd(d Deps) *cobra.Command {
	var name, description, definition string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a policy baseline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			var def map[string]string
			if definition != "" {
				if err := json.Unmarshal([]byte(definition), &def); err != nil {
					return fmt.Errorf("invalid --definition %q: want a JSON object", definition)
				}
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			tmpl, err := cl.CreatePolicyTemplate(name, description, def)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "template %s (%s)\n", tmpl.Name, tmpl.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "template name")
	cmd.Flags().StringVar(&description, "description", "", "template description")
	cmd.Flags().StringVar(&definition, "definition", "", "template definition as JSON object")
	return cmd
}

func newPolicyUpdateCmd(d Deps) *cobra.Command {
	var templateID, name, description, definition string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a policy baseline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if templateID == "" {
				return fmt.Errorf("--id is required for policy update")
			}
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			var def map[string]string
			if definition != "" {
				if err := json.Unmarshal([]byte(definition), &def); err != nil {
					return fmt.Errorf("invalid --definition %q: want a JSON object", definition)
				}
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			tmpl, err := cl.UpdatePolicyTemplate(templateID, name, description, def)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "template %s v%d\n", tmpl.Name, tmpl.Version)
			return nil
		},
	}
	cmd.Flags().StringVar(&templateID, "id", "", "template ID")
	cmd.Flags().StringVar(&name, "name", "", "template name")
	cmd.Flags().StringVar(&description, "description", "", "template description")
	cmd.Flags().StringVar(&definition, "definition", "", "template definition as JSON object")
	return cmd
}

func newPolicyDeleteCmd(d Deps) *cobra.Command {
	var templateID string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a policy baseline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if templateID == "" {
				return fmt.Errorf("--id is required for policy delete")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.DeletePolicyTemplate(templateID); err != nil {
				return err
			}
			fmt.Fprintln(d.Out, "template deleted")
			return nil
		},
	}
	cmd.Flags().StringVar(&templateID, "id", "", "template ID")
	return cmd
}

func newPolicyApplyCmd(d Deps) *cobra.Command {
	var project, template string
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Link/unlink a baseline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required for policy apply")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			eff, err := cl.SetProjectPolicy(project, template)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "policy: floor=%s (%s) watcher=%s (%s)\n", eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource)
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&template, "template", "", "baseline name (empty unlinks)")
	return cmd
}

func newPolicyOverridesCmd(d Deps) *cobra.Command {
	var project, overrides string
	cmd := &cobra.Command{
		Use:   "overrides",
		Short: "Replace per-key overrides",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if project == "" {
				return fmt.Errorf("--project is required for policy overrides")
			}
			var ov map[string]string
			if overrides != "" {
				if err := json.Unmarshal([]byte(overrides), &ov); err != nil {
					return fmt.Errorf("invalid --set %q: want a JSON object", overrides)
				}
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			eff, err := cl.SetProjectPolicyOverrides(project, ov)
			if err != nil {
				return err
			}
			fmt.Fprintf(d.Out, "policy: floor=%s (%s) watcher=%s (%s)\n", eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource)
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&overrides, "set", "", "overrides as JSON object")
	return cmd
}

func newPolicyEffectiveCmd(d Deps, s *settings) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "effective",
		Short: "Show resolved policy with provenance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "policy effective"); err != nil {
				return err
			}
			format, err := resolveFormat(s)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			eff, err := cl.GetEffectivePolicy(project)
			if err != nil {
				return err
			}
			if format == "json" {
				return writeJSONOut(d.Out, eff)
			}
			template := "(none)"
			if eff.TemplateName != nil {
				template = fmt.Sprintf("%s v%d", *eff.TemplateName, eff.TemplateVersion)
			}
			fmt.Fprintf(d.Out, "template: %s\nfloor=%s (%s) watcher=%s (%s)\n", template, eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource)
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	return cmd
}
