package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newAPIKeysCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api-keys",
		Short: "Manage a project's API keys",
	}
	cmd.AddCommand(newAPIKeysListCmd(d, s), newAPIKeysCreateCmd(d, s), newAPIKeysRevokeCmd(d))
	return cmd
}

func newAPIKeysListCmd(d Deps, s *settings) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's API keys",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "api-keys list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			keys, err := cl.ListAPIKeys(project)
			if err != nil {
				return err
			}
			return emit(d, s, keys, func(w io.Writer) error {
				if len(keys) == 0 {
					_, err := fmt.Fprintln(w, "No API keys.")
					return err
				}
				for _, k := range keys {
					shown := k.KeyPrefix
					if k.LastFour != nil && *k.LastFour != "" {
						shown += "..." + *k.LastFour
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.ID, k.Name, shown, k.CreatedAt); err != nil {
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

func newAPIKeysCreateCmd(d Deps, s *settings) *cobra.Command {
	var project, name string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Make an API key for a project (project admin)",
		Long:  "Make an API key. The key itself is shown once, here, and cannot be read again.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "api-keys create"); err != nil {
				return err
			}
			if err := requireFlag(name, "--name", "api-keys create"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			key, err := cl.CreateAPIKey(project, name)
			if err != nil {
				return err
			}
			return emit(d, s, key, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "key %s (%s)\n%s\nThis key is shown once. Keep it somewhere safe.\n", key.Name, key.ID, key.RawKey)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&name, "name", "", "what the key is for, such as ci")
	return cmd
}

func newAPIKeysRevokeCmd(d Deps) *cobra.Command {
	var project, id string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Stop an API key from working (project admin)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "api-keys revoke"); err != nil {
				return err
			}
			if err := requireFlag(id, "--id", "api-keys revoke"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			if err := cl.RevokeAPIKey(project, id); err != nil {
				return err
			}
			_, err = fmt.Fprintln(d.Out, "key revoked")
			return err
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", "key ID")
	return cmd
}
