package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func newTargetsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{Use: "targets", Short: "List what a project's scans ran against"}
	var project string
	list := &cobra.Command{
		Use:   "list",
		Short: "List a project's scan targets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "targets list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			targets, err := cl.ListTargets(project)
			if err != nil {
				return err
			}
			return emit(d, s, targets, func(w io.Writer) error {
				if len(targets) == 0 {
					_, err := fmt.Fprintln(w, "No scan targets.")
					return err
				}
				for _, t := range targets {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Kind, dashIfEmpty(t.Locator)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	list.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.AddCommand(list)
	return cmd
}

func newArtifactsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{Use: "artifacts", Short: "List the build artifacts a project's scans saw"}
	var project string
	list := &cobra.Command{
		Use:   "list",
		Short: "List a project's artifacts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "artifacts list"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			artifacts, err := cl.ListArtifacts(project)
			if err != nil {
				return err
			}
			return emit(d, s, artifacts, func(w io.Writer) error {
				if len(artifacts) == 0 {
					_, err := fmt.Fprintln(w, "No artifacts.")
					return err
				}
				for _, a := range artifacts {
					name := a.Name
					if a.Version != "" {
						name += " " + a.Version
					}
					digest := strings.TrimPrefix(a.Digest, "sha256:")
					if len(digest) > 12 {
						digest = digest[:12]
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.ID, name, a.ArtifactType, dashIfEmpty(digest)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	list.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.AddCommand(list)
	return cmd
}
