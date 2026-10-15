package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

func newScannersCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{Use: "scanners", Short: "See which scanners Specht reads"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the scanners, the files each reads and how to produce them",
		Long: "List the scanners, the files each reads and the command that produces each file.\n" +
			"The first word is the name to give to --scanner. This needs a signed-in session, not a project API key.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			scanners, err := cl.ListScanners()
			if err != nil {
				return err
			}
			return emit(d, s, scanners, func(w io.Writer) error {
				for _, sc := range scanners {
					if _, err := fmt.Fprintf(w, "%s\t%s\n", sc.Name, sc.DisplayName); err != nil {
						return err
					}
					for _, f := range sc.Formats {
						if _, err := fmt.Fprintf(w, "  %s (%s)\t%s\n", f.Name, strings.Join(f.Extensions, ", "), f.Command); err != nil {
							return err
						}
					}
				}
				return nil
			})
		},
	})
	return cmd
}
