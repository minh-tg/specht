package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

func newReportsCmd(d Deps, s *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "List, upload and delete scan reports",
	}
	cmd.AddCommand(newReportsListCmd(d, s), newReportsGetCmd(d, s), newReportsUploadCmd(d, s), newReportsDeleteCmd(d))
	return cmd
}

func newReportsListCmd(d Deps, s *settings) *cobra.Command {
	var project string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List a project's reports, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "reports list"); err != nil {
				return err
			}
			pageSize, err := limitArg("--limit", limit)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			reports, err := cl.ListReports(project, pageSize, 0)
			if err != nil {
				return err
			}
			return emit(d, s, reports, func(w io.Writer) error {
				if len(reports) == 0 {
					_, err := fmt.Fprintln(w, "No reports.")
					return err
				}
				for _, r := range reports {
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Status, r.ToolName,
						countText(r.TotalFindings), shortCommit(r.CommitSha), r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().IntVar(&limit, "limit", 0, "show at most this many reports (0 for the server's default)")
	return cmd
}

func newReportsGetCmd(d Deps, s *settings) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Show one report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(id, "--id", "reports get"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			r, err := cl.GetReport(id)
			if err != nil {
				return err
			}
			return emit(d, s, r, func(w io.Writer) error {
				_, err := fmt.Fprintf(w, "ID:        %s\nTool:      %s\nStatus:    %s\nScan type: %s\nFindings:  %s\nBranch:    %s\nCommit:    %s\nCreated:   %s\n",
					r.ID, r.ToolName, r.Status, r.ScanType, countText(r.TotalFindings), dashIfEmpty(deref(r.Branch)), dashIfEmpty(deref(r.CommitSha)),
					r.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"))
				return err
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "report ID")
	return cmd
}

func newReportsDeleteCmd(d Deps) *cobra.Command {
	var project, id string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a report",
		Long: "Delete a report. Findings that only this report showed are archived, not erased, and a later scan\n" +
			"that sees them again opens them afresh.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireFlag(project, "--project", "reports delete"); err != nil {
				return err
			}
			if err := requireFlag(id, "--id", "reports delete"); err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			archived, err := cl.DeleteReport(project, id)
			if err != nil {
				return err
			}
			if archived == 0 {
				_, err = fmt.Fprintln(d.Out, "report deleted")
			} else {
				_, err = fmt.Fprintf(d.Out, "report deleted; %d %s archived\n", archived, plural(archived, "finding", "findings"))
			}
			return err
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&id, "id", "", "report ID")
	return cmd
}

func newReportsUploadCmd(d Deps, s *settings) *cobra.Command {
	var project, scanner, file, branch, commit, environment, owner string
	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload a scanner's report",
		Long: "Upload the output of a scanner. --file is a path, or - for standard input. A .jsonl or .ndjson file\n" +
			"(Nuclei writes one) is sent as a list of its lines. Run specht scanners list to see which scanner\n" +
			"reads which file and how to produce it.\n\n" +
			"This records the scan. To fail a build on a blocked gate, use specht-adapter.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, check := range []struct{ value, flag string }{{project, "--project"}, {scanner, "--scanner"}, {file, "--file"}} {
				if err := requireFlag(check.value, check.flag, "reports upload"); err != nil {
					return err
				}
			}
			raw, err := readScanFile(d, file)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			resp, err := cl.IngestReport(&client.IngestPayload{
				Project: project, Scanner: scanner, RawData: raw,
				Branch: branch, CommitSha: commit, Environment: environment, Owner: owner,
			})
			if err != nil {
				return err
			}
			return emit(d, s, resp, func(w io.Writer) error {
				gate := "passed"
				if resp.ThresholdBreached {
					gate = "blocked"
				}
				note := ""
				if resp.Replayed {
					note = " (already ingested)"
				}
				_, err := fmt.Fprintf(w, "report %s: %d %s, gate %s%s\n", resp.ReportID, resp.TotalFindings,
					plural(resp.TotalFindings, "finding", "findings"), gate, note)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&project, "project", "", flagProjectSlugUsage)
	cmd.Flags().StringVar(&scanner, "scanner", "", "scanner that wrote the file, such as trivy (see scanners list)")
	cmd.Flags().StringVar(&file, "file", "", "the scan file, or - for standard input")
	cmd.Flags().StringVar(&branch, "branch", "", "branch that was scanned")
	cmd.Flags().StringVar(&commit, "commit", "", "commit that was scanned")
	cmd.Flags().StringVar(&environment, "environment", "", "environment the scan describes, such as production")
	cmd.Flags().StringVar(&owner, "owner", "", "repository the scan belongs to, such as github://owner/repo")
	return cmd
}

// readScanFile reads a scan file the way the server takes it: one JSON value, or for
// .jsonl and .ndjson a list with one value for each line. Standard input is read as JSON
// first and as lines if that fails.
func readScanFile(d Deps, path string) (json.RawMessage, error) {
	var data []byte
	var err error
	name := path
	if path == "-" {
		name = "standard input"
		if d.In == nil {
			return nil, fmt.Errorf("--file - needs standard input")
		}
		data, err = io.ReadAll(d.In)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	// PowerShell's > writes UTF-16, which no scanner output parser reads. A UTF-8 byte order
	// mark, which many Windows editors add, is harmless but makes the file invalid JSON.
	if bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF}) {
		return nil, fmt.Errorf("%s is UTF-16 text, which Specht cannot read: save it as UTF-8 and upload it again", name)
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s is empty", name)
	}
	lower := strings.ToLower(path)
	lines := strings.HasSuffix(lower, ".jsonl") || strings.HasSuffix(lower, ".ndjson")
	if path == "-" && !json.Valid(data) {
		lines = true
	}
	if !lines {
		if !json.Valid(data) {
			return nil, fmt.Errorf("%s is not valid JSON", name)
		}
		return json.RawMessage(bytes.TrimSpace(data)), nil
	}
	var events []json.RawMessage
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !json.Valid([]byte(line)) {
			return nil, fmt.Errorf("%s: line %d is not valid JSON", name, i+1)
		}
		events = append(events, json.RawMessage(line))
	}
	return json.Marshal(events)
}

func countText(n *int32) string {
	if n == nil {
		return "-"
	}
	return fmt.Sprint(*n)
}

func shortCommit(sha *string) string {
	v := deref(sha)
	if v == "" {
		return "-"
	}
	if len(v) > 7 {
		return v[:7]
	}
	return v
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
