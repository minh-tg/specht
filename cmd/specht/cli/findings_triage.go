package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/minh-tg/specht/internal/client"
	"github.com/spf13/cobra"
)

const triageStates = "unanalyzed, in_triage, exploitable, false_positive, not_affected, accepted_risk or wont_fix"

func newFindingsTriageCmd(d Deps, s *settings) *cobra.Command {
	var state, reason, expires string
	cmd := &cobra.Command{
		Use:   "triage <id>",
		Short: "Record an analyst decision on a finding",
		Long: "Record an analyst decision on a finding.\n\n" +
			"The state is one of " + triageStates + ".\n" +
			"false_positive, not_affected, accepted_risk and wont_fix ignore the gate, so they need --reason;\n" +
			"accepted_risk and wont_fix also need --expires, the day the decision lapses.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req, err := triageRequest(state, reason, expires)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			result, err := cl.TriageFinding(args[0], req)
			if err != nil {
				return err
			}
			return emit(d, s, result, func(w io.Writer) error {
				return writeTriageResult(w, *result)
			})
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "decision: "+triageStates)
	cmd.Flags().StringVar(&reason, "reason", "", "why; required for the states that ignore the gate")
	cmd.Flags().StringVar(&expires, "expires", "", "when the decision lapses: 2026-12-31 or an RFC 3339 time")
	return cmd
}

func newFindingsBulkTriageCmd(d Deps, s *settings) *cobra.Command {
	var ids []string
	var state, reason, expires string
	cmd := &cobra.Command{
		Use:   "bulk-triage",
		Short: "Apply one decision to several findings",
		Long: "Apply one decision to several findings. The rules for --state, --reason and --expires are\n" +
			"the same as for triage.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			findingIDs := splitIDs(ids)
			if len(findingIDs) == 0 {
				return fmt.Errorf("--id is required for findings bulk-triage")
			}
			req, err := triageRequest(state, reason, expires)
			if err != nil {
				return err
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			results, err := cl.BulkTriage(&client.BulkTriageRequest{
				FindingIDs:        findingIDs,
				AnalysisState:     req.AnalysisState,
				Reason:            req.Reason,
				AnalysisExpiresAt: req.AnalysisExpiresAt,
			})
			if err != nil {
				return err
			}
			return emit(d, s, results, func(w io.Writer) error {
				for _, r := range results {
					if err := writeTriageResult(w, r); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringSliceVar(&ids, "id", nil, "finding ID; repeat or separate with commas")
	cmd.Flags().StringVar(&state, "state", "", "decision: "+triageStates)
	cmd.Flags().StringVar(&reason, "reason", "", "why; required for the states that ignore the gate")
	cmd.Flags().StringVar(&expires, "expires", "", "when the decision lapses: 2026-12-31 or an RFC 3339 time")
	return cmd
}

func newFindingsEventsCmd(d Deps, s *settings) *cobra.Command {
	var types []string
	var limit int
	cmd := &cobra.Command{
		Use:   "events <id>",
		Short: "Show a finding's history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 0 {
				return fmt.Errorf("--limit must not be negative")
			}
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			events, err := cl.ListFindingEvents(args[0], splitIDs(types), int32(limit), 0)
			if err != nil {
				return err
			}
			return emit(d, s, events, func(w io.Writer) error {
				if len(events) == 0 {
					_, err := fmt.Fprintln(w, "No events.")
					return err
				}
				for _, e := range events {
					who := e.UserName
					if who == "" {
						who = e.UserID
					}
					if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
						e.CreatedAt.UTC().Format(time.RFC3339), e.EventType, who, change(e), deref(e.Comment)); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringSliceVar(&types, "type", nil, "only these event types; repeat or separate with commas")
	cmd.Flags().IntVar(&limit, "limit", 0, "show at most this many events (0 for the server's default)")
	return cmd
}

// triageRequest builds the request both triage commands send. It checks what only
// the command line can: that a state was named and that --expires is a time. Which
// states need a reason or an expiry is the server's rule, and its message is shown.
func triageRequest(state, reason, expires string) (*client.TriageRequest, error) {
	if err := requireFlag(state, "--state", "triage"); err != nil {
		return nil, err
	}
	req := &client.TriageRequest{AnalysisState: state, Reason: reason}
	if expires != "" {
		when, err := parseWhen("--expires", expires)
		if err != nil {
			return nil, err
		}
		req.AnalysisExpiresAt = &when
	}
	return req, nil
}

func writeTriageResult(w io.Writer, r client.TriageResponse) error {
	_, err := fmt.Fprintf(w, "%s\t%s\tgate: %s\n", r.FindingID, r.AnalysisState, r.GateEffect)
	return err
}

// change renders an event's old and new value as "old -> new", or whichever exists.
func change(e client.FindingEvent) string {
	switch {
	case e.OldValue != nil && e.NewValue != nil:
		return *e.OldValue + " -> " + *e.NewValue
	case e.NewValue != nil:
		return *e.NewValue
	case e.OldValue != nil:
		return *e.OldValue + " ->"
	}
	return ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
