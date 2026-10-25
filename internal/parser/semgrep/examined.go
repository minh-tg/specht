package semgrep

import (
	"strings"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// runProof reads the rules a SARIF run loaded and whether it finished. Semgrep
// SARIF lists no scanned files, so the rule list is the only proof it gives
// and a rule counts for every file (see parseutil.RuleRun). The native JSON
// format lists no rules and proves nothing.
func runProof(run sarifRun) parseutil.RuleRun {
	proof := parseutil.RuleRun{Kind: "sast"}
	for _, r := range run.Tool.Driver.Rules {
		proof.RuleIDs = append(proof.RuleIDs, r.ID)
	}
	for _, a := range run.Artifacts {
		if f := parseutil.CleanFilePath(a.Location.URI); f != "" {
			proof.Files = append(proof.Files, f)
		}
	}
	for _, inv := range run.Invocations {
		if inv.ExecutionSuccessful != nil && !*inv.ExecutionSuccessful {
			proof.Failed = true
		}
		for _, n := range inv.ToolExecutionNotifications {
			if strings.EqualFold(n.Level, "error") {
				proof.Failed = true
			}
		}
	}
	return proof
}
