package semgrep

import (
	"strings"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// runProof reads the rules a SARIF run loaded, the files it lists and whether
// it finished. Semgrep SARIF lists no scanned files, so a finished run is taken
// to have run its listed rules over every file. A rule it did not list, or a run
// that failed, still closes nothing.
func runProof(run sarifRun) parseutil.RuleRun {
	proof := parseutil.RuleRun{Kind: "sast", AssumeAllFiles: true}
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
