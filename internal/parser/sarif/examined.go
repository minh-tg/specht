package sarif

import (
	"strings"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// runProof reads what a run says about the rules it loaded and the files it
// scanned (see parseutil.RuleRun). Results are not read here: the caller
// marks the rules whose results it dropped as unproven.
func runProof(run sarifRun) parseutil.RuleRun {
	proof := parseutil.RuleRun{Kind: "sast", Unproven: map[string]bool{}}
	for _, r := range run.Tool.Driver.Rules {
		proof.RuleIDs = append(proof.RuleIDs, r.ID)
	}
	for _, ext := range run.Tool.Extensions {
		for _, r := range ext.Rules {
			proof.RuleIDs = append(proof.RuleIDs, r.ID)
		}
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
