package gitleaks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

// Gitleaks writes SARIF with --report-format sarif. Each result is one leak, and
// the region's snippet holds the matched credential, so the same identity rules
// as the JSON format apply: a keyed digest of the credential, never the
// credential itself. The generic SARIF adapter cannot do that (it hashes the
// producer's partialFingerprints, which are the commit and author and are empty
// outside a git scan, so every secret of one rule in one file collapses into
// one finding), which is why it hands Gitleaks logs to this adapter.

// isSARIFTool is true for the tool name Gitleaks writes into a SARIF log.
func isSARIFTool(name string) bool { return strings.EqualFold(strings.TrimSpace(name), "gitleaks") }

type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string `json:"name"`
			Rules []struct {
				ID               string `json:"id"`
				ShortDescription struct {
					Text string `json:"text"`
				} `json:"shortDescription"`
			} `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int             `json:"startLine"`
				StartColumn int             `json:"startColumn"`
				EndLine     int             `json:"endLine"`
				EndColumn   int             `json:"endColumn"`
				Snippet     json.RawMessage `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

// recognizeSARIF is definite for a log in which every run names Gitleaks. A log
// that mixes tools is left to the generic SARIF adapter, which refuses the
// Gitleaks run in it rather than reading a secret as an ordinary finding.
func recognizeSARIF(data []byte) scanner.Recognition {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil || len(log.Runs) == 0 {
		return scanner.NotRecognized
	}
	for _, run := range log.Runs {
		if !isSARIFTool(run.Tool.Driver.Name) {
			return scanner.NotRecognized
		}
	}
	return scanner.Definite
}

// readSARIF turns the results of a Gitleaks SARIF log into the entries the JSON
// format would hold. Gitleaks gives a SARIF result no fingerprint of its own, so
// one is built from the commit, file, rule and position: it is the identity of
// last resort for a report written with --redact, where the snippet reads
// REDACTED and there is no credential to hash.
func readSARIF(data []byte) ([]gitleaksFinding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, scanner.Malformed("gitleaks", err)
	}
	var out []gitleaksFinding
	for _, run := range log.Runs {
		descriptions := map[string]string{}
		for _, rule := range run.Tool.Driver.Rules {
			if _, seen := descriptions[rule.ID]; !seen {
				descriptions[rule.ID] = rule.ShortDescription.Text
			}
		}
		for _, r := range run.Results {
			ruleID := r.RuleID
			if ruleID == "" && r.RuleIndex != nil && *r.RuleIndex >= 0 && *r.RuleIndex < len(run.Tool.Driver.Rules) {
				ruleID = run.Tool.Driver.Rules[*r.RuleIndex].ID
			}
			if len(r.Locations) == 0 {
				continue
			}
			loc := r.Locations[0].PhysicalLocation
			g := gitleaksFinding{
				RuleID:      ruleID,
				File:        loc.ArtifactLocation.URI,
				Description: descriptions[ruleID],
				Secret:      snippetText(loc.Region.Snippet),
				StartLine:   loc.Region.StartLine,
				EndLine:     loc.Region.EndLine,
				StartColumn: loc.Region.StartColumn,
				EndColumn:   loc.Region.EndColumn,
				Commit:      r.PartialFingerprints["commitSha"],
			}
			g.Fingerprint = fmt.Sprintf("%s:%s:%s:%d:%d", g.Commit, g.File, g.RuleID, g.StartLine, g.StartColumn)
			out = append(out, g)
		}
	}
	return out, nil
}

// snippetText is the matched text of a region's snippet. Gitleaks writes an
// object with a text member. Redaction replaces the whole object with a string
// placeholder, which comes back as it is and is then read as redacted.
func snippetText(raw json.RawMessage) string {
	var obj struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Text
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	return ""
}

// redactSARIF scrubs a Gitleaks SARIF log: the snippet of a region holds the
// credential and a contextRegion holds the source around it.
func redactSARIF(data []byte) ([]byte, error) {
	return parseutil.RedactRawJSON("gitleaks", data, "snippet", "contextRegion")
}
