// Package remediate turns normalized finding evidence into reviewable
// remediation suggestions. It never invents fixes: every suggestion is
// built from scanner-supplied data (fixed versions, guidelines, rule
// remediation) or labeled as kind-level guidance with low confidence.
//
// Confidence contract:
//   - high: exact target + exact change from the scanner (package,
//     installed and fixed versions; secret rotation procedure).
//   - medium: source guidance without an exact change (guideline URL,
//     rule fix summary).
//   - low: kind-level fallback when the source supplied nothing usable.
//     Low suggestions are guidance text, never actions.
//
// Suggestions carry the finding identity they were built for so later
// verification scans can link fix and outcome.
package remediate

import (
	"fmt"
	"strings"
)

// Confidence grades how actionable a suggestion is.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Input is the evidence one suggestion is built from.
type Input struct {
	FindingID   string
	FindingKind string
	Title       string
	// Dims carries the finding's canonical dimensions (fixed_version,
	// installed_version, package_name, rule_id, resource, file, url…).
	Dims map[string]string
	// FixSummary and FixURL are the source's own remediation, when any.
	FixSummary string
	FixURL     string
	// Tool names the scanner that supplied the evidence.
	Tool string
}

// Suggestion is one reviewable remediation proposal.
type Suggestion struct {
	FindingID  string     `json:"finding_id"`
	Action     string     `json:"action"`
	Target     string     `json:"target,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Confidence Confidence `json:"confidence"`
	Source     string     `json:"source,omitempty"`
}

// Suggest builds the suggestion for one finding. It always returns exactly
// one suggestion: source-backed when evidence allows, labeled fallback
// otherwise.
func Suggest(in Input) Suggestion {
	switch in.FindingKind {
	case "sca":
		return suggestSCA(in)
	case "iac":
		return suggestIaC(in)
	case "secret":
		return Suggestion{
			FindingID: in.FindingID,
			Action:    "rotate",
			Target:    in.Dims["file"],
			Detail: "Revoke the exposed credential with its provider, issue a replacement, " +
				"and purge it from history. Verify by rescanning: the finding must be absent.",
			Confidence: ConfidenceHigh,
			Source:     in.Tool,
		}
	case "sast":
		if in.FixSummary != "" {
			return Suggestion{
				FindingID: in.FindingID, Action: "fix-code",
				Target: targetOf(in), Detail: in.FixSummary,
				Confidence: ConfidenceMedium, Source: in.Tool,
			}
		}
	case "dast":
		if in.FixSummary != "" {
			return Suggestion{
				FindingID: in.FindingID, Action: "fix-configuration",
				Target: in.Dims["url"], Detail: in.FixSummary,
				Confidence: ConfidenceMedium, Source: in.Tool,
			}
		}
	}
	return fallback(in)
}

func suggestSCA(in Input) Suggestion {
	pkg := in.Dims["package_name"]
	installed := in.Dims["installed_version"]
	fixed := in.Dims["fixed_version"]
	if pkg != "" && fixed != "" {
		detail := fmt.Sprintf("Upgrade %s", pkg)
		if installed != "" {
			detail += fmt.Sprintf(" from %s", installed)
		}
		detail += fmt.Sprintf(" to %s or later, then rescan to verify.", fixed)
		return Suggestion{
			FindingID: in.FindingID, Action: "upgrade",
			Target: pkg, Detail: detail,
			Confidence: ConfidenceHigh, Source: in.Tool,
		}
	}
	if in.FixSummary != "" || in.FixURL != "" {
		return Suggestion{
			FindingID: in.FindingID, Action: "upgrade",
			Target: pkg, Detail: coalesce(in.FixSummary, in.FixURL),
			Confidence: ConfidenceMedium, Source: in.Tool,
		}
	}
	return fallback(in)
}

func suggestIaC(in Input) Suggestion {
	target := in.Dims["resource"]
	if target == "" {
		target = in.Dims["file"]
	}
	if in.FixURL != "" {
		return Suggestion{
			FindingID: in.FindingID, Action: "configure",
			Target:     target,
			Detail:     fmt.Sprintf("Apply the policy guideline at %s: %s", target, in.FixURL),
			Confidence: ConfidenceMedium, Source: in.Tool,
		}
	}
	if in.FixSummary != "" {
		return Suggestion{
			FindingID: in.FindingID, Action: "configure",
			Target: target, Detail: in.FixSummary,
			Confidence: ConfidenceMedium, Source: in.Tool,
		}
	}
	return fallback(in)
}

func fallback(in Input) Suggestion {
	detail := map[string]string{
		"sca":    "No fixed version reported — review the advisory to determine the upgrade path.",
		"sast":   "No fix description reported — follow the rule documentation for the secure pattern.",
		"iac":    "No remediation reported — find the resource policy and apply the required configuration.",
		"secret": "Rotate the exposed credential with its provider and purge it from history.",
		"dast":   "No remediation reported — reproduce against the observed URL and harden the endpoint.",
	}[in.FindingKind]
	if detail == "" {
		detail = "No remediation reported by the scanner for this finding."
	}
	return Suggestion{
		FindingID: in.FindingID, Action: "review",
		Target: targetOf(in), Detail: detail,
		Confidence: ConfidenceLow, Source: in.Tool,
	}
}

func targetOf(in Input) string {
	for _, k := range []string{"package_name", "resource", "file", "url"} {
		if v := in.Dims[k]; v != "" {
			return v
		}
	}
	return ""
}

func coalesce(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
