package patch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/remediate"
)

// Class names a supported remediation class. Only listed classes ever
// produce edits; everything else is an explicit unsupported outcome.
type Class string

const (
	// ClassDependencyBump upgrades one dependency to a scanner-reported
	// fixed version. The only supported class: exact package, exact
	// versions, no invented content.
	ClassDependencyBump Class = "dependency-bump"
)

// ApplyModeManual is the only apply mode: every proposal is reviewable
// before application and nothing merges or deploys by itself.
const ApplyModeManual = "manual"

// Input is the evidence one proposal is built from.
type Input struct {
	FindingID   string
	FindingKind string
	Title       string
	// Dims carries canonical dimensions (package_name, installed_version,
	// fixed_version, file, purl, ecosystem…).
	Dims map[string]string
	// FixSummary and FixURL are the source's own remediation, when any.
	FixSummary string
	FixURL     string
	// Tool names the scanner that supplied the evidence.
	Tool string
	// ReportID and CommitSha link the proposal to the source scan.
	ReportID  string
	CommitSha string
}

// Evidence pins a proposal to its source: which scan, what it reported,
// and what change it justifies.
type Evidence struct {
	ReportID         string `json:"report_id,omitempty"`
	Scanner          string `json:"scanner,omitempty"`
	CommitSha        string `json:"commit_sha,omitempty"`
	Package          string `json:"package,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	ManifestFile     string `json:"manifest_file,omitempty"`
}

// FileEdit is one scoped, reproducible file operation.
type FileEdit struct {
	// File is the manifest path; empty when unknown (apply by hand).
	File string `json:"file,omitempty"`
	// Operation is the machine-readable op (only set-dependency-version).
	Operation   string `json:"operation"`
	Package     string `json:"package"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version"`
}

// Proposal is one reviewable remediation proposal.
type Proposal struct {
	ID         string     `json:"id"`
	FindingID  string     `json:"finding_id"`
	Class      Class      `json:"class"`
	Confidence string     `json:"confidence"`
	Rationale  string     `json:"rationale"`
	Evidence   Evidence   `json:"evidence"`
	Edits      []FileEdit `json:"edits"`
	// ApplyMode is always manual: proposals never self-apply.
	ApplyMode string `json:"apply_mode"`
	// VerifyBy states how to prove the fix worked.
	VerifyBy string `json:"verify_by"`
}

// Outcome is either a proposal or an explicit refusal. Refusals carry the
// reason; no partial patch is ever produced.
type Outcome struct {
	Supported bool      `json:"supported"`
	Proposal  *Proposal `json:"proposal,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// Propose builds the patch outcome for one finding's evidence.
func Propose(in Input) Outcome {
	// Secrets are never patched: rotation handles credentials, and patch
	// content must never carry secret material. Compared case-insensitively
	// so no casing variant slips into the patchable path.
	if strings.EqualFold(in.FindingKind, "secret") {
		return Outcome{Reason: "secret findings are never auto-patched: rotate the credential with its provider, revoke the old value, and purge it from history"}
	}
	suggestion := remediate.Suggest(remediate.Input{
		FindingID: in.FindingID, FindingKind: in.FindingKind, Title: in.Title,
		Dims: in.Dims, FixSummary: in.FixSummary, FixURL: in.FixURL, Tool: in.Tool,
	})
	if suggestion.Action != "upgrade" || suggestion.Confidence != remediate.ConfidenceHigh {
		return Outcome{Reason: fmt.Sprintf("no deterministic transformation for kind %q (suggestion: %s/%s)", in.FindingKind, suggestion.Action, suggestion.Confidence)}
	}
	pkg := in.Dims["package_name"]
	fixed := in.Dims["fixed_version"]
	if pkg == "" || fixed == "" {
		return Outcome{Reason: "dependency-bump requires package_name and fixed_version evidence"}
	}
	installed := in.Dims["installed_version"]
	manifest := in.Dims["file"]
	proposal := &Proposal{
		ID:         proposalID(in.FindingID, string(ClassDependencyBump), pkg, fixed),
		FindingID:  in.FindingID,
		Class:      ClassDependencyBump,
		Confidence: string(suggestion.Confidence),
		Rationale:  suggestion.Detail,
		Evidence: Evidence{
			ReportID: in.ReportID, Scanner: in.Tool, CommitSha: in.CommitSha,
			Package: pkg, InstalledVersion: installed, FixedVersion: fixed,
			ManifestFile: manifest,
		},
		Edits: []FileEdit{{
			File: manifest, Operation: "set-dependency-version",
			Package: pkg, FromVersion: installed, ToVersion: fixed,
		}},
		ApplyMode: ApplyModeManual,
		VerifyBy:  "rescan: the finding must be absent from the next completed full scan",
	}
	return Outcome{Supported: true, Proposal: proposal}
}

// proposalID is deterministic over finding, class, package, and target
// version: identical evidence always yields the identical proposal.
func proposalID(findingID, class, pkg, toVersion string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{findingID, class, pkg, toVersion}, "\x00")))
	return "patch-" + hex.EncodeToString(sum[:])[:12]
}
