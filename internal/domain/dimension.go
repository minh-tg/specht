// Package domain defines the core, engine-neutral domain vocabulary of
// Specht: the normalized scan report/finding model, canonical dimension
// keys, and the reachability hint shape. Packages inside internal/domain
// must not import sqlc, pgtype, HTTP, or scanner packages; the persistence
// adapter (internal/repo) and the HTTP layer translate between this
// vocabulary and their own representations.
//
// The normalized report model was moved here verbatim from
// internal/scanner (a boundary move, not a semantic rewrite). The scanner
// package re-exports the same identifiers so the first cutover is a
// mechanical import change; new code should import internal/domain
// directly.
package domain

// ScanType classifies what kind of artifact a scan covered.
type ScanType string

const (
	ScanTypeImage      ScanType = "image"
	ScanTypeFilesystem ScanType = "filesystem"
	ScanTypeRepository ScanType = "repository"
	ScanTypeIaC        ScanType = "iac"
	ScanTypeSBOM       ScanType = "sbom"
	ScanTypeLockfile   ScanType = "lockfile"
)

// Severity is the normalized severity scale used across scanners. The int
// values are ordered so severity comparisons (>, >=) work across the whole
// pipeline.
type Severity int

const (
	SeverityUnknown  Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// ContractVersion is the version of the normalized report contract a
// producer (scanner parser) implements.
type ContractVersion uint16

// FingerprintVersion is the version of the finding fingerprint algorithm a
// finding's fingerprint was produced with. Version 1 fingerprints remain
// stable so existing rows and waivers do not silently fork.
type FingerprintVersion uint16

// ScanCompleteness describes how much of a scan target the report covers.
type ScanCompleteness string

const (
	CompletenessUnknown  ScanCompleteness = "unknown"
	CompletenessPartial  ScanCompleteness = "partial"
	CompletenessComplete ScanCompleteness = "complete"
)

// PackageRef identifies a single package found in a scan, whether or not it
// has an associated finding. The PURL is normalized (qualifiers and subpath
// stripped) so inventory lookups can be matched by name and version; note
// that some scanners (e.g. osv-scanner) emit finding purls without a version,
// so callers should not assume every purl carries one.
type PackageRef struct {
	PURL         string
	Ecosystem    string
	Name         string
	Version      string
	ManifestPath string
}

// TargetInfo identifies the scan target (repository, image, filesystem...).
type TargetInfo struct {
	Kind       string
	Identifier string
}

// ArtifactInfo identifies a specific artifact of the target when the scanner
// reports one.
type ArtifactInfo struct {
	Kind       string
	Identifier string
	Metadata   map[string]any
}

// NormalizedFinding is one scanner-detected issue in the normalized model.
// Fingerprint must be stable across scans of the same issue (see the
// per-kind fingerprint formulas) and Dimensions carries the structured
// key/value pairs used for waiver matching and display.
type NormalizedFinding struct {
	Fingerprint  string
	FindingKind  string
	Title        string
	Description  string
	Severity     Severity
	Score        float64
	Location     string
	Resource     string
	Aliases      []string
	Reachability *ReachabilityHint
	CVSS         *CVSSInfo
	Fix          *FixInfo
	CodeLocation *CodeLocation
	Dimensions   []Dimension
	// Extensions carries producer payloads that do not fit a canonical
	// dimension or typed field. The Postgres occurrence mapper preserves
	// payloads under their source namespace (extension keys are namespaced
	// by producer, e.g. "trivy.cwe_ids") and reserves the "specht" namespace
	// for canonical CVSS/fix/location/resource data. Extension keys never
	// become identity or gate inputs.
	Extensions map[string]any
}

// CVSSInfo is a parsed CVSS vector and its score.
type CVSSInfo struct {
	Version string
	Vector  string
	Score   float64
}

// FixInfo describes the remediation for a finding when known.
type FixInfo struct {
	Summary     string
	Description string
	URL         string
	Diff        string
}

// CodeLocation is the source location of a SAST/secret finding.
type CodeLocation struct {
	File        string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Snippet     string
}

// Dimension is one structured attribute of a finding, persisted as a
// finding_dimensions row and used for waiver matching (e.g.
// vulnerability_id, package_name, fixed_version).
type Dimension struct {
	Key   string
	Value string
}

// Fingerprint is a stable finding identifier within a project.
type Fingerprint string

// SCAFingerprint computes the SCA fingerprint from a vulnerability id and
// normalized purl.
func SCAFingerprint(vulnID, purl string) Fingerprint {
	return Fingerprint(vulnID + ":" + purl)
}

// Canonical dimension-key vocabulary. These keys are the persisted
// snake_case contract shared by every scanner/watcher producer, the waiver
// matcher, and the UI. New producers must emit exactly these keys; plugin
// payloads that do not fit a canonical key belong in the namespaced
// Extensions map, never as unbounded dimension keys.
const (
	DimVulnerabilityID string = "vulnerability_id"
	DimAlias           string = "alias"
	DimPURL            string = "purl"
	DimPackageName     string = "package_name"
	DimEcosystem       string = "ecosystem"
	DimInstalledVer    string = "installed_version"
	DimFixedVersion    string = "fixed_version"
	DimRuleID          string = "rule_id"
	DimFile            string = "file"
	DimLine            string = "line"
	DimResource        string = "resource"
	DimSource          string = "source"
)
