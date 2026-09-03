// Package scanner defines the normalized report/finding model that every
// scanner parser produces and the registry that maps scanner names to their
// parser implementations. Parsers live in internal/parser/<name> and convert
// vendor-specific output into this package's types.
package scanner

import (
	"context"
)

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

// Scanner adapts a vendor scanner output format to the normalized model.
// Registry maps scanner names to implementations; the HTTP ingest path finds
// a scanner by name and calls Parse.
type Scanner interface {
	Name() string
	DetectFormat(data []byte) bool
	Parse(ctx context.Context, data []byte) (*NormalizedReport, error)
	FindingKind() string
}

// NormalizedReport is a scanner-agnostic scan result: the findings a parser
// extracted plus full package inventory and the context of what was scanned.
// Parsers produce this; the ingest use case persists it.
type NormalizedReport struct {
	ToolName      string
	ToolVersion   string
	ParserVersion string
	ScanType      ScanType
	Target        *TargetInfo
	Artifact      *ArtifactInfo
	Findings      []NormalizedFinding
	Packages      []PackageRef
	ScanScope     map[string]any
}

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
	Reachability *bool
	CVSS         *CVSSInfo
	Fix          *FixInfo
	CodeLocation *CodeLocation
	Dimensions   []Dimension
	Display      map[string]any
	Metadata     map[string]any
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
