package scanner

import (
	"context"
)

type ScanType string

const (
	ScanTypeImage      ScanType = "image"
	ScanTypeFilesystem ScanType = "filesystem"
	ScanTypeRepository ScanType = "repository"
	ScanTypeIaC        ScanType = "iac"
	ScanTypeSBOM       ScanType = "sbom"
	ScanTypeLockfile   ScanType = "lockfile"
)

type Severity int

const (
	SeverityUnknown  Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

type Scanner interface {
	Name() string
	DetectFormat(data []byte) bool
	Parse(ctx context.Context, data []byte) (*NormalizedReport, error)
	FindingKind() string
}

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
// stripped) so findings can be matched against inventory by purl@version.
type PackageRef struct {
	PURL         string
	Ecosystem    string
	Name         string
	Version      string
	ManifestPath string
}

type TargetInfo struct {
	Kind       string
	Identifier string
}

type ArtifactInfo struct {
	Kind       string
	Identifier string
	Metadata   map[string]any
}

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

type CVSSInfo struct {
	Version string
	Vector  string
	Score   float64
}

type FixInfo struct {
	Summary     string
	Description string
	URL         string
	Diff        string
}

type CodeLocation struct {
	File        string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Snippet     string
}

type Dimension struct {
	Key   string
	Value string
}

type Fingerprint string

func SCAFingerprint(vulnID, purl string) Fingerprint {
	return Fingerprint(vulnID + ":" + purl)
}
