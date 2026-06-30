package scanner

import (
	"context"
	"io"
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

type Parser interface {
	Name() string
	ScanTypes() []ScanType
	Parse(ctx context.Context, r io.Reader) (*NormalizedReport, error)
}

type NormalizedReport struct {
	ScannerName string
	ScanType    ScanType
	Target      *TargetInfo
	Artifact    *ArtifactInfo
	Findings    []NormalizedFinding
	ScanScope   map[string]any
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
	Fingerprint string
	FindingKind string
	Title       string
	Description string
	Severity    Severity
	Score       float64
	Location    string
	Dimensions  []Dimension
	Display     map[string]any
	Metadata    map[string]any
}

type Dimension struct {
	Key   string
	Value string
}

type Fingerprint string

func SCAFingerprint(vulnID, purl string) Fingerprint {
	return Fingerprint(vulnID + ":" + purl)
}
