package domain

// NormalizedReport is a scanner-agnostic scan result: the findings a parser
// extracted plus full package inventory and the context of what was scanned.
// Parsers produce this; the ingest use case persists it.
//
// Provenance (scanner name/version, parser version) intentionally does NOT
// live on the report: scanner descriptors and the ingest transport request
// are the provenance sources. ContractVersion and FingerprintVersion
// describe the report envelope and the fingerprint algorithm used.
type NormalizedReport struct {
	ContractVersion    ContractVersion
	FingerprintVersion FingerprintVersion
	ScanType           ScanType
	Completeness       ScanCompleteness
	Target             *TargetInfo
	Artifact           *ArtifactInfo
	Findings           []NormalizedFinding
	Packages           []PackageRef
	// ScanScope holds typed scan scope attributes: the target and artifact
	// identifiers plus branch, commit SHA, and stable extension attributes.
	// Ingest hashes the full typed scope so identical content scanned at a
	// different revision or artifact never collides.
	ScanScope *ScanScope
}

// ScanScope is the typed scope of a scan: what was scanned (target,
// artifact), under which revision (branch, commit SHA), plus stable
// extension attributes supplied by the ingest transport (never free-form
// plugin payload — plugins keep that in NormalizedFinding.Extensions).
type ScanScope struct {
	Target      string
	TargetKind  string
	Artifact    string
	ArtifactVer string
	ArtifactTyp string
	Branch      string
	CommitSha   string
	// Ext holds stable, transport-supplied scope attributes (e.g. the
	// environment name). Keys must be namespaced by the producer.
	Ext map[string]string
}
