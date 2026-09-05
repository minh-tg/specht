package domain

// NormalizedReport is a scanner-agnostic scan result: the findings a parser
// extracted plus full package inventory and the context of what was scanned.
// Parsers produce this; the ingest use case persists it.
//
// Provenance (scanner name/version, parser version) intentionally does NOT
// live on the report: scanner descriptors and the ingest transport request
// are the provenance sources. ContractVersion and FingerprintVersion
// describe the report envelope and the fingerprint algorithm used.
//
// NOTE: the ToolName/ToolVersion/ParserVersion/Display/Metadata/Reachability
// fields below are the version-1 normalized contract. They are retained on
// the boundary-moved type until every producer (the six parser adapters and
// the watcher) migrates in the same change that introduces the namespaced
// Extensions map and the typed reachability hint; after that cutover they are
// removed with no compatibility shim.
type NormalizedReport struct {
	ToolName           string
	ToolVersion        string
	ParserVersion      string
	ContractVersion    ContractVersion
	FingerprintVersion FingerprintVersion
	ScanType           ScanType
	Completeness       ScanCompleteness
	Target             *TargetInfo
	Artifact           *ArtifactInfo
	Findings           []NormalizedFinding
	Packages           []PackageRef
	// ScanScope holds typed scan scope attributes (target, artifact, branch,
	// commit SHA, stable extension attributes).
	ScanScope map[string]any
}
