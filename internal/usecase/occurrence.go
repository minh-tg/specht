package usecase

import (
	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

// Extension namespace prefixes. The occurrence mapper preserves producer
// payloads under their source namespace (e.g. "trivy.cwe_ids") and reserves
// the "specht" namespace for canonical CVSS/fix/location/resource data the
// ingest path writes itself. Extension keys never become identity or gate
// inputs.
const (
	spechtNamespace = "specht"
)

// occurrenceDocument is the persisted display/metadata JSON document for one
// occurrence: the namespaced extension payload plus canonical specht data.
type occurrenceDocument struct {
	// Display carries the human-facing summary document (display JSONB).
	Display map[string]any
	// Metadata carries the namespaced observation payload (metadata JSONB).
	Metadata map[string]any
}

// buildOccurrenceDocument maps one normalized finding to the occurrence
// display/metadata documents the Postgres adapter persists. Aliases, CVSS,
// fixes, code locations, resources, and reachability hints are no longer
// silently dropped: they land under the "specht" namespace of the metadata
// document. Producer payloads land under their source namespace (the
// scanner's registered name).
//
// Canonical enrichment never changes finding identity or gate effect: it
// only shapes the occurrence row.
func buildOccurrenceDocument(f scanner.NormalizedFinding, source string) occurrenceDocument {
	display := map[string]any{}
	metadata := map[string]any{}

	// Producer payload, namespaced by source. Reserved "specht" keys from
	// producers are ignored — the canonical namespace belongs to the core.
	for k, v := range f.Extensions {
		if isReservedKey(k) {
			continue
		}
		metadata[source+"."+k] = v
	}

	specht := map[string]any{}
	if len(f.Aliases) > 0 {
		specht["aliases"] = f.Aliases
	}
	if f.CVSS != nil {
		specht["cvss"] = f.CVSS
	}
	if f.Fix != nil {
		specht["fix"] = f.Fix
	}
	if f.CodeLocation != nil {
		specht["code_location"] = f.CodeLocation
	}
	if f.Resource != "" {
		specht["resource"] = f.Resource
	}
	if f.Reachability != nil {
		specht["reachability_hint"] = map[string]any{
			"state":    string(f.Reachability.State),
			"evidence": f.Reachability.Evidence,
			"source":   f.Reachability.Source,
		}
	}
	// The specht namespace holds no display content (title/severity/location
	// are first-class occurrence columns).
	if len(specht) > 0 {
		metadata[spechtNamespace] = specht
	}

	return occurrenceDocument{Display: display, Metadata: metadata}
}

// isReservedKey reports whether an extension key collides with the core's
// reserved "specht" namespace (keys are always fully namespaced in the
// persisted document, but producers may not emit a bare "specht" key).
func isReservedKey(k string) bool {
	return k == spechtNamespace || len(k) > len(spechtNamespace) && k[:len(spechtNamespace)+1] == spechtNamespace+"."
}

// toOccurrenceParams converts a normalized finding into the repo occurrence
// params used by ingest, mapping display/metadata through
// buildOccurrenceDocument and preserving typed columns.
func toOccurrenceParams(f scanner.NormalizedFinding, source string) repo.CreateOccurrenceParams {
	doc := buildOccurrenceDocument(f, source)
	return repo.CreateOccurrenceParams{
		Title:           f.Title,
		Description:     textPtr(f.Description),
		Severity:        severityStr(f.Severity),
		SeverityRank:    severityRank(f.Severity),
		Score:           scoreToNumeric(f.Score),
		ToolName:        source,
		LocationSummary: textPtr(f.Location),
		Display:         mustMarshal(doc.Display),
		Metadata:        mustMarshal(doc.Metadata),
	}
}

// canonicalDimensionKeys is the persisted snake_case vocabulary (domain
// constants); the ingest path persists dimensions through it. Keeping the
// set here as the single validator prevents extension keys from silently
// becoming identity or waiver inputs.
var canonicalDimensionKeys = map[string]struct{}{
	domain.DimVulnerabilityID: {},
	domain.DimAlias:           {},
	domain.DimPURL:            {},
	domain.DimPackageName:     {},
	domain.DimEcosystem:       {},
	domain.DimInstalledVer:    {},
	domain.DimFixedVersion:    {},
	domain.DimRuleID:          {},
	domain.DimFile:            {},
	domain.DimLine:            {},
	domain.DimResource:        {},
	domain.DimSource:          {},
}

// isCanonicalDimension reports whether a dimension key is part of the
// persisted canonical vocabulary. Non-canonical keys are dropped before
// persistence (with a marker in the observation payload where useful) so
// they can never become gate/waiver inputs.
func isCanonicalDimension(key string) bool {
	_, ok := canonicalDimensionKeys[key]
	return ok
}
