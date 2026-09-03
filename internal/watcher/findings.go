// This file holds the pure decision logic that turns one (advisory,
// inventory purl) pair into watcher action: create a cve_watcher finding,
// or skip it because a scan-derived finding already covers the pair. It
// contains no database, HTTP, or daemon code — the poll loop supplies
// context, the gap-check callback, and persistence. Every function here
// is deterministic: the same inputs always produce the same decision, so
// a re-poll (idempotent) produces identical output.
package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/xMinhx/specht/internal/cvss"
	"github.com/xMinhx/specht/internal/scanner"
)

const (
	// FindingKindCVEWatcher is the finding kind seeded by migration 000017
	// for findings created by the CVE feed watcher.
	FindingKindCVEWatcher = "cve_watcher"
	// DimensionSourceValue is the dim_key='source' value carried by watcher
	// findings so dimension-based waivers and the gate filter can
	// identify them.
	DimensionSourceValue = "cve_watcher"

	// EventAutoRuleApplied and EventAutoRuleSkipped are the audit event
	// types emitted when a watcher finding is created or suppressed
	// (migration 000009).
	EventAutoRuleApplied = "auto_rule_applied"
	EventAutoRuleSkipped = "auto_rule_skipped"
)

// Advisory mirrors the subset of the OSV schema
// (https://ossf.github.io/osv-schema/) the watcher consumes. The HTTP
// client decodes querybatch responses directly into this type, and
// DecideFinding consumes it. Affected reuses the matcher's type, which
// carries OSV json tags for direct decoding.
type Advisory struct {
	ID        string             `json:"id"`
	Aliases   []string           `json:"aliases"`
	Summary   string             `json:"summary"`
	Details   string             `json:"details"`
	Published string             `json:"published"`
	Modified  string             `json:"modified"`
	Severity  []AdvisorySeverity `json:"severity"`
	Affected  []Affected         `json:"affected"`
	Refs      []AdvisoryRef      `json:"references"`
	// Raw holds the exact upstream querybatch JSON bytes for this advisory,
	// captured by the HTTP client from the raw response body. Evidence
	// persistence uses these bytes verbatim: a re-marshal of this struct
	// silently drops database_specific, credits, and
	// affected[].database_specific, so the raw form is the provenance
	// record, not the decoded subset.
	Raw []byte `json:"-"`
}

// AdvisorySeverity is one OSV "severity[]" entry. The Score field carries a
// CVSS vector string (for example "CVSS:3.1/AV:N/AC:L/...").
type AdvisorySeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// AdvisoryRef is one OSV "references[]" entry.
type AdvisoryRef struct {
	URL string `json:"url"`
}

// DecideInput is everything DecideFinding needs for one (advisory,
// inventory purl) pair. Purl is the normalized versioned purl from the
// project inventory (pkg:npm/lodash@4.17.19); Version comes from the same
// inventory row. Ecosystem is the OSV-canonical ecosystem name the pair was
// queried under (the daemon derives it from the stored case via OSVEcosystem
// when grouping), so the matcher compares it against the advisory's canonical
// affected[].ecosystem under one mapping; the watcher still normalizes the
// stored dimension value to lowercase — watcher code is the single
// normalization point, not each parser.
type DecideInput struct {
	ProjectID string
	Advisory  Advisory
	Purl      string
	Version   string
	Ecosystem string
}

// GapCheck reports whether a scan-derived finding already covers the
// (project, name-level purl, candidate advisory ids) pair. The poll loop
// supplies the implementation backed by the FindingExistsForPurlAndCve
// query; tests inject a stub. An error aborts the decision so a broken
// gap check fails the poll instead of double-creating findings.
type GapCheck func(ctx context.Context, projectID, purlName string, candidateIDs []string) (bool, error)

// Decision is the outcome of evaluating one pair: create the finding, or
// skip it with a reason.
type Decision struct {
	// Created is true when the watcher must persist a new finding.
	Created bool
	// SkipReason explains why the finding was not created (gap-fill
	// suppression, no affected entry, ...). Empty when Created is true.
	SkipReason string
	// Finding carries the full finding payload when Created is true.
	Finding FindingPayload
	// Event is the audit event to log: auto_rule_applied when Created,
	// auto_rule_skipped when a scan-derived finding suppressed creation.
	// It is nil when the pair produced no event title (for example an
	// advisory that does not affect the version at all, where there is no
	// finding to attach an event to). The poll loop attaches the skipped
	// event to the suppressing finding when it can identify it.
	Event *Event
	// Evidence is the upstream advisory JSON, stored as a provenance
	// artifact per finding (design: provenance). Non-nil only when Created.
	Evidence []byte
}

// FindingPayload is the watcher's plan for a cve_watcher finding: every
// value the poll loop needs to persist the finding row, its occurrence,
// and its scan-equivalent dimensions.
type FindingPayload struct {
	ProjectID    string
	FindingKind  string
	Fingerprint  string
	Title        string
	Description  string
	Severity     string
	SeverityRank int16
	Score        float64
	Remediation  string
	Dimensions   []scanner.Dimension
	Display      map[string]any
	Metadata     map[string]any
}

// Event is the audit event the poll loop persists for a decision. Field
// names match the finding_events columns; empty values map to NULL.
type Event struct {
	EventType string
	OldValue  string
	NewValue  string
	Comment   string
	Changes   []byte
}

// DecideFinding evaluates one (advisory, purl) pair and returns the
// watcher's decision. It is deterministic and performs no I/O other than
// the injected gapCheck callback.
//
// Decision order:
//  1. Normalize identifiers (primary CVE > GHSA > other; aliases sorted).
//  2. Guard against unusable input (no identifiers, empty purl).
//  3. Select the affected[] entry matching the inventory ecosystem and
//     version via the matcher; unmatched pairs are skipped.
//  4. Gap-fill check at name-level purl against every candidate id.
//  5. Create: fingerprint sha256(purl|cve_id), severity from advisory CVSS
//     ratings (unknown/rank 0 when unrated — still created), scan-equivalent
//     dimensions, remediation from fixed versions and references.
func DecideFinding(ctx context.Context, input DecideInput, gapCheck GapCheck) (Decision, error) {
	if gapCheck == nil {
		return Decision{}, fmt.Errorf("gap check callback is required")
	}

	// 1. Primary id + aliases.
	ids := make([]string, 0, len(input.Advisory.Aliases)+1)
	if input.Advisory.ID != "" {
		ids = append(ids, input.Advisory.ID)
	}
	ids = append(ids, input.Advisory.Aliases...)
	primary, aliases := NormalizeAliases(ids)
	if primary == "" {
		// No CVE, GHSA, or OSV id: the pair cannot be fingerprinted or
		// matched against existing vulnerability_id dimensions.
		return skipDecision("advisory has no usable identifiers"), nil
	}

	// 2. Usable input guards (no false positives on malformed inventory).
	if strings.TrimSpace(input.Purl) == "" {
		return skipDecision("inventory purl is empty"), nil
	}
	if strings.TrimSpace(input.Version) == "" {
		return skipDecision("inventory version is empty"), nil
	}

	// 3. Affected-entry selection. OSV querybatch responses are already
	// filtered to the queried package, so matching is ecosystem +
	// version; the matcher never reports unparseable versions affected.
	aff, ok := matchAffected(input.Advisory, input.Ecosystem, input.Version)
	if !ok {
		return skipDecision("no affected entry matches the inventory version"), nil
	}

	nameLevel := purlNameLevel(input.Purl)

	// 4. Gap-fill: never duplicate, never reopen. Any sca finding — open
	// or fixed — with a matching name-level purl dimension and a
	// vulnerability_id dimension equal to any candidate id suppresses
	// creation (any-alias, name-level purl; no reopen logic exists by design).
	candidateIDs := append([]string{primary}, aliases...)
	covered, err := gapCheck(ctx, input.ProjectID, nameLevel, candidateIDs)
	if err != nil {
		return Decision{}, fmt.Errorf("gap check %s/%s: %w", input.Purl, primary, err)
	}
	if covered {
		reason := "already covered by a scan-derived finding"
		ev := &Event{
			EventType: EventAutoRuleSkipped,
			Changes:   eventChanges(input.Advisory.ID, reason),
		}
		return skipDecision(reason, ev), nil
	}

	// 5. Create.
	severity, rank, score, vector := advisorySeverity(input.Advisory.Severity)
	fixed := fixedVersions([]Affected{aff})
	remediation := remediationText(fixed, advisoryURLs(input.Advisory.Refs))
	fingerprint := fingerprint(input.Purl, primary)

	// Provenance: persist the raw upstream bytes when the client captured
	// them; fall back to the decoded subset only for hand-built fixtures.
	evidence := mustJSON(input.Advisory)
	if len(input.Advisory.Raw) > 0 {
		evidence = input.Advisory.Raw
	}

	title := strings.TrimSpace(input.Advisory.Summary)
	if title == "" {
		title = fmt.Sprintf("%s affects %s", primary, nameLevel)
	}

	ecosystem := normalizeEcosystem(input.Ecosystem)

	dims := []scanner.Dimension{
		{Key: "purl", Value: input.Purl},
		{Key: "severity", Value: severity},
		{Key: "cve_id", Value: primary},
		{Key: "component.identity", Value: nameLevel},
		{Key: "source", Value: DimensionSourceValue},
		{Key: "installed_version", Value: input.Version},
	}
	if ecosystem != "" {
		dims = append(dims, scanner.Dimension{Key: "ecosystem", Value: ecosystem})
	}
	for _, a := range aliases {
		dims = append(dims, scanner.Dimension{Key: "alias", Value: a})
	}
	for _, fv := range fixed {
		dims = append(dims, scanner.Dimension{Key: "fixed_version", Value: fv})
	}

	display := map[string]any{
		"purl":         input.Purl,
		"package_name": nameLevel,
		"version":      input.Version,
		"severity":     severity,
		"advisory_id":  input.Advisory.ID,
		"source":       DimensionSourceValue,
	}
	if ecosystem != "" {
		display["ecosystem"] = ecosystem
	}

	metadata := map[string]any{
		"advisory_id":  input.Advisory.ID,
		"aliases":      aliases,
		"severity_src": "osv",
		"source":       DimensionSourceValue,
	}
	if input.Advisory.Published != "" {
		metadata["published"] = input.Advisory.Published
	}
	if input.Advisory.Modified != "" {
		metadata["modified"] = input.Advisory.Modified
	}
	if vector != "" {
		metadata["cvss_vector"] = vector
	}
	if urls := advisoryURLs(input.Advisory.Refs); len(urls) > 0 {
		metadata["references"] = urls
	}

	finding := FindingPayload{
		ProjectID:    input.ProjectID,
		FindingKind:  FindingKindCVEWatcher,
		Fingerprint:  fingerprint,
		Title:        title,
		Description:  input.Advisory.Details,
		Severity:     severity,
		SeverityRank: rank,
		Score:        score,
		Remediation:  remediation,
		Dimensions:   dims,
		Display:      display,
		Metadata:     metadata,
	}

	return Decision{
		Created: true,
		Finding: finding,
		Event: &Event{
			EventType: EventAutoRuleApplied,
			Changes:   eventChanges(input.Advisory.ID, ""),
		},
		Evidence: evidence,
	}, nil
}

// fingerprint is the cve_watcher identity formula from the design:
// sha256(purl@version | cve_id), hex-encoded. The purl is the versioned
// form (pkg:npm/lodash@4.17.19) and cve_id is the advisory's primary id
// (CVE-, GHSA-, or OSV- prefixed as NormalizeAliases decides). Combined
// with the UNIQUE(project_id, finding_kind, fingerprint) constraint this
// gives DB-level idempotency for re-polls.
func fingerprint(purl, primary string) string {
	sum := sha256.Sum256([]byte(purl + "|" + primary))
	return hex.EncodeToString(sum[:])
}

// matchAffected returns the first affected[] entry whose ecosystem matches
// the inventory ecosystem (case-insensitive) and whose region contains
// version. When the inventory ecosystem is known, a differing affected
// ecosystem is a different package identity and is skipped. When the
// inventory ecosystem is EMPTY, an affected entry with a NON-empty ecosystem
// is also skipped — a same-named package in another ecosystem must never
// match an inventory row whose own ecosystem is unknown. Only an affected
// entry with no ecosystem can match an ecosystem-less inventory row.
func matchAffected(ad Advisory, ecosystem, version string) (Affected, bool) {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	for _, aff := range ad.Affected {
		// Real OSV records nest the ecosystem inside affected[].package;
		// prefer that, falling back to the top-level Affected.Ecosystem for
		// hand-built fixtures/tests.
		affEcosystem := aff.Package.Ecosystem
		if affEcosystem == "" {
			affEcosystem = aff.Ecosystem
		}
		affEco := strings.ToLower(strings.TrimSpace(string(affEcosystem)))
		if eco != "" {
			// Inventory ecosystem known: skipping a differing affected
			// ecosystem is a different-package guard, not a version check.
			if affEco != "" && affEco != eco {
				continue
			}
		} else if affEco != "" {
			// Inventory ecosystem unknown: never let a same-named package
			// in another ecosystem match.
			continue
		}
		if VersionAffected(aff, version) {
			return aff, true
		}
	}
	return Affected{}, false
}

// purlNameLevel strips the version from a purl, producing the name-level
// identity used for the gap-fill join and the component.identity dimension.
// Version-less purls pass through unchanged, matching the osv-scanner
// finding contract. Non-purl inputs (scanner PkgID-style fallbacks) fall
// back to cutting at the last '@'.
func purlNameLevel(purl string) string {
	if pkgType, name, _ := scanner.SplitPURL(purl); pkgType != "" && name != "" {
		return "pkg:" + pkgType + "/" + name
	}
	if i := strings.LastIndexByte(purl, '@'); i >= 0 {
		return purl[:i]
	}
	return purl
}

// normalizeEcosystem is the single ecosystem normalization point for the
// watcher: the ecosystem dimension value is always lowercase, regardless
// of the mixed case parsers store.
func normalizeEcosystem(ecosystem string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem))
}

// advisorySeverity resolves an advisory's CVSS ratings to the finding's
// severity string, rank, numeric score, and winning vector. The highest
// parseable score wins; ratings that cannot be parsed are ignored. The
// distinguishing flag is whether ANY rating parsed — not the score's sign —
// so a legitimate CVSS 2.0 vector scoring exactly 0.0
// (CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:N) still maps to low/rank 1 rather than
// unknown. An advisory with no usable rating yields severity 'unknown',
// rank 0 — visible on dashboards but never gating
// (design: unrated advisory policy) — and the finding is still created.
func advisorySeverity(ratings []AdvisorySeverity) (severity string, rank int16, score float64, vector string) {
	var (
		best  float64
		rated bool
	)
	for _, r := range ratings {
		v := strings.TrimSpace(r.Score)
		if v == "" {
			continue
		}
		s, err := cvss.Calculate(v)
		if err != nil {
			continue
		}
		if !rated || s > best {
			best, vector = s, v
			rated = true
		}
	}
	if !rated {
		return "unknown", 0, 0, ""
	}
	switch {
	case best >= 9.0:
		return "critical", 4, best, vector
	case best >= 7.0:
		return "high", 3, best, vector
	case best >= 4.0:
		return "medium", 2, best, vector
	default:
		return "low", 1, best, vector
	}
}

// fixedVersions collects the distinct canonical fix versions across all
// affected[] entries' range events ("fixed" bounds), sorted for
// determinism. Non-semver bounds are dropped, mirroring the matcher's
// conservative semver-only stance.
func fixedVersions(affs []Affected) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, aff := range affs {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if fv := normalizeVersion(ev.Fixed); fv != "" {
					if _, ok := seen[fv]; !ok {
						seen[fv] = struct{}{}
						out = append(out, fv)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// remediationText builds the finding's remediation guidance from the fixed
// versions and the advisory's first reference URL. Deterministic: fixed
// versions are pre-sorted, and reference order is the OSV-published order.
func remediationText(fixed []string, refs []string) string {
	var parts []string
	if len(fixed) > 0 {
		parts = append(parts, "Upgrade to "+strings.Join(fixed, ", "))
	}
	if len(refs) > 0 {
		parts = append(parts, "See "+refs[0])
	}
	return strings.Join(parts, "; ")
}

// advisoryURLs extracts non-empty, deduplicated reference URLs in
// published order.
func advisoryURLs(refs []AdvisoryRef) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range refs {
		u := strings.TrimSpace(r.URL)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

// eventChanges builds the auto_rule event payload: the watcher source and
// the upstream advisory id (brief: metadata source/advisory_id), plus the
// skip reason when the event is auto_rule_skipped.
func eventChanges(advisoryID, reason string) []byte {
	m := map[string]any{
		"source":      DimensionSourceValue,
		"advisory_id": advisoryID,
	}
	if reason != "" {
		m["reason"] = reason
	}
	return mustJSON(m)
}

// skipDecision assembles a skip outcome with an optional attached event.
func skipDecision(reason string, ev ...*Event) Decision {
	var event *Event
	if len(ev) > 0 {
		event = ev[0]
	}
	return Decision{Created: false, SkipReason: reason, Event: event}
}

// mustJSON marshals v into JSON, returning nil on the (impossible for the
// values used here) error case so callers stay simple.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
