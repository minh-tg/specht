package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/cvedetail"
	"github.com/minh-tg/specht/internal/port"
)

// ErrNotCVE reports a finding whose vulnerability_id is not a CVE identifier.
var ErrNotCVE = errors.New("finding has no CVE identifier")

// CVEOccurrenceReader reads the newest occurrence per tool for a finding,
// including CVE watcher occurrences that have no report.
type CVEOccurrenceReader interface {
	ListLatestCVEOccurrences(ctx context.Context, findingID string) ([]cvedetail.Occurrence, error)
}

// CVEProviderResolver serves cached provider answers and schedules fetches
// in the background. *cvedetail.Resolver implements it.
type CVEProviderResolver interface {
	Providers() []string
	Lookup(ctx context.Context, cveID string, need bool) ([]cvedetail.ProviderLookup, error)
	Status(ctx context.Context) ([]cvedetail.ProviderStatus, error)
}

// IntelRecord is the EPSS and KEV data the CVE detail read shows. Empty
// strings and zero values mean the feed did not say.
type IntelRecord struct {
	EPSS           float64
	EPSSDate       string
	EPSSPercentile float64
	KEV            bool
	KEVDateAdded   string
	// KEVDueDate is YYYY-MM-DD.
	KEVDueDate string
	// KEVRansomware is "Known" or "Unknown" as the KEV catalog spells it.
	KEVRansomware string
	FetchedAt     time.Time
}

// IntelLookup reads cached EPSS and KEV data for one CVE without fetching.
type IntelLookup interface {
	LookupIntel(cveID string) (IntelRecord, bool)
}

// CVEDetailDeps wires the CVE detail read. Occurrences is required for the
// endpoint; a nil Providers means no provider is configured and a nil Intel
// leaves EPSS and KEV out.
type CVEDetailDeps struct {
	Occurrences CVEOccurrenceReader
	Providers   CVEProviderResolver
	Intel       IntelLookup
}

// Provenance kinds.
const (
	ProvenanceScanReport = "scan_report"
	ProvenanceWatcher    = "watcher"
	ProvenanceProvider   = "provider"
	ProvenanceFeed       = "feed"
)

// CVEProvenance says where one datum came from. A scan report names the tool,
// the report and when it was observed; a provider or feed names itself and
// when it was fetched.
type CVEProvenance struct {
	Kind       string     `json:"kind"`
	Tool       string     `json:"tool,omitempty"`
	ReportID   *string    `json:"report_id,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Provider   string     `json:"provider,omitempty"`
	FetchedAt  *time.Time `json:"fetched_at,omitempty"`
	// Detail carries the scoring party a source names, such as
	// "nvd@nist.gov primary".
	Detail string `json:"detail,omitempty"`
}

// CVECVSS is one CVSS vector with its score and metrics.
type CVECVSS struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	// BaseScore is computed from the vector; nil when the vector does not parse.
	BaseScore *float64 `json:"base_score"`
	// ReportedScore is the score the source printed next to the vector.
	ReportedScore *float64           `json:"reported_score"`
	Severity      *string            `json:"severity"`
	Valid         bool               `json:"valid"`
	Metrics       []cvedetail.Metric `json:"metrics"`
	Provenance    CVEProvenance      `json:"provenance"`
}

// CVEEPSS is the EPSS probability and percentile on a date.
type CVEEPSS struct {
	Probability float64       `json:"probability"`
	Percentile  *float64      `json:"percentile"`
	Date        *string       `json:"date"`
	Provenance  CVEProvenance `json:"provenance"`
}

// CVEKEV is CISA KEV membership.
type CVEKEV struct {
	Listed             bool          `json:"listed"`
	DateAdded          *string       `json:"date_added"`
	DueDate            *string       `json:"due_date"`
	KnownRansomwareUse *string       `json:"known_ransomware_use"`
	Provenance         CVEProvenance `json:"provenance"`
}

// CVECWE is one CWE identifier.
type CVECWE struct {
	ID         string        `json:"id"`
	Provenance CVEProvenance `json:"provenance"`
}

// CVEDate is a dated value with its source.
type CVEDate struct {
	Value      time.Time     `json:"value"`
	Provenance CVEProvenance `json:"provenance"`
}

// CVEReference is one https reference link.
type CVEReference struct {
	URL        string        `json:"url"`
	Provenance CVEProvenance `json:"provenance"`
}

// CVEProviderState is one provider's part in this answer.
type CVEProviderState struct {
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
}

// CVEDetailResponse is GET /api/v1/findings/{id}/cve.
type CVEDetailResponse struct {
	CVEID string `json:"cve_id"`
	// Pending is true while a provider fetch is scheduled or running; the
	// client may read again shortly.
	Pending     bool               `json:"pending"`
	CVSS        []CVECVSS          `json:"cvss"`
	EPSS        *CVEEPSS           `json:"epss"`
	KEV         *CVEKEV            `json:"kev"`
	CWEs        []CVECWE           `json:"cwes"`
	PublishedAt *CVEDate           `json:"published_at"`
	ModifiedAt  *CVEDate           `json:"modified_at"`
	References  []CVEReference     `json:"references"`
	Providers   []CVEProviderState `json:"providers"`
}

// Bounds on what one response lists.
const (
	maxCVSSPerSource  = 6
	maxCVEReferences  = 20
	maxCVECWEs        = 20
	maxCVEVectorBytes = 256
)

// GetFindingCVE returns the CVE evaluation details of a finding: every CVSS
// vector the scan reports carry, EPSS and KEV from the intel feeds, CWEs,
// dates and references, each with its provenance. When the reports are
// incomplete it adds what the configured providers have cached and schedules
// a background fetch for the rest. It never waits on a provider and never
// fails because of one.
func (u *Usecases) GetFindingCVE(ctx context.Context, findingID string) (*CVEDetailResponse, error) {
	id, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	f, err := u.deps.Stores.Findings.GetByID(ctx, id.String())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, fmt.Errorf("get finding: %w", ErrFindingNotFound)
		}
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if err := u.checkFindingVisibility(ctx, f.ProjectID); err != nil {
		return nil, err
	}
	dims, err := u.deps.Stores.Findings.ListDimensions(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("get finding dimensions: %w", err)
	}
	cve := findingCVE(dims, cvedetail.ValidCVEID)
	if cve == "" {
		return nil, ErrNotCVE
	}
	if u.deps.CVEDetail.Occurrences == nil {
		return nil, errors.New("cve detail: occurrence reader not configured")
	}
	occurrences, err := u.deps.CVEDetail.Occurrences.ListLatestCVEOccurrences(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("list finding occurrences: %w", err)
	}

	resp := &CVEDetailResponse{CVEID: cve, CVSS: []CVECVSS{}, CWEs: []CVECWE{}, References: []CVEReference{}}
	b := cveBuilder{resp: resp, cwes: map[string]bool{}, refs: map[string]bool{}}
	for _, occ := range occurrences {
		b.addOccurrence(occ)
	}
	need := reportIncomplete(resp)
	u.attachCVEIntel(cve, resp)
	resp.Providers = u.attachCVEProviders(cvedetail.WithOwner(ctx, f.ProjectID), cve, need, &b)
	for _, p := range resp.Providers {
		if p.Status == cvedetail.LookupPending {
			resp.Pending = true
		}
	}
	return resp, nil
}

// reportIncomplete is the rule for asking providers: the reports carry no
// valid CVSS v3.0, v3.1 or v4.0 vector, or they carry neither a CWE nor a
// published date. A report with only a v2 vector counts as incomplete.
func reportIncomplete(resp *CVEDetailResponse) bool {
	modern := false
	for _, c := range resp.CVSS {
		if c.Valid && (c.Version == "3.0" || c.Version == "3.1" || c.Version == "4.0") {
			modern = true
			break
		}
	}
	return !modern || (len(resp.CWEs) == 0 && resp.PublishedAt == nil)
}

func (u *Usecases) attachCVEIntel(cve string, resp *CVEDetailResponse) {
	if u.deps.CVEDetail.Intel == nil {
		return
	}
	rec, ok := u.deps.CVEDetail.Intel.LookupIntel(cve)
	if !ok {
		return
	}
	var fetched *time.Time
	if !rec.FetchedAt.IsZero() {
		t := rec.FetchedAt
		fetched = &t
	}
	if rec.EPSSDate != "" || rec.EPSS > 0 {
		resp.EPSS = &CVEEPSS{
			Probability: rec.EPSS,
			Percentile:  positiveOrNil(rec.EPSSPercentile),
			Date:        stringOrNil(rec.EPSSDate),
			Provenance:  CVEProvenance{Kind: ProvenanceFeed, Provider: "epss", FetchedAt: fetched},
		}
	}
	// KEV absence is not a negative assertion: a missing record may mean the
	// catalog fetch failed, so only positive membership is shown.
	if rec.KEV {
		resp.KEV = &CVEKEV{
			Listed:             true,
			DateAdded:          stringOrNil(rec.KEVDateAdded),
			DueDate:            stringOrNil(rec.KEVDueDate),
			KnownRansomwareUse: stringOrNil(rec.KEVRansomware),
			Provenance:         CVEProvenance{Kind: ProvenanceFeed, Provider: "kev", FetchedAt: fetched},
		}
	}
}

// attachCVEProviders adds the cached provider answers and lists every known
// provider with its status. Provider values sit beside the report's values:
// they never replace a vector, CWE or date the report carries.
func (u *Usecases) attachCVEProviders(ctx context.Context, cve string, need bool, b *cveBuilder) []CVEProviderState {
	var out []CVEProviderState
	seen := map[string]bool{}
	if r := u.deps.CVEDetail.Providers; r != nil && len(r.Providers()) > 0 {
		lookups, err := r.Lookup(ctx, cve, need)
		if err != nil {
			slog.Warn("cve detail cache read failed", "cve", cve, "error", err)
			for _, name := range r.Providers() {
				out = append(out, CVEProviderState{Name: name, Status: cvedetail.LookupError})
				seen[name] = true
			}
		}
		for _, l := range lookups {
			seen[l.Name] = true
			out = append(out, CVEProviderState{Name: l.Name, Status: l.Status, FetchedAt: l.FetchedAt})
			if l.Status == cvedetail.LookupFound && l.Record != nil {
				b.addProviderRecord(l.Name, l.FetchedAt, *l.Record)
			}
		}
	}
	for _, name := range cvedetail.KnownProviders {
		if !seen[name] {
			out = append(out, CVEProviderState{Name: name, Status: cvedetail.LookupDisabled})
		}
	}
	return out
}

// cveBuilder accumulates the response, keeping the first source of each CWE
// and reference so a report value is never listed again under a provider.
type cveBuilder struct {
	resp *CVEDetailResponse
	cwes map[string]bool
	refs map[string]bool
}

// cveSpechtMetadata is the canonical namespace of an occurrence's metadata.
// cvss_all holds every vector a scanner reported; cvss, written by older
// releases with capitalised keys, holds one.
type cveSpechtMetadata struct {
	CVSSAll []struct {
		Version string  `json:"version"`
		Vector  string  `json:"vector"`
		Score   float64 `json:"score"`
		Source  string  `json:"source"`
	} `json:"cvss_all"`
	CVSS *struct {
		Version string  `json:"Version"`
		Vector  string  `json:"Vector"`
		Score   float64 `json:"Score"`
	} `json:"cvss"`
}

type rawCVSS struct {
	version, vector, source string
	score                   float64
}

func (b *cveBuilder) addOccurrence(occ cvedetail.Occurrence) {
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(occ.Metadata, &meta); err != nil {
		return
	}
	observed := occ.ObservedAt
	prov := CVEProvenance{Kind: ProvenanceScanReport, Tool: occ.ToolName, ReportID: occ.ReportID, ObservedAt: &observed}
	// Report occurrences namespace producer keys by tool; watcher occurrences
	// store bare keys taken from the OSV advisory.
	prefix := occ.ToolName + "."
	if occ.ReportID == nil {
		prov.Kind = ProvenanceWatcher
		prov.Detail = "osv"
		prefix = ""
	}

	var vectors []rawCVSS
	if raw, ok := meta["specht"]; ok {
		var sm cveSpechtMetadata
		if json.Unmarshal(raw, &sm) == nil {
			for _, c := range sm.CVSSAll {
				vectors = append(vectors, rawCVSS{version: c.Version, vector: c.Vector, source: c.Source, score: c.Score})
			}
			if len(vectors) == 0 && sm.CVSS != nil {
				vectors = append(vectors, rawCVSS{version: sm.CVSS.Version, vector: sm.CVSS.Vector, score: sm.CVSS.Score})
			}
		}
	}
	if len(vectors) == 0 && occ.ReportID == nil {
		if v := metaString(meta, "cvss_vector"); v != "" {
			vectors = append(vectors, rawCVSS{vector: v})
		}
	}
	seen := map[string]bool{}
	for _, v := range vectors {
		if len(seen) == maxCVSSPerSource {
			break
		}
		vector := cvedetail.NormalizeVector(v.vector)
		if vector == "" || len(vector) > maxCVEVectorBytes || seen[vector] {
			continue
		}
		seen[vector] = true
		p := prov
		p.Detail = firstNonEmpty(v.source, prov.Detail)
		if c, ok := buildCVSS(v.version, vector, v.score, p); ok {
			b.resp.CVSS = append(b.resp.CVSS, c)
		}
	}

	for _, k := range []string{"cwe_ids", "cwes"} {
		for _, id := range cweIDs(meta[prefix+k]) {
			b.addCWE(id, prov)
		}
	}
	if t := cvedetail.ParseTime(metaString(meta, prefix+"published")); t != nil && b.resp.PublishedAt == nil {
		b.resp.PublishedAt = &CVEDate{Value: *t, Provenance: prov}
	}
	for _, k := range []string{"modified", "last_modified"} {
		if t := cvedetail.ParseTime(metaString(meta, prefix+k)); t != nil && b.resp.ModifiedAt == nil {
			b.resp.ModifiedAt = &CVEDate{Value: *t, Provenance: prov}
		}
	}
	if v := metaString(meta, prefix+"primary_url"); v != "" {
		b.addReference(v, prov)
	}
	for _, v := range metaStrings(meta[prefix+"references"]) {
		b.addReference(v, prov)
	}
}

func (b *cveBuilder) addProviderRecord(name string, fetchedAt *time.Time, rec cvedetail.Record) {
	prov := CVEProvenance{Kind: ProvenanceProvider, Provider: name, FetchedAt: fetchedAt}
	for i, c := range rec.CVSS {
		if i == maxCVSSPerSource {
			break
		}
		vector := cvedetail.NormalizeVector(c.Vector)
		if vector == "" || len(vector) > maxCVEVectorBytes {
			continue
		}
		p := prov
		p.Detail = strings.TrimSpace(c.Source + " " + strings.ToLower(c.Type))
		if entry, ok := buildCVSS(c.Version, vector, c.Score, p); ok {
			b.resp.CVSS = append(b.resp.CVSS, entry)
		}
	}
	for _, id := range rec.CWEs {
		b.addCWE(id, prov)
	}
	if rec.Published != nil && b.resp.PublishedAt == nil {
		b.resp.PublishedAt = &CVEDate{Value: *rec.Published, Provenance: prov}
	}
	if rec.Modified != nil && b.resp.ModifiedAt == nil {
		b.resp.ModifiedAt = &CVEDate{Value: *rec.Modified, Provenance: prov}
	}
	for _, ref := range rec.References {
		b.addReference(ref, prov)
	}
}

func (b *cveBuilder) addCWE(id string, prov CVEProvenance) {
	if b.cwes[id] || len(b.resp.CWEs) == maxCVECWEs {
		return
	}
	b.cwes[id] = true
	b.resp.CWEs = append(b.resp.CWEs, CVECWE{ID: id, Provenance: prov})
}

func (b *cveBuilder) addReference(raw string, prov CVEProvenance) {
	raw = strings.TrimSpace(raw)
	if b.refs[raw] || len(b.resp.References) == maxCVEReferences || len(raw) > 2048 || !cvedetail.IsHTTPSURL(raw) {
		return
	}
	b.refs[raw] = true
	b.resp.References = append(b.resp.References, CVEReference{URL: raw, Provenance: prov})
}

// buildCVSS scores a normalized vector. The version comes from the vector
// prefix; the source's own label is used only when the prefix is unknown,
// and such a vector is reported as not valid. A vector whose version is
// unknown either way is dropped.
func buildCVSS(label, vector string, reported float64, prov CVEProvenance) (CVECVSS, bool) {
	out := CVECVSS{Vector: vector, Metrics: []cvedetail.Metric{}, Provenance: prov}
	out.Version = cvedetail.VectorVersion(vector)
	if out.Version == "" {
		switch label {
		case "2.0", "3.0", "3.1", "4.0":
			out.Version = label
		default:
			return CVECVSS{}, false
		}
	}
	if reported > 0 {
		r := reported
		out.ReportedScore = &r
	}
	if score, ok := cvedetail.ScoreVector(vector); ok {
		out.Valid = true
		out.BaseScore = &score
		out.Metrics = cvedetail.Metrics(vector)
		band := cvedetail.SeverityBand(out.Version, score)
		out.Severity = &band
	} else if out.ReportedScore != nil {
		band := cvedetail.SeverityBand(out.Version, *out.ReportedScore)
		out.Severity = &band
	}
	return out, true
}

var cweNumber = regexp.MustCompile(`^(?:CWE-)?([0-9]{1,6})$`)

// cweIDs reads a CWE list a scanner stored: strings like "CWE-79" (trivy) or
// numbers like 79 (CycloneDX). Anything else is ignored.
func cweIDs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []any
	if json.Unmarshal(raw, &items) != nil {
		var one any
		if json.Unmarshal(raw, &one) != nil {
			return nil
		}
		items = []any{one}
	}
	var out []string
	for _, it := range items {
		var s string
		switch v := it.(type) {
		case string:
			s = strings.ToUpper(strings.TrimSpace(v))
		case float64:
			if v != float64(int64(v)) || v < 0 {
				continue
			}
			s = strconv.FormatInt(int64(v), 10)
		default:
			continue
		}
		if m := cweNumber.FindStringSubmatch(s); m != nil {
			out = append(out, "CWE-"+m[1])
		}
	}
	return out
}

func metaString(meta map[string]json.RawMessage, key string) string {
	raw, ok := meta[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func metaStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func positiveOrNil(v float64) *float64 {
	if v <= 0 {
		return nil
	}
	return &v
}

func stringOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// findingCVE returns the CVE a finding is about: its vulnerability_id when
// that is a CVE, otherwise the first CVE among its alias dimensions. A
// scanner can use a GHSA as the primary id and carry the CVE as an alias;
// the alias is a valid identity for the provider and intel lookups. isCVE
// decides what counts as a CVE id. Empty means the finding has none.
func findingCVE(dims []port.FindingDimension, isCVE func(string) bool) string {
	for _, d := range dims {
		if d.Key == "vulnerability_id" && isCVE(d.Value) {
			return d.Value
		}
	}
	for _, d := range dims {
		if d.Key == "alias" && isCVE(d.Value) {
			return d.Value
		}
	}
	return ""
}
