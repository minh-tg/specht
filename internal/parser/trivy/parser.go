package trivy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Results       []trivyResult `json:"Results"`
}

type legacyTrivyReport []trivyResult

type trivyResult struct {
	Target          string           `json:"Target"`
	Class           string           `json:"Class"`
	Type            string           `json:"Type"`
	Packages        []trivyPackage   `json:"Packages"`
	Vulnerabilities []trivyVuln      `json:"Vulnerabilities"`
	Secrets         []trivySecret    `json:"Secrets"`
	Misconfigs      []trivyMisconfig `json:"Misconfigurations"`
}

type trivyPackage struct {
	Name       string             `json:"Name"`
	Version    string             `json:"Version"`
	PkgID      string             `json:"PkgID"`
	Identifier trivyPkgIdentifier `json:"Identifier"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgID            string               `json:"PkgID"`
	PkgName          string               `json:"PkgName"`
	PkgIdentifier    trivyPkgIdentifier   `json:"PkgIdentifier"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Status           string               `json:"Status"`
	Layer            *trivyLayer          `json:"Layer"`
	Severity         string               `json:"Severity"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	PublishedDate    *string              `json:"PublishedDate"`
	LastModifiedDate *string              `json:"LastModifiedDate"`
	CweIDs           []string             `json:"CweIDs"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	PrimaryURL       string               `json:"PrimaryURL"`
	DataSource       *trivyDataSource     `json:"DataSource"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type trivyLayer struct {
	DiffID string `json:"DiffID"`
}

type trivyCVSS struct {
	V4Score  float64 `json:"V4Score"`
	V4Vector string  `json:"V4Vector"`
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V2Vector string  `json:"V2Vector"`
}

type trivyDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type trivySecret struct {
	RuleID   string          `json:"RuleID"`
	Category string          `json:"Category"`
	Severity string          `json:"Severity"`
	Title    string          `json:"Title"`
	Match    string          `json:"Match"`
	Code     json.RawMessage `json:"Code"`
	Layer    *trivyLayer     `json:"Layer"`
	// StartLine and EndLine are the 1-based lines of the match.
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}

type trivyMisconfig struct {
	ID       string      `json:"ID"`
	RuleID   string      `json:"RuleID"`
	Severity string      `json:"Severity"`
	Title    string      `json:"Title"`
	Message  string      `json:"Message"`
	Layer    *trivyLayer `json:"Layer"`
	// CauseMetadata names the resource a check failed on (for Terraform the
	// address, such as aws_s3_bucket.logs) and its line range.
	CauseMetadata trivyCause `json:"CauseMetadata"`
}

type trivyCause struct {
	Resource  string `json:"Resource"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

// Finding kind constants this adapter emits. Trivy emits multiple kinds from
// one report (sca, secret, iac), which is why capability discovery is
// per-descriptor rather than a single FindingKind() method.
const (
	kindSCA    = "sca"
	kindSecret = "secret"
	kindIaC    = "iac"
)

// Scanner adapts trivy JSON output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the trivy adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:        "trivy",
		DisplayName: "Trivy",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `trivy fs --format json -o trivy.json .`,
				TestedWith: "Trivy 0.74.0",
				Note:       "`trivy image` and `trivy config` write the same format.",
			},
		},
		Version:               "2",
		ContractVersion:       1,
		FingerprintVersion:    fingerprintVersion,
		FindingKinds:          []scanner.FindingKind{kindSCA, kindSecret, kindIaC},
		ScanTypes:             []domain.ScanType{domain.ScanTypeImage, domain.ScanTypeIaC, domain.ScanTypeFilesystem},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. A scan that names its artifact or has a result
// with a target is Trivy's for certain. A bare schema version could be a clean
// scan from another version, so it is only possible. Trivy output is an object
// (or, in the legacy form, a list of results), never an empty list.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok {
		return scanner.NotRecognized
	}
	if shape.IsArray() {
		for _, el := range shape.Array {
			if hasTarget(el) {
				return scanner.Definite
			}
		}
		return scanner.NotRecognized
	}
	if !shape.IsObject() {
		return scanner.NotRecognized
	}
	if shape.String("ArtifactName") != "" {
		return scanner.Definite
	}
	results, _ := shape.List("Results")
	for _, el := range results {
		if hasTarget(el) {
			return scanner.Definite
		}
	}
	if shape.Has("SchemaVersion") {
		return scanner.Possible
	}
	return scanner.NotRecognized
}

func hasTarget(raw json.RawMessage) bool {
	var r struct {
		Target string `json:"Target"`
	}
	return json.Unmarshal(raw, &r) == nil && r.Target != ""
}

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{"", "Results", "Packages", "Vulnerabilities", "Secrets", "Misconfigurations"}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("trivy")
	}
	report, err := decode(data)
	if err != nil {
		return nil, scanner.Malformed("trivy", err)
	}

	return parseutil.Hardened(convert(budget, report))
}

// RedactRaw scrubs secret material from raw Trivy evidence and caps the result
// at scanner.RawEvidenceCap. A secret finding carries the matched text in Match
// and the surrounding source in Code, so both keys are redacted at any depth.
// Data that cannot be decoded is an error and no output comes back.
func (s *Scanner) RedactRaw(data []byte) ([]byte, error) {
	return parseutil.RedactRawJSON("trivy", data, "Match", "Code")
}

func decode(data []byte) (trivyReport, error) {
	var report trivyReport
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &report); err != nil {
			return trivyReport{}, err
		}
		return report, nil
	}

	var legacy legacyTrivyReport
	if err := json.Unmarshal(trimmed, &legacy); err != nil {
		return trivyReport{}, err
	}
	return trivyReport{Results: legacy}, nil
}

func convert(budget *parseutil.Budget, report trivyReport) (*domain.NormalizedReport, error) {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		// Trivy scans its whole target, so a result class it listed is
		// examined in full. Completeness is settled below from the classes
		// the document actually lists.
		Completeness: domain.CompletenessComplete,
		ScanType:     domain.ScanTypeImage,
		Findings:     nil,
	}

	nr.Target = reportTarget(report)

	covered := map[string]bool{}
	for _, result := range report.Results {
		switch result.Class {
		case "os-pkgs", "lang-pkgs":
			covered["sca"] = true
		case "config":
			covered["iac"] = true
		case "secret":
			covered["secret"] = true
		}
		if len(result.Vulnerabilities) > 0 {
			covered["sca"] = true
		}
		if len(result.Secrets) > 0 {
			covered["secret"] = true
		}
		if len(result.Misconfigs) > 0 {
			covered["iac"] = true
		}
		// full package inventory, vulnerable or not
		for _, add := range []func(*parseutil.Budget, *domain.NormalizedReport, trivyResult) error{addPackages, addVulns, addSecrets, addMisconfigs} {
			if err := add(budget, nr, result); err != nil {
				return nil, err
			}
		}
	}
	numberSecrets(nr.Findings)
	// A result class is the only evidence Trivy gives that a category was
	// scanned. Without one, an empty report proves no category is clean.
	nr.CoveredFindingKinds = trivyCoveredKinds(covered)
	if len(nr.CoveredFindingKinds) == 0 {
		nr.Completeness = domain.CompletenessUnknown
	}

	return nr, nil
}

// reportTarget names what the scan ran against. ArtifactName is the stable
// name of the scanned artifact (an image reference, a scanned path); a result
// Target is a per-class detail such as "alpine:3.20 (alpine 3.20.3)" or
// whichever lockfile Trivy listed first, so it only names the target when the
// report carries no artifact name.
func reportTarget(report trivyReport) *domain.TargetInfo {
	if len(report.Results) == 0 {
		if report.ArtifactName == "" {
			return nil
		}
		// The same mapping as a scan with results, so a clean scan does not
		// flip the stored kind of a target an earlier scan created.
		kind := artifactKind(report.ArtifactType)
		if kind == "" {
			kind = report.ArtifactType
		}
		return &domain.TargetInfo{Identifier: report.ArtifactName, Kind: kind}
	}
	target := resultTarget(report.Results[0])
	if report.ArtifactName != "" {
		target.Identifier = report.ArtifactName
		if kind := artifactKind(report.ArtifactType); kind != "" {
			target.Kind = kind
		}
	}
	return target
}

// artifactKind maps Trivy's ArtifactType onto target kinds. An unknown type
// returns "" so the caller keeps the kind implied by the result class.
func artifactKind(artifactType string) string {
	switch artifactType {
	case "container_image":
		return "container_image"
	case "filesystem", "repository":
		return "filesystem"
	}
	return ""
}

func resultTarget(first trivyResult) *domain.TargetInfo {
	target := &domain.TargetInfo{Identifier: first.Target}
	switch first.Class {
	case "os-pkgs", "lang-pkgs":
		target.Kind = "container_image"
	case "config":
		target.Kind = "iac"
	case "secret":
		target.Kind = "filesystem"
	default:
		target.Kind = "filesystem"
	}
	return target
}

func addPackages(budget *parseutil.Budget, nr *domain.NormalizedReport, result trivyResult) error {
	cleanTarget := parseutil.CleanFilePath(result.Target)
	for _, p := range result.Packages {
		purl := p.Identifier.PURL
		if purl == "" {
			purl = p.PkgID
		}
		if purl == "" {
			continue
		}
		if err := budget.Add(1); err != nil {
			return err
		}
		nr.Packages = append(nr.Packages, parseutil.HardenPackage(domain.PackageRef{
			PURL:         domain.NormalizePURL(purl),
			Ecosystem:    result.Type,
			Name:         p.Name,
			Version:      p.Version,
			ManifestPath: cleanTarget,
		}))
	}
	return nil
}

func addVulns(budget *parseutil.Budget, nr *domain.NormalizedReport, result trivyResult) error {
	cleanTarget := parseutil.CleanFilePath(result.Target)
	for _, v := range result.Vulnerabilities {
		if err := budget.Add(1); err != nil {
			return err
		}
		purl := v.PkgIdentifier.PURL
		if purl == "" {
			purl = v.PkgID
		}

		dims := []domain.Dimension{
			{Key: domain.DimVulnerabilityID, Value: v.VulnerabilityID},
			{Key: domain.DimPackageName, Value: v.PkgName},
			{Key: domain.DimInstalledVer, Value: v.InstalledVersion},
			{Key: domain.DimPURL, Value: purl},
		}
		if v.FixedVersion != "" {
			dims = append(dims, domain.Dimension{Key: domain.DimFixedVersion, Value: v.FixedVersion})
		}

		ext := map[string]any{
			"target":       cleanTarget,
			"pkg_name":     v.PkgName,
			"pkg_id":       v.PkgID,
			"purl":         purl,
			"status":       v.Status,
			"severity_src": "trivy",
			"cwe_ids":      v.CweIDs,
		}
		if v.Layer != nil {
			ext["layer"] = v.Layer.DiffID
		}
		if v.PublishedDate != nil {
			ext["published"] = *v.PublishedDate
		}
		if v.LastModifiedDate != nil {
			ext["last_modified"] = *v.LastModifiedDate
		}
		if v.PrimaryURL != "" {
			ext["primary_url"] = v.PrimaryURL
		}
		if v.DataSource != nil {
			ext["data_source"] = v.DataSource.URL
		}

		nr.Findings = append(nr.Findings, parseutil.HardenFinding(domain.NormalizedFinding{
			Fingerprint: string(domain.SCAFingerprint(v.VulnerabilityID, purl)),
			FindingKind: kindSCA,
			Title:       v.Title,
			Description: v.Description,
			Severity:    normalizeSeverity(v.Severity),
			Score:       maxCVSSScore(v.CVSS),
			CVSSAll:     cvssRecords(v.CVSS),
			Location:    domain.SCALocation(v.PkgName, v.InstalledVersion, cleanTarget),
			Dimensions:  dims,
			Extensions:  ext,
		}))
	}
	return nil
}

// maxCVSSScore returns the highest available CVSS score for a vulnerability,
// preferring nvd, then redhat, then any vendor source, across CVSS versions.
func maxCVSSScore(cvss map[string]trivyCVSS) float64 {
	if cvss == nil {
		return 0
	}
	for _, source := range []string{"nvd", "redhat"} {
		if c, ok := cvss[source]; ok {
			if score := bestCVSSScore(c); score > 0 {
				return score
			}
		}
	}
	for _, c := range cvss {
		if score := bestCVSSScore(c); score > 0 {
			return score
		}
	}
	return 0
}

// cvssRecords lists every vector Trivy reports, source by source: nvd first,
// then redhat, then the others by name, the same preference maxCVSSScore uses.
// Inside one source the newest version comes first. A score with no vector is
// not a record. Trivy does not say which source is primary.
func cvssRecords(cvss map[string]trivyCVSS) []domain.CVSSRecord {
	sources := make([]string, 0, len(cvss))
	for name := range cvss {
		sources = append(sources, name)
	}
	rank := func(name string) int {
		switch name {
		case "nvd":
			return 0
		case "redhat":
			return 1
		default:
			return 2
		}
	}
	slices.SortFunc(sources, func(a, b string) int {
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a, b))
	})

	var out []domain.CVSSRecord
	for _, name := range sources {
		c := cvss[name]
		source := strings.ToLower(strings.TrimSpace(name))
		for _, v := range []struct {
			vector string
			score  float64
		}{{c.V4Vector, c.V4Score}, {c.V3Vector, c.V3Score}, {c.V2Vector, c.V2Score}} {
			if rec, ok := parseutil.NewCVSSRecord(v.vector, v.score, source); ok {
				out = parseutil.AddCVSS(out, rec)
			}
		}
	}
	return out
}

func bestCVSSScore(c trivyCVSS) float64 {
	switch {
	case c.V4Score > 0:
		return c.V4Score
	case c.V3Score > 0:
		return c.V3Score
	case c.V2Score > 0:
		return c.V2Score
	default:
		return 0
	}
}

func addSecrets(budget *parseutil.Budget, nr *domain.NormalizedReport, result trivyResult) error {
	cleanTarget := parseutil.CleanFilePath(result.Target)
	if cleanTarget == "" {
		cleanTarget = "unknown"
	}
	for _, s := range result.Secrets {
		if err := budget.Add(1); err != nil {
			return err
		}
		start, end := lineRange(s.StartLine, s.EndLine)
		dims := []domain.Dimension{{Key: domain.DimRuleID, Value: s.RuleID}}
		if start > 0 {
			dims = append(dims, domain.Dimension{Key: domain.DimLine, Value: strconv.Itoa(start)})
		}
		anchor, basis := secretAnchor(s.Match, start)
		nr.Findings = append(nr.Findings, parseutil.HardenFinding(domain.NormalizedFinding{
			Fingerprint:  secretFingerprint(s.RuleID, cleanTarget, anchor),
			FindingKind:  kindSecret,
			Title:        s.Title,
			Severity:     normalizeSeverity(s.Severity),
			Location:     lineLocation(cleanTarget, start),
			CodeLocation: codeLocation(cleanTarget, start, end),
			Dimensions:   dims,
			Extensions: map[string]any{
				"category":       s.Category,
				"identity_basis": basis,
			},
		}))
	}
	return nil
}

func addMisconfigs(budget *parseutil.Budget, nr *domain.NormalizedReport, result trivyResult) error {
	cleanTarget := parseutil.CleanFilePath(result.Target)
	if cleanTarget == "" {
		cleanTarget = "unknown"
	}
	for _, m := range result.Misconfigs {
		if err := budget.Add(1); err != nil {
			return err
		}
		ruleID := m.RuleID
		if ruleID == "" {
			ruleID = m.ID
		}
		resource := m.CauseMetadata.Resource
		start, end := lineRange(m.CauseMetadata.StartLine, m.CauseMetadata.EndLine)
		dims := []domain.Dimension{{Key: domain.DimRuleID, Value: ruleID}}
		if resource != "" {
			dims = append(dims, domain.Dimension{Key: domain.DimResource, Value: resource})
		}
		nr.Findings = append(nr.Findings, parseutil.HardenFinding(domain.NormalizedFinding{
			Fingerprint:  misconfigFingerprint(ruleID, resource, cleanTarget, start),
			FindingKind:  kindIaC,
			Title:        m.Title,
			Severity:     normalizeSeverity(m.Severity),
			Location:     lineLocation(cleanTarget, start),
			Resource:     resource,
			CodeLocation: codeLocation(cleanTarget, start, end),
			Dimensions:   dims,
			Extensions: map[string]any{
				"message":      m.Message,
				"severity_raw": m.Severity,
			},
		}))
	}
	return nil
}

// fingerprintVersion is the version of this scanner's identity formula.
// Version 2 tells apart two secrets of one rule in one file and two resources
// that fail one check in one file, and keys both on the cleaned path. Version
// 1 merged each pair into one finding.
const fingerprintVersion = 2

// secretFingerprint is the rule, the file and an anchor that says which match
// in the file this is (see secretAnchor). The line is left out, so a secret
// keeps its identity, and its triage, when lines above it change.
func secretFingerprint(ruleID, file, anchor string) string {
	fp := "secret:" + ruleID + ":" + file
	if anchor != "" {
		fp += ":" + anchor
	}
	return fp
}

// secretAnchor is the first 16 hex digits of the SHA-256 of Trivy's Match, the
// matched line with the credential replaced by asterisks, whitespace runs
// collapsed. A Match with no asterisk is not masked (or not there), so it is
// never hashed: the line stands in, and basis says which was used.
func secretAnchor(match string, line int) (anchor, basis string) {
	if m := strings.Join(strings.Fields(match), " "); strings.Contains(m, "*") {
		sum := sha256.Sum256([]byte(m))
		return hex.EncodeToString(sum[:])[:16], "match"
	}
	if line > 0 {
		return "line" + strconv.Itoa(line), "line"
	}
	return "", "line"
}

// numberSecrets tells apart secrets that share a fingerprint, two tokens of one
// length in identical lines of one file, by appending "#1", "#2"... in line
// order. The first keeps the plain fingerprint.
func numberSecrets(findings []domain.NormalizedFinding) {
	var order []int
	for i, f := range findings {
		if f.FindingKind == kindSecret {
			order = append(order, i)
		}
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(secretLine(findings[a]), secretLine(findings[b]))
	})
	seen := make(map[string]int, len(order))
	for _, i := range order {
		fp := findings[i].Fingerprint
		n := seen[fp]
		seen[fp]++
		if n > 0 {
			findings[i].Fingerprint = parseutil.BoundFingerprint(fp + "#" + strconv.Itoa(n))
		}
	}
}

func secretLine(f domain.NormalizedFinding) int {
	if f.CodeLocation == nil {
		return 0
	}
	return f.CodeLocation.StartLine
}

// misconfigFingerprint is the rule, the resource and the file, the IaC
// identity Checkov findings use, so a finding stays put when its resource
// moves within the file. A check that names no resource (a Dockerfile
// instruction, say) falls back to the line it failed on.
func misconfigFingerprint(ruleID, resource, file string, line int) string {
	fp := "iac:" + ruleID + ":" + resource + ":" + file
	if resource == "" && line > 0 {
		fp += ":" + strconv.Itoa(line)
	}
	return fp
}

func lineRange(start, end int) (int, int) {
	start = parseutil.SafeLine(start)
	end = parseutil.SafeLine(end)
	if end < start {
		end = start
	}
	return start, end
}

func lineLocation(file string, line int) string {
	if line <= 0 {
		return file
	}
	return file + ":" + strconv.Itoa(line)
}

func codeLocation(file string, start, end int) *domain.CodeLocation {
	if start <= 0 || file == "unknown" {
		return nil
	}
	return &domain.CodeLocation{File: file, StartLine: start, EndLine: end}
}

// trivyCoveredKinds returns the covered kinds in a stable order.
func trivyCoveredKinds(covered map[string]bool) []string {
	out := make([]string, 0, len(covered))
	for _, kind := range []string{"sca", "sast", "iac", "secret", "dast"} {
		if covered[kind] {
			out = append(out, kind)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}
