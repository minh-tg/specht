// Package scanner defines the plugin seam between Specht's core and vendor
// scanner output: the Scanner interface a parser adapter implements, the
// deterministic registry that maps scanner names to implementations, and the
// descriptor a scanner publishes about itself.
//
// The normalized report/finding model itself lives in internal/domain (it
// moved here from this package so the core model carries no plugin
// vocabulary). This package re-exports the domain identifiers below so the
// existing parser adapters and tests keep compiling while the boundary move
// lands; new code should import internal/domain directly.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/xMinhx/specht/internal/domain"
)

// Re-exported domain identifiers (boundary move compatibility layer; removed
// once every in-repository caller imports internal/domain).
type (
	ScanType           = domain.ScanType
	Severity           = domain.Severity
	NormalizedReport   = domain.NormalizedReport
	NormalizedFinding  = domain.NormalizedFinding
	PackageRef         = domain.PackageRef
	TargetInfo         = domain.TargetInfo
	ArtifactInfo       = domain.ArtifactInfo
	CVSSInfo           = domain.CVSSInfo
	FixInfo            = domain.FixInfo
	CodeLocation       = domain.CodeLocation
	Dimension          = domain.Dimension
	Fingerprint        = domain.Fingerprint
	ContractVersion    = domain.ContractVersion
	FingerprintVersion = domain.FingerprintVersion
	ScanCompleteness   = domain.ScanCompleteness
	ReachabilityState  = domain.ReachabilityState
	ReachabilityHint   = domain.ReachabilityHint
)

const (
	ScanTypeImage      = domain.ScanTypeImage
	ScanTypeFilesystem = domain.ScanTypeFilesystem
	ScanTypeRepository = domain.ScanTypeRepository
	ScanTypeIaC        = domain.ScanTypeIaC
	ScanTypeSBOM       = domain.ScanTypeSBOM
	ScanTypeLockfile   = domain.ScanTypeLockfile

	SeverityUnknown  = domain.SeverityUnknown
	SeverityLow      = domain.SeverityLow
	SeverityMedium   = domain.SeverityMedium
	SeverityHigh     = domain.SeverityHigh
	SeverityCritical = domain.SeverityCritical

	CompletenessUnknown  = domain.CompletenessUnknown
	CompletenessPartial  = domain.CompletenessPartial
	CompletenessComplete = domain.CompletenessComplete

	ReachabilityReachable     = domain.ReachabilityReachable
	ReachabilityNotReachable  = domain.ReachabilityNotReachable
	ReachabilityUnknown       = domain.ReachabilityUnknown
	ReachabilityNotApplicable = domain.ReachabilityNotApplicable
)

// SCAFingerprint computes the SCA fingerprint from a vulnerability id and
// normalized purl. It is the version-1 fingerprint formula.
func SCAFingerprint(vulnID, purl string) Fingerprint {
	return domain.SCAFingerprint(vulnID, purl)
}

// ScanTypeSARIF classifies a SARIF-format scan (semgrep). It is the scanner
// plugin's declaration of a scan type; the domain ScanType vocabulary covers
// the persisted scan_type column, while SARIF is the report envelope a
// parser consumes.
type ScanTypeSARIF string

const ScanTypeSARIFValue ScanTypeSARIF = "sarif"

// FindingKind is the persisted finding-kind vocabulary a finding carries
// (sca, sast, iac, secret, image_config, license, cve_watcher). The type is
// declared here for plugin descriptors; the finding row references
// finding_kinds(code) in PostgreSQL.
type FindingKind string

// Descriptor describes a scanner plugin: its stable name, version, the
// contract/fingerprint versions it produces, the finding kinds and scan
// types it can emit, and its capabilities. One scanner can emit multiple
// finding kinds (e.g. Trivy emits sca, secret, and iac findings from one
// report), which is why capability discovery is per-descriptor rather than
// a single FindingKind() method.
type Descriptor struct {
	// Name is the canonical registered scanner name (e.g. "trivy"). It is
	// the authoritative tool identity; ingest selects by it.
	Name string
	// Version is the scanner binary/report-format version the descriptor
	// targets (e.g. "2.0" for the parsed output format).
	Version string
	// ContractVersion is the version of the normalized report contract the
	// parser produces.
	ContractVersion ContractVersion
	// FingerprintVersion is the fingerprint-algorithm version the parser's
	// fingerprints use. Version 1 preserves existing finding identities.
	FingerprintVersion FingerprintVersion
	// FindingKinds lists the finding kinds this scanner can emit.
	FindingKinds []FindingKind
	// ScanTypes lists the scan types this scanner can cover.
	ScanTypes []ScanType
	// ProvidesPackages reports whether the scanner emits package inventory.
	ProvidesPackages bool
	// SupportsAutoDetection reports whether DetectFormat can identify this
	// scanner's output format.
	SupportsAutoDetection bool
}

// Scanner adapts a vendor scanner output format to the normalized domain
// model. A scanner is a compile-time plugin: the composition root registers
// concrete implementations; core consumers depend on this interface.
type Scanner interface {
	// Descriptor returns the scanner's static capability description.
	Descriptor() Descriptor
	// DetectFormat reports whether data looks like this scanner's output
	// format. Used only for optional format detection; ingest selects by
	// explicit name.
	DetectFormat(data []byte) bool
	// Parse converts raw vendor output into a normalized report.
	Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error)
}

var (
	// ErrNoMatch is returned by Registry.Detect when no registered scanner
	// recognizes the data.
	ErrNoMatch = errors.New("no scanner matched the data")
	// ErrAmbiguousMatch is returned by Registry.Detect when more than one
	// registered scanner recognizes the data and no deterministic priority
	// resolves it.
	ErrAmbiguousMatch = errors.New("multiple scanners matched the data")
	// ErrDuplicateName is returned by Registry.Register when a scanner with
	// the same name is already registered.
	ErrDuplicateName = errors.New("scanner name already registered")
	// ErrInvalidDescriptor is returned by Registry.Register for nil scanners
	// or descriptors with an empty name.
	ErrInvalidDescriptor = errors.New("invalid scanner descriptor")
)

// Registry maps scanner names to their Scanner implementations. Registration
// order is retained so listing is deterministic and detection can resolve
// ties by registration priority.
type Registry struct {
	mu       sync.RWMutex
	scanners []registered
	byName   map[string]Scanner
}

type registered struct {
	name string
	sc   Scanner
}

// NewRegistry builds an empty scanner registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Scanner)}
}

// Register adds a scanner under its descriptor name. It returns
// ErrDuplicateName when the name is already registered and
// ErrInvalidDescriptor when s is nil or its descriptor has an empty name.
func (r *Registry) Register(s Scanner) error {
	if s == nil {
		return ErrInvalidDescriptor
	}
	d := s.Descriptor()
	if d.Name == "" {
		return ErrInvalidDescriptor
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[d.Name]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateName, d.Name)
	}
	r.byName[d.Name] = s
	r.scanners = append(r.scanners, registered{name: d.Name, sc: s})
	return nil
}

// Get returns the scanner registered under name, or ErrNoMatch when no
// scanner is registered under it.
func (r *Registry) Get(name string) (Scanner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoMatch, name)
	}
	return s, nil
}

// List returns every registered scanner's descriptor in registration order.
func (r *Registry) List() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.scanners))
	for _, reg := range r.scanners {
		out = append(out, reg.sc.Descriptor())
	}
	return out
}

// DescriptorForKind returns the descriptors of every registered scanner that
// declares the given finding kind, in registration order.
func (r *Registry) DescriptorForKind(kind FindingKind) []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Descriptor
	for _, reg := range r.scanners {
		for _, k := range reg.sc.Descriptor().FindingKinds {
			if k == kind {
				out = append(out, reg.sc.Descriptor())
				break
			}
		}
	}
	return out
}

// Detect finds the single scanner that recognizes data. When no scanner
// matches it returns ErrNoMatch; when several do it returns ErrAmbiguousMatch
// unless exactly one matches. Matching is evaluated in registration order so
// the outcome is deterministic; the first matching scanner wins only when
// later scanners' formats are strict supersets handled by earlier, more
// specific ones — prefer explicit-name ingest.
func (r *Registry) Detect(data []byte) (Scanner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matches []Scanner
	for _, reg := range r.scanners {
		if reg.sc.DetectFormat(data) {
			matches = append(matches, reg.sc)
		}
	}
	switch len(matches) {
	case 0:
		return nil, ErrNoMatch
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrAmbiguousMatch, namesOf(matches))
	}
}

func namesOf(scanners []Scanner) string {
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Descriptor().Name
	}
	sort.Strings(names)
	return stringsJoin(names, ", ")
}

func stringsJoin(items []string, sep string) string {
	out := ""
	for i, it := range items {
		if i > 0 {
			out += sep
		}
		out += it
	}
	return out
}
