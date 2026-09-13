package provider

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Conclusion is a pull-request check outcome.
type Conclusion string

const (
	// ConclusionSuccess means no blocking finding touches the change.
	ConclusionSuccess Conclusion = "success"
	// ConclusionFailure means at least one unwaived blocking finding does.
	ConclusionFailure Conclusion = "failure"
	// ConclusionNeutral means the plan carries information only (e.g. every
	// finding lacked a mappable location and degraded to a summary).
	ConclusionNeutral Conclusion = "neutral"
)

// AnnotationLevel is the provider-neutral severity of one inline annotation.
type AnnotationLevel string

const (
	AnnotationInfo    AnnotationLevel = "info"
	AnnotationWarning AnnotationLevel = "warning"
	AnnotationError   AnnotationLevel = "error"
)

// Finding is the subset of a finding a provider needs to plan a check:
// identity, severity, and an optional code location. A finding without a
// file degrades to summary counts — never dropped silently, never guessed.
type Finding struct {
	ID             string
	Title          string
	Severity       string
	SeverityRank   int16
	Fingerprint    string
	File           string
	StartLine      int
	EndLine        int
	Introduced     bool
	RemediationURL string
}

// Annotation is one inline pull-request annotation.
type Annotation struct {
	// ExternalID is stable across reruns (finding fingerprint scoped to
	// the check), so repeated scans update existing feedback instead of
	// creating noise.
	ExternalID string
	FindingID  string
	File       string
	StartLine  int
	EndLine    int
	Level      AnnotationLevel
	Title      string
	Message    string
}

// CheckPlan is the provider-neutral pull-request check: one conclusion
// tied to an exact scan and commit, plus bounded inline annotations.
// Unsupported or incomplete locations degrade to SummaryCounts.
type CheckPlan struct {
	Provider    string
	CommitSha   string
	ReportID    string
	Conclusion  Conclusion
	Title       string
	Summary     string
	Annotations []Annotation
	// SummaryCounts tallies every considered finding by severity,
	// including ones without a mappable location.
	SummaryCounts map[string]int
	// Truncated is true when annotations hit the provider cap; the
	// summary still covers everything.
	Truncated bool
	// Supersedes names the check run this plan updates on rerun, so
	// platforms replace stale feedback instead of duplicating it.
	Supersedes string
}

// CheckInput scopes one plan: the revision under review, the report that
// scanned it, and the gate decision it reflects.
type CheckInput struct {
	CommitSha  string
	ReportID   string
	Branch     string
	Repository string
	Breached   bool
	Findings   []Finding
}

// Descriptor describes a provider adapter.
type Descriptor struct {
	// Name is the canonical provider name (e.g. "github").
	Name string
	// MaxAnnotations bounds inline annotations per check run.
	MaxAnnotations int
}

// Provider plans pull-request checks for one code-hosting platform. It is
// a compile-time plugin: the composition root registers concrete
// implementations; core consumers depend on this interface.
type Provider interface {
	// Descriptor returns the provider's static description.
	Descriptor() Descriptor
	// PlanCheck maps findings to a check plan. It performs no I/O.
	PlanCheck(input CheckInput) (CheckPlan, error)
}

var (
	// ErrDuplicateName is returned by Registry.Register for a repeated name.
	ErrDuplicateName = errors.New("provider name already registered")
	// ErrInvalidDescriptor is returned for nil providers or empty names.
	ErrInvalidDescriptor = errors.New("invalid provider descriptor")
	// ErrNoMatch is returned by Registry.Get for unknown names.
	ErrNoMatch = errors.New("no provider matched the name")
)

// Registry maps provider names to implementations in registration order.
type Registry struct {
	mu        sync.RWMutex
	providers []registered
	byName    map[string]Provider
}

type registered struct {
	name string
	p    Provider
}

// NewRegistry builds an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Provider)}
}

// Register adds a provider under its descriptor name.
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return ErrInvalidDescriptor
	}
	d := p.Descriptor()
	if d.Name == "" {
		return ErrInvalidDescriptor
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[d.Name]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateName, d.Name)
	}
	r.byName[d.Name] = p
	r.providers = append(r.providers, registered{name: d.Name, p: p})
	return nil
}

// Get returns the provider registered under name.
func (r *Registry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoMatch, name)
	}
	return p, nil
}

// List returns every registered provider name in registration order.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.providers))
	for _, reg := range r.providers {
		out = append(out, reg.name)
	}
	return out
}

// SortFindings orders findings deterministically for stable plans:
// severity rank first, then fingerprint.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].SeverityRank != findings[j].SeverityRank {
			return findings[i].SeverityRank > findings[j].SeverityRank
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}
