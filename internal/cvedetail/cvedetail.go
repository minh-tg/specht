// Package cvedetail looks up CVE details (CVSS vectors, CWEs, dates and
// references) from external providers when a scan report leaves them out.
//
// The scan report stays the primary source. A Provider answers for one CVE
// identifier and nothing else leaves the server: no package, project or
// finding data is sent. Providers are off unless configured, run through a
// Resolver that rate limits each one, caches answers in PostgreSQL with a
// positive and a negative TTL, and fetches in the background so a finding
// read never waits on the network.
package cvedetail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
)

// Provider names. They key the cache and the status table and appear in API
// responses as the provenance of a value.
const (
	ProviderNVD       = "nvd"
	ProviderVulnCheck = "vulncheck"
	ProviderOSV       = "osv"
)

// KnownProviders lists every provider the server can be configured with, in
// the order the documentation names them.
var KnownProviders = []string{ProviderNVD, ProviderVulnCheck, ProviderOSV}

// ErrNotFound reports that a provider has no record for the CVE. The resolver
// stores it in the negative cache.
var ErrNotFound = errors.New("cvedetail: cve not found")

// RateLimitedError reports a provider refusal for too many requests.
// RetryAfter is the wait the provider asked for, or a default when it gave
// none.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("cvedetail: rate limited, retry after %s", e.RetryAfter)
}

// HTTPStatusError reports an unexpected HTTP status. It carries the code only:
// response bodies may echo request headers and never reach an error string.
type HTTPStatusError struct {
	Code int
}

func (e *HTTPStatusError) Error() string {
	return "cvedetail: unexpected status " + strconv.Itoa(e.Code)
}

// errDecode wraps a body that is not the JSON the provider documents.
var errDecode = errors.New("cvedetail: malformed response")

// Error categories stored in cve_provider_status.last_error and shown to
// operators. They are fixed words so no provider text or key can reach the
// database or the admin page.
const (
	ErrKindTimeout     = "timeout"
	ErrKindRateLimited = "rate_limited"
	ErrKind4xx         = "http_4xx"
	ErrKind5xx         = "http_5xx"
	ErrKindDecode      = "decode"
	ErrKindTooLarge    = "too_large"
	ErrKindTLS         = "tls"
	ErrKindNetwork     = "network"
)

// ErrorKind maps a provider error to its category.
func ErrorKind(err error) string {
	var rl *RateLimitedError
	var status *HTTPStatusError
	var netErr net.Error
	var certErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	switch {
	case errors.As(err, &rl):
		return ErrKindRateLimited
	case errors.As(err, &status):
		if status.Code >= 500 {
			return ErrKind5xx
		}
		return ErrKind4xx
	case errors.Is(err, netutil.ErrBodyTooLarge), errors.Is(err, errRecordTooLarge):
		return ErrKindTooLarge
	case errors.Is(err, errDecode):
		return ErrKindDecode
	case errors.As(err, &certErr), errors.As(err, &recordErr):
		return ErrKindTLS
	case errors.Is(err, context.DeadlineExceeded):
		return ErrKindTimeout
	case errors.As(err, &netErr) && netErr.Timeout():
		return ErrKindTimeout
	default:
		return ErrKindNetwork
	}
}

// CVSSRecord is one CVSS vector a provider published, with who scored it.
type CVSSRecord struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	// Source names the scoring party, for example "nvd@nist.gov".
	Source string `json:"source,omitempty"`
	// Type is "Primary" or "Secondary" where the provider says so.
	Type string `json:"type,omitempty"`
}

// Record is the provider-neutral answer for one CVE.
type Record struct {
	CVEID      string       `json:"cve_id"`
	CVSS       []CVSSRecord `json:"cvss,omitempty"`
	CWEs       []string     `json:"cwes,omitempty"`
	Published  *time.Time   `json:"published,omitempty"`
	Modified   *time.Time   `json:"modified,omitempty"`
	References []string     `json:"references,omitempty"`
}

// Provider looks up one CVE. Lookup returns ErrNotFound when the provider has
// no record, *RateLimitedError when it refuses for load, and any other error
// for a failure worth retrying later.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, cveID string) (Record, error)
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)

// ValidCVEID reports whether id is a well-formed CVE identifier, the only
// value a provider request may carry.
func ValidCVEID(id string) bool {
	return cvePattern.MatchString(id)
}

// Bounds on a normalized record. A provider answer is trimmed to them before
// it is cached, so one oversized CVE cannot fill the cache table.
const (
	maxRecordCVSS       = 6
	maxRecordCWEs       = 20
	maxRecordReferences = 20
	maxVectorLen        = 256
	maxReferenceLen     = 2048
	maxSourceLen        = 128
	// MaxRecordBytes caps the cached JSON record (64 KiB).
	MaxRecordBytes = 64 << 10
)

var (
	cwePattern        = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	errRecordTooLarge = errors.New("cvedetail: record too large")
)

// normalize trims a record to the bounds above, keeps only CWE identifiers
// of the form CWE-<n>, and keeps only https references.
func normalize(rec Record) Record {
	out := Record{CVEID: rec.CVEID, Published: rec.Published, Modified: rec.Modified}
	for _, c := range rec.CVSS {
		if len(out.CVSS) == maxRecordCVSS {
			break
		}
		if c.Vector == "" || len(c.Vector) > maxVectorLen {
			continue
		}
		c.Source = truncate(c.Source, maxSourceLen)
		c.Type = truncate(c.Type, maxSourceLen)
		out.CVSS = append(out.CVSS, c)
	}
	seen := map[string]bool{}
	for _, cwe := range rec.CWEs {
		if len(out.CWEs) == maxRecordCWEs {
			break
		}
		if cwePattern.MatchString(cwe) && !seen[cwe] {
			seen[cwe] = true
			out.CWEs = append(out.CWEs, cwe)
		}
	}
	seen = map[string]bool{}
	for _, ref := range rec.References {
		if len(out.References) == maxRecordReferences {
			break
		}
		if len(ref) <= maxReferenceLen && IsHTTPSURL(ref) && !seen[ref] {
			seen[ref] = true
			out.References = append(out.References, ref)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Occurrence is the newest sighting of a finding by one tool, as the CVE
// detail read path needs it. ReportID is nil for CVE watcher occurrences.
type Occurrence struct {
	ToolName   string
	ReportID   *string
	ObservedAt time.Time
	Metadata   []byte
}
