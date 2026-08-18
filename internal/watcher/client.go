// The OSV querybatch client turns a batch of package queries
// into per-query advisory lists, capturing the RAW upstream JSON for every
// advisory so evidence persistence is byte-exact (raw-bytes provenance).
//
// Error taxonomy: transport failures and HTTP 429 / 5xx responses are
// retryable (IsRetryable true); other 4xx responses are not. The client is
// safe for concurrent use; QueryBatch may be called from the poll loop and
// the backfill path.
package watcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultOSVEndpoint is the OSV querybatch endpoint.
	DefaultOSVEndpoint = "https://api.osv.dev/v1/querybatch"
	// DefaultBatchSize is the default number of package queries packed into
	// one querybatch HTTP request (WATCHER_BATCH_SIZE).
	DefaultBatchSize = 1000
)

// Query is one entry of the querybatch "queries" array. Ecosystem carries
// the OSV canonical ecosystem name (Go, npm, PyPI, ...); the daemon derives
// it from stored casing via OSVEcosystem.
type Query struct {
	Package QueryPackage `json:"package"`
}

// QueryPackage identifies one package for the OSV querybatch API. This is a
// separate type from matcher.Package because the OSV request schema carries
// an ecosystem alongside the name.
type QueryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// QueryResult is the per-query outcome of a batch: the query as sent and the
// advisories OSV knows for it (empty when OSV knows none).
type QueryResult struct {
	Query      Query
	Advisories []Advisory
}

// Client is the OSV querybatch surface the poll loop depends on.
type Client interface {
	// QueryBatch asks OSV about every query and returns one QueryResult per
	// query in the input order. Failures that IsRetryable classifies as
	// transient abort the whole call; the caller backs off and retries.
	QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error)
}

// HTTPError is a non-200 OSV response. It carries the status and the
// response body (truncated) for diagnostics.
type HTTPError struct {
	Status     int
	StatusText string
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("osv querybatch: http %d %s: %s", e.Status, e.StatusText, e.Body)
}

// ErrMalformedResponse marks an OSV response that cannot be decoded. It is
// deterministic — retrying the same batch cannot fix a garbage body — so
// IsRetryable reports false for it.
var ErrMalformedResponse = errors.New("osv querybatch: malformed response")

// IsRetryable reports whether err is a transient OSV failure suitable for
// backoff-driven retry: transport-level failures (including timeouts) and
// HTTP 429 / 5xx responses. Genuine client errors (other 4xx) and malformed
// responses are not retryable — retrying them will not succeed. Nil and
// context cancellation are not retryable.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrMalformedResponse) {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status == http.StatusTooManyRequests || he.Status >= 500
	}
	return true
}

// HTTPClientConfig configures the HTTP client implementation.
type HTTPClientConfig struct {
	// Endpoint is the querybatch URL. Defaults to DefaultOSVEndpoint.
	Endpoint string
	// BatchSize is the number of queries per HTTP request. Defaults to
	// DefaultBatchSize.
	BatchSize int
	// CacheTTL is how long a raw batch response is cached before a re-poll
	// refetches it; typically the poll interval. Zero disables caching.
	CacheTTL time.Duration
	// HTTP is the underlying transport. Defaults to a 30s-timeout client.
	HTTP *http.Client
	// Now supplies the cache clock; nil means time.Now.
	Now func() time.Time
}

// HTTPClient is the production Client: POSTs querybatch requests, batches
// queries by BatchSize, and caches raw responses keyed by batch (TTL =
// CacheTTL) so repeated polls do not refetch unchanged history.
type HTTPClient struct {
	endpoint  string
	http      *http.Client
	batchSize int
	cache     *responseCache
}

// NewHTTPClient builds an HTTPClient from cfg, applying defaults.
func NewHTTPClient(cfg HTTPClientConfig) *HTTPClient {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultOSVEndpoint
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &HTTPClient{
		endpoint:  cfg.Endpoint,
		http:      cfg.HTTP,
		batchSize: cfg.BatchSize,
		cache:     newResponseCache(cfg.CacheTTL, cfg.Now),
	}
}

// QueryBatch implements Client. Queries are split into BatchSize chunks
// executed sequentially (upstream rate limits are not documented, so the
// client stays conservative), and results are merged back into the original
// query order.
func (c *HTTPClient) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	results := make([]QueryResult, len(queries))
	for start := 0; start < len(queries); start += c.batchSize {
		end := min(start+c.batchSize, len(queries))
		chunk := queries[start:end]
		chunkResults, err := c.queryBatchChunk(ctx, chunk)
		if err != nil {
			return nil, err
		}
		copy(results[start:end], chunkResults)
	}
	return results, nil
}

// queryBatchChunk performs one querybatch POST. The raw response body is
// cached under a stable key derived from the chunk; a cache hit short-circuits
// the network round trip entirely.
func (c *HTTPClient) queryBatchChunk(ctx context.Context, queries []Query) ([]QueryResult, error) {
	key := cacheKey(queries)
	if raw, ok := c.cache.get(key); ok {
		if results, err := decodeQueryBatch(raw); err == nil {
			return results, nil
		}
		// A corrupted cache entry falls through to a refetch.
	}

	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, fmt.Errorf("osv querybatch marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv querybatch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		// Transport failure (connection, DNS, timeout): retryable.
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("osv querybatch read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{Status: resp.StatusCode, StatusText: resp.Status, Body: truncate(raw, 512)}
	}

	c.cache.put(key, raw)
	return decodeQueryBatch(raw)
}

// decodeQueryBatch parses the querybatch response envelope and captures each
// advisory's raw bytes verbatim. The response shape is
//
//	{"results":[{"vulns":[{...advisory...}, ...]}, ...]}
//
// with one results entry per query, in query order.
func decodeQueryBatch(raw []byte) ([]QueryResult, error) {
	var envelope struct {
		Results []struct {
			Vulns []json.RawMessage `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	results := make([]QueryResult, 0, len(envelope.Results))
	for i, r := range envelope.Results {
		advisories := make([]Advisory, 0, len(r.Vulns))
		for _, vm := range r.Vulns {
			var a Advisory
			if err := json.Unmarshal(vm, &a); err != nil {
				return nil, fmt.Errorf("%w: advisory %d: %v", ErrMalformedResponse, i, err)
			}
			a.Raw = append([]byte(nil), vm...) // verbatim upstream bytes
			advisories = append(advisories, a)
		}
		results = append(results, QueryResult{Advisories: advisories})
	}
	return results, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// cacheKey derives a stable key for a query chunk from the sorted
// (ecosystem, name) pairs, so identical batches hit regardless of the order
// they were collected in.
func cacheKey(queries []Query) string {
	pairs := make([]string, len(queries))
	for i, q := range queries {
		pairs[i] = q.Package.Ecosystem + "\x00" + q.Package.Name
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, "\x01")))
	return hex.EncodeToString(sum[:])
}

// OSVEcosystem maps a stored ecosystem to the OSV canonical name used in
// querybatch queries (the OSV API is case-sensitive about these). The
// mapping covers the ecosystems Specht's SCA parsers emit; unknown
// ecosystems pass through trimmed but otherwise unchanged, since OSV defines
// many more ecosystems than any single parser emits.
func OSVEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "go", "golang":
		return "Go"
	case "npm", "node", "nodejs":
		return "npm"
	case "pypi", "python", "pip":
		return "PyPI"
	case "maven", "java":
		return "Maven"
	case "debian":
		return "Debian"
	case "crates", "crates.io", "cargo", "rust":
		return "crates.io"
	case "rubygems", "ruby", "gem":
		return "RubyGems"
	default:
		return strings.TrimSpace(ecosystem)
	}
}

// responseCache is a tiny TTL cache of raw querybatch bodies keyed by
// cacheKey. It is not a distributed cache — one daemon process, one mutex —
// which is exactly the lifetime the poll loop needs.
type responseCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	entries map[string]cacheEntry
}

type cacheEntry struct {
	raw       []byte
	expiresAt time.Time
}

func newResponseCache(ttl time.Duration, now func() time.Time) *responseCache {
	return &responseCache{ttl: ttl, now: now, entries: make(map[string]cacheEntry)}
}

func (c *responseCache) get(key string) ([]byte, bool) {
	if c.ttl <= 0 || c == nil {
		// nil caches never happen in practice (NewHTTPClient always
		// constructs one); the ttl gate is the disable switch.
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if c.now().After(e.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return e.raw, true
}

func (c *responseCache) put(key string, raw []byte) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{raw: raw, expiresAt: c.now().Add(c.ttl)}
}
