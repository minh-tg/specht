// This file implements the OSV querybatch client. It turns a batch of
// package queries into per-query advisory lists, capturing the RAW upstream
// JSON for every advisory so evidence persistence is byte-exact.
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
	// DefaultOSVVulnURL is the template for fetching a full advisory record by
	// ID; "{id}" is replaced with the advisory ID. OSV's querybatch endpoint
	// returns only ids, so full records are fetched per matched ID.
	DefaultOSVVulnURL = "https://api.osv.dev/v1/vulns/{id}"
	// DefaultBatchSize is the default number of package queries packed into
	// one querybatch HTTP request (WATCHER_BATCH_SIZE). Design spec default 100.
	DefaultBatchSize = 100
	// DefaultVulnFetchConcurrency bounds simultaneous full-advisory requests.
	DefaultVulnFetchConcurrency = 5
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

// QueryResult is the per-query outcome of a batch: the advisories OSV knows
// for it (empty when OSV knows none). Results are returned in the input
// order, and the caller (PollOnce) pairs each result with its query by
// position — the query itself is not carried on the result.
type QueryResult struct {
	Advisories []Advisory
}

// Client is the OSV surface the poll loop depends on.
type Client interface {
	// QueryBatch asks OSV about every query and returns one QueryResult per
	// query in the input order, each holding the FULL advisory records for
	// that package. Failures that IsRetryable classifies as transient abort
	// the whole call; the caller backs off and retries.
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
	// VulnEndpoint is the base URL template for fetching a full advisory
	// record by ID. Defaults to DefaultOSVVulnURL, which contains the
	// literal "{id}" placeholder that is substituted with the advisory ID.
	VulnEndpoint string
	// BatchSize is the number of queries per HTTP request. Defaults to
	// DefaultBatchSize.
	BatchSize int
	// CacheTTL is how long a raw batch response is cached before a re-poll
	// refetches it; typically the poll interval. Zero disables caching.
	CacheTTL time.Duration
	// MaxConcurrentVulnFetches bounds simultaneous full-advisory GETs. Values
	// less than one use DefaultVulnFetchConcurrency.
	MaxConcurrentVulnFetches int
	// HTTP is the underlying transport. Defaults to a 30s-timeout client.
	HTTP *http.Client
	// Now supplies the cache clock; nil means time.Now.
	Now func() time.Time
}

// HTTPClient is the production Client: POSTs querybatch requests to discover
// matched advisory IDs, GETs the full record for each ID with bounded
// concurrency, batches queries by BatchSize, and caches raw querybatch
// responses keyed by batch (TTL = CacheTTL) so repeated polls do not refetch
// unchanged history.
type HTTPClient struct {
	endpoint                 string
	vulnURL                  string
	http                     *http.Client
	batchSize                int
	maxConcurrentVulnFetches int
	cache                    *responseCache
}

// NewHTTPClient builds an HTTPClient from cfg, applying defaults.
func NewHTTPClient(cfg HTTPClientConfig) *HTTPClient {
	if cfg.Endpoint == "" {
		cfg.Endpoint = DefaultOSVEndpoint
	}
	if cfg.VulnEndpoint == "" {
		cfg.VulnEndpoint = DefaultOSVVulnURL
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.MaxConcurrentVulnFetches <= 0 {
		cfg.MaxConcurrentVulnFetches = DefaultVulnFetchConcurrency
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &HTTPClient{
		endpoint:                 cfg.Endpoint,
		vulnURL:                  cfg.VulnEndpoint,
		http:                     cfg.HTTP,
		batchSize:                cfg.BatchSize,
		maxConcurrentVulnFetches: cfg.MaxConcurrentVulnFetches,
		cache:                    newResponseCache(cfg.CacheTTL, cfg.Now),
	}
}

// endpointVuln returns the full-record URL for the given advisory ID by
// substituting the "{id}" placeholder in the configured template.
func (c *HTTPClient) endpointVuln(id string) string {
	return strings.ReplaceAll(c.vulnURL, "{id}", id)
}

// QueryBatch implements Client. Querybatch POSTs are split into BatchSize
// chunks executed sequentially; full advisory records are fetched with bounded
// concurrency. Results are merged back into the original query order.
func (c *HTTPClient) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	results := make([]QueryResult, len(queries))
	// Phase 1: querybatch — returns only the matching vulnerability IDs per
	// query (OSV's querybatch endpoint returns {id, modified} only, not full
	// records). Sliced into BatchSize chunks executed sequentially.
	idBatches := make([][]string, len(queries))
	for start := 0; start < len(queries); start += c.batchSize {
		end := min(start+c.batchSize, len(queries))
		chunk := queries[start:end]
		chunkIDs, err := c.queryBatchChunk(ctx, chunk)
		if err != nil {
			return nil, err
		}
		copy(idBatches[start:end], chunkIDs)
	}

	// Phase 2: fetch the full record for every distinct matched ID. OSV has no
	// batch full-record endpoint, so one GET /v1/vulns/{id} per unique ID.
	// Fetches are deduped so a package matched by many queries never refetches.
	full, err := c.fetchFullRecords(ctx, idBatches)
	if err != nil {
		return nil, err
	}
	for i, ids := range idBatches {
		for _, id := range ids {
			if a, ok := full[id]; ok {
				results[i].Advisories = append(results[i].Advisories, a)
			}
		}
	}
	return results, nil
}

// queryBatchChunk performs one querybatch POST and returns the matched
// vulnerability IDs per query (the only data querybatch returns). The raw
// response body is cached under a stable key derived from the chunk; a cache
// hit short-circuits the network round trip entirely.
func (c *HTTPClient) queryBatchChunk(ctx context.Context, queries []Query) ([][]string, error) {
	key := cacheKey(queries)
	if raw, ok := c.cache.get(key); ok {
		if ids, err := decodeQueryBatch(raw); err == nil {
			if err := validateIDLength(ids, len(queries)); err != nil {
				// A cached body whose result count no longer matches the
				// query count is treated as corrupted (drop the cache
				// entry) rather than trusted.
				c.cache.del(key)
				return nil, err
			}
			return ids, nil
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
	ids, err := decodeQueryBatch(raw)
	if err != nil {
		return nil, err
	}
	if err := validateIDLength(ids, len(queries)); err != nil {
		return nil, err
	}
	return ids, nil
}

// fetchFullRecords fetches the full advisory record for every distinct ID
// across all per-query ID slices, returning a map keyed by ID. IDs are
// deduped across queries so a package matched many times is fetched once.
// Concurrent GETs are bounded by maxConcurrentVulnFetches.
func (c *HTTPClient) fetchFullRecords(ctx context.Context, idBatches [][]string) (map[string]Advisory, error) {
	seen := make(map[string]bool)
	var ids []string
	for _, batch := range idBatches {
		for _, id := range batch {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}

	records := make(map[string]Advisory, len(ids))
	if len(ids) == 0 {
		return records, nil
	}

	workers := min(c.maxConcurrentVulnFetches, len(ids))
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	var workersWG sync.WaitGroup
	var recordsMu sync.Mutex
	var errorOnce sync.Once
	var firstErr error

	for range workers {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for {
				select {
				case <-fetchCtx.Done():
					return
				case index, ok := <-jobs:
					if !ok || fetchCtx.Err() != nil {
						return
					}
					id := ids[index]
					record, err := c.fetchVuln(fetchCtx, id)
					if err != nil {
						errorOnce.Do(func() {
							firstErr = err
							cancel()
						})
						return
					}
					recordsMu.Lock()
					records[id] = record
					recordsMu.Unlock()
				}
			}
		}()
	}

sendJobs:
	for index := range ids {
		select {
		case jobs <- index:
		case <-fetchCtx.Done():
			break sendJobs
		}
	}
	close(jobs)
	workersWG.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// fetchVuln fetches one full advisory record via GET /v1/vulns/{id}. OSV's
// querybatch endpoint returns only IDs; the full record (affected, aliases,
// severity, summary, ...) comes from this endpoint.
func (c *HTTPClient) fetchVuln(ctx context.Context, id string) (Advisory, error) {
	url := c.endpointVuln(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Advisory{}, fmt.Errorf("osv vuln request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Advisory{}, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return Advisory{}, fmt.Errorf("osv vuln read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Advisory{}, &HTTPError{Status: resp.StatusCode, StatusText: resp.Status, Body: truncate(raw, 512)}
	}

	var a Advisory
	if err := json.Unmarshal(raw, &a); err != nil {
		return Advisory{}, fmt.Errorf("%w: vuln %s: %v", ErrMalformedResponse, id, err)
	}
	// Persist the verbatim full-record bytes for byte-exact evidence.
	a.Raw = append([]byte(nil), raw...)
	return a, nil
}

// validateIDLength enforces a 1:1 correspondence between the queries sent
// and the results returned. A short results array means the upstream silently
// dropped responses, which must be surfaced as a malformed (non-retryable)
// response — otherwise advisories would be silently lost while the poll's
// watermark still advanced.
func validateIDLength(ids [][]string, queryCount int) error {
	if len(ids) != queryCount {
		return fmt.Errorf("%w: got %d results for %d queries", ErrMalformedResponse, len(ids), queryCount)
	}
	return nil
}

// decodeQueryBatch parses the querybatch response envelope and returns the
// matched vulnerability IDs per query. The response shape is
//
//	{"results":[{"vulns":[{"id":"GHSA-...","modified":"..."}, ...]}, ...]}
//
// with one results entry per query, in query order. OSV's querybatch endpoint
// returns only the id and modified fields per match — the full advisory
// records must be fetched separately (see fetchFullRecords).
func decodeQueryBatch(raw []byte) ([][]string, error) {
	var envelope struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	results := make([][]string, 0, len(envelope.Results))
	for i, r := range envelope.Results {
		ids := make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			if v.ID == "" {
				return nil, fmt.Errorf("%w: query %d has an advisory with an empty id", ErrMalformedResponse, i)
			}
			ids = append(ids, v.ID)
		}
		results = append(results, ids)
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
// which is exactly the lifetime the poll loop needs. Entry count is kept
// bounded (see responseCacheMaxEntries) so batch keys that are never
// re-queried after expiry cannot grow the map without limit over a long
// running daemon.
type responseCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	now        func() time.Time
	maxEntries int
	entries    map[string]cacheEntry
}

// responseCacheMaxEntries caps the number of cached batch bodies. Without a
// cap the cache would only ever evict on access-after-expiry, so batch keys a
// changing inventory stops re-querying would linger for the process lifetime
// (whole-branch review, Minor finding). 4096 raw batch bodies is generous for
// the largest plausible query space while firmly bounding memory.
const responseCacheMaxEntries = 4096

type cacheEntry struct {
	raw       []byte
	expiresAt time.Time
}

func newResponseCache(ttl time.Duration, now func() time.Time) *responseCache {
	if now == nil {
		now = time.Now
	}
	return &responseCache{
		ttl:        ttl,
		now:        now,
		maxEntries: responseCacheMaxEntries,
		entries:    make(map[string]cacheEntry),
	}
}

func (c *responseCache) get(key string) ([]byte, bool) {
	if c == nil || c.ttl <= 0 {
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
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		// Over budget for a brand-new key: expire-sweep first, then evict
		// the least-recently-set entry so the map stays bounded.
		c.evictLocked()
	}
	c.entries[key] = cacheEntry{raw: raw, expiresAt: c.now().Add(c.ttl)}
}

// evictLocked drops already-expired entries, then — if the map is still over
// the cap — evicts the entry with the oldest expiry until it is back within
// budget. Equal-expiry ties are broken by key (lexicographically smallest
// evicted first) so eviction is fully deterministic — Go map iteration order
// is randomized, and two entries written under the same clock/TTL share an
// expiresAt, so picking "the oldest" without a tie-break would be arbitrary.
// Callers hold c.mu.
func (c *responseCache) evictLocked() {
	now := c.now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= c.maxEntries {
		var (
			oldestKey string
			oldest    time.Time
			first     = true
		)
		for k, e := range c.entries {
			if first || e.expiresAt.Before(oldest) || (e.expiresAt.Equal(oldest) && k < oldestKey) {
				oldestKey, oldest = k, e.expiresAt
				first = false
			}
		}
		delete(c.entries, oldestKey)
	}
}

// del removes a cache entry. Used to drop a body that no longer decodes or
// no longer matches its query count.
func (c *responseCache) del(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
