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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
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
	// maxQueryBatchPages bounds how many querybatch round trips one chunk may
	// take while following next_page_token. OSV pages at 1,000 vulns per
	// query, so this allows far more history than any real package has; a
	// response that keeps paging past it is treated as malformed.
	maxQueryBatchPages = 64
	// maxResponseBytes caps one querybatch or full-record answer. A larger
	// body fails with netutil.ErrBodyTooLarge instead of being cut short.
	maxResponseBytes = 32 << 20
)

// Query is one entry of the querybatch "queries" array. Ecosystem carries
// the OSV canonical ecosystem name (Go, npm, PyPI, ...); the daemon derives
// it from stored casing via OSVEcosystem.
type Query struct {
	Package QueryPackage `json:"package"`
	// PageToken asks OSV for the next page of a query whose previous
	// response carried next_page_token. Callers leave it empty; the client
	// sets it while following pagination.
	PageToken string `json:"page_token,omitempty"`
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

// HTTPError is a non-200 OSV response. It carries only the status code: the
// response body and reason phrase come from a server the process does not
// control, and the message is stored as the watcher's last error, returned by
// the status endpoint and logged.
type HTTPError struct {
	Status int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("osv querybatch: http %d %s", e.Status, http.StatusText(e.Status))
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
	if errors.Is(err, ErrMalformedResponse) || errors.Is(err, netutil.ErrBodyTooLarge) {
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
	// HTTP is the underlying transport. Defaults to a 30s-timeout client that
	// refuses redirects and non-public addresses (loopback only when Endpoint
	// is itself a loopback host).
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
		cfg.HTTP = netutil.SafeHTTPClientForURL(cfg.Endpoint, 30*time.Second)
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

// queryBatchChunk returns the matched vulnerability IDs per query for one
// chunk. OSV paginates a querybatch result (above 1,000 vulns for one query
// or 3,000 for the batch) and marks the cut with next_page_token. Every query
// that carries a token is re-sent with page_token until none is left, and its
// IDs are appended to that query's list. Stopping at the first page would
// drop advisories while the poll still counted as a success.
func (c *HTTPClient) queryBatchChunk(ctx context.Context, queries []Query) ([][]string, error) {
	ids := make([][]string, len(queries))
	pending := queries
	// index maps a position in pending back to its position in queries.
	index := make([]int, len(queries))
	for i := range index {
		index[i] = i
	}
	for page := 0; len(pending) > 0; page++ {
		if page == maxQueryBatchPages {
			return nil, fmt.Errorf("%w: querybatch still paging after %d requests", ErrMalformedResponse, page)
		}
		results, err := c.queryBatchPage(ctx, pending)
		if err != nil {
			return nil, err
		}
		var next []Query
		var nextIndex []int
		for j, r := range results {
			ids[index[j]] = append(ids[index[j]], r.ids...)
			if r.nextPageToken != "" {
				q := pending[j]
				q.PageToken = r.nextPageToken
				next = append(next, q)
				nextIndex = append(nextIndex, index[j])
			}
		}
		pending, index = next, nextIndex
	}
	return ids, nil
}

// queryBatchPage performs one querybatch POST and returns one result per
// query. The raw response body is cached under a key derived from the
// queries, page tokens included; a cache hit skips the network round trip.
func (c *HTTPClient) queryBatchPage(ctx context.Context, queries []Query) ([]batchResult, error) {
	key := cacheKey(queries)
	if raw, ok := c.cache.get(key); ok {
		if results, err := decodeQueryBatch(raw); err == nil {
			if err := validateResultCount(results, len(queries)); err != nil {
				// A cached body whose result count no longer matches the
				// query count is treated as corrupted (drop the cache
				// entry) rather than trusted.
				c.cache.del(key)
				return nil, err
			}
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
	// Closing the upstream response is best-effort after reading its body.
	defer func() {
		_ = resp.Body.Close()
	}()

	raw, err := netutil.ReadAllLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("osv querybatch read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{Status: resp.StatusCode}
	}

	c.cache.put(key, raw)
	results, err := decodeQueryBatch(raw)
	if err != nil {
		return nil, err
	}
	if err := validateResultCount(results, len(queries)); err != nil {
		return nil, err
	}
	return results, nil
}

// fetchFullRecords fetches the full advisory record for every distinct ID
// across all per-query ID slices, returning a map keyed by ID. IDs are
// deduped across queries so a package matched many times is fetched once.
// Concurrent GETs are bounded by maxConcurrentVulnFetches.
func (c *HTTPClient) fetchFullRecords(ctx context.Context, idBatches [][]string) (map[string]Advisory, error) {
	ids := uniqueVulnIDs(idBatches)
	records := make(map[string]Advisory, len(ids))
	if len(ids) == 0 {
		return records, nil
	}

	fetcher := fullRecordFetcher{
		client:  c,
		ids:     ids,
		records: records,
	}
	return fetcher.run(ctx)
}

func uniqueVulnIDs(idBatches [][]string) []string {
	seen := make(map[string]struct{})
	var ids []string
	for _, batch := range idBatches {
		for _, id := range batch {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// fullRecordFetcher coordinates one bounded set of advisory fetch workers.
type fullRecordFetcher struct {
	client    *HTTPClient
	ids       []string
	records   map[string]Advisory
	recordsMu sync.Mutex
	errorOnce sync.Once
	firstErr  error
}

func (f *fullRecordFetcher) run(ctx context.Context) (map[string]Advisory, error) {
	workers := min(f.client.maxConcurrentVulnFetches, len(f.ids))
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int)
	var workersWG sync.WaitGroup
	for range workers {
		workersWG.Add(1)
		go f.fetchWorker(fetchCtx, cancel, jobs, &workersWG)
	}

	dispatchFullRecordJobs(fetchCtx, jobs, len(f.ids))
	close(jobs)
	workersWG.Wait()

	if f.firstErr != nil {
		return nil, f.firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.records, nil
}

func (f *fullRecordFetcher) fetchWorker(ctx context.Context, cancel context.CancelFunc, jobs <-chan int, workersWG *sync.WaitGroup) {
	defer workersWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case index, ok := <-jobs:
			if !ok || ctx.Err() != nil {
				return
			}
			id := f.ids[index]
			record, err := f.client.fetchVuln(ctx, id)
			if err != nil {
				if isAdvisoryGone(err) {
					// A withdrawn or removed advisory must not stop every
					// other advisory in the batch from being processed.
					continue
				}
				f.errorOnce.Do(func() {
					f.firstErr = err
					cancel()
				})
				return
			}
			f.recordsMu.Lock()
			f.records[id] = record
			f.recordsMu.Unlock()
		}
	}
}

func dispatchFullRecordJobs(ctx context.Context, jobs chan<- int, count int) {
	for index := range count {
		select {
		case jobs <- index:
		case <-ctx.Done():
			return
		}
	}
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
	// Closing the upstream response is best-effort after reading its body.
	defer func() {
		_ = resp.Body.Close()
	}()

	raw, err := netutil.ReadAllLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return Advisory{}, fmt.Errorf("osv vuln read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Advisory{}, &HTTPError{Status: resp.StatusCode}
	}

	var a Advisory
	if err := json.Unmarshal(raw, &a); err != nil {
		return Advisory{}, fmt.Errorf("%w: vuln %s: %v", ErrMalformedResponse, id, err)
	}
	// Persist the verbatim full-record bytes for byte-exact evidence.
	a.Raw = append([]byte(nil), raw...)
	return a, nil
}

// isAdvisoryGone reports a full-record fetch that OSV no longer knows.
func isAdvisoryGone(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound
}

// validateResultCount enforces a 1:1 correspondence between the queries sent
// and the results returned. A short results array means the upstream silently
// dropped responses, which must be surfaced as a malformed (non-retryable)
// response — otherwise advisories would be silently lost while the poll's
// watermark still advanced.
func validateResultCount(results []batchResult, queryCount int) error {
	if len(results) != queryCount {
		return fmt.Errorf("%w: got %d results for %d queries", ErrMalformedResponse, len(results), queryCount)
	}
	return nil
}

// batchResult is one querybatch results entry: the matched IDs on this page
// and the token for the next page, empty on the last page.
type batchResult struct {
	ids           []string
	nextPageToken string
}

// decodeQueryBatch parses the querybatch response envelope and returns the
// matched vulnerability IDs and next page token per query. The response
// shape is
//
//	{"results":[{"vulns":[{"id":"GHSA-...","modified":"..."}, ...],
//	             "next_page_token":"..."}, ...]}
//
// with one results entry per query, in query order. OSV's querybatch endpoint
// returns only the id and modified fields per match — the full advisory
// records must be fetched separately (see fetchFullRecords).
func decodeQueryBatch(raw []byte) ([]batchResult, error) {
	var envelope struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedResponse, err)
	}
	results := make([]batchResult, 0, len(envelope.Results))
	for i, r := range envelope.Results {
		ids := make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			if v.ID == "" {
				return nil, fmt.Errorf("%w: query %d has an advisory with an empty id", ErrMalformedResponse, i)
			}
			ids = append(ids, v.ID)
		}
		results = append(results, batchResult{ids: ids, nextPageToken: r.NextPageToken})
	}
	return results, nil
}

// cacheKey derives a key for a query chunk from the (ecosystem, name) pairs
// in query order. The cached body is positional (result i answers query i),
// so a reordered batch must miss: serving [b, a]'s body for [a, b] would pair
// each package with the other's advisories.
func cacheKey(queries []Query) string {
	pairs := make([]string, len(queries))
	for i, q := range queries {
		pairs[i] = q.Package.Ecosystem + "\x00" + q.Package.Name + "\x00" + q.PageToken
	}
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

// responseCacheMaxEntries caps retained query-batch responses. Keys that
// disappear from a changing inventory would otherwise linger until reused;
// 4096 entries bounds memory while accommodating the expected query set.
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
