package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cannedAdvisory is a minimal OSV advisory exercising the fields the watcher
// consumes (id, aliases, published, severity, affected).
func cannedAdvisory(id, published string) map[string]any {
	return map[string]any{
		"id":        id,
		"aliases":   []string{"CVE-2024-0001"},
		"summary":   "test advisory " + id,
		"published": published,
		"severity": []map[string]any{
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		"affected": []map[string]any{
			{
				"ecosystem": "npm", "package": map[string]string{"name": "lodash"},
				"ranges": []map[string]any{
					{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.20"}}},
				},
			},
		},
		"details":           "details",
		"references":        []map[string]string{{"url": "https://example.test/advisory"}},
		"database_specific": map[string]any{"cwe_ids": []string{"CWE-79"}, "source": "nvd"},
	}
}

// querybatchResponse renders {"results":[{vulns...}...]} from the given
// advisory lists, mirroring the real OSV envelope.
func querybatchResponse(vulnsLists ...[]map[string]any) []byte {
	var results []map[string]any
	for _, vulns := range vulnsLists {
		results = append(results, map[string]any{"vulns": vulns})
	}
	b, _ := json.Marshal(map[string]any{"results": results})
	return b
}

func queryFor(name string) Query {
	return Query{Package: QueryPackage{Ecosystem: "npm", Name: name}}
}

func TestQueryBatch_OKParsesAndCapturesRawBytes(t *testing.T) {
	databaseSpecific := map[string]any{"cwe_ids": []string{"CWE-79"}, "credits": map[string]any{"a": "b"}}
	advisory := cannedAdvisory("GHSA-test-1", "2024-01-01T00:00:00Z")
	advisory["database_specific"] = databaseSpecific
	advisory["credits"] = []map[string]string{{"name": "nobody"}}

	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type = %q, want application/json", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(querybatchResponse([]map[string]any{advisory}))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, BatchSize: 10})
	results, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if len(results) != 1 || len(results[0].Advisories) != 1 {
		t.Fatalf("results = %+v, want 1 result with 1 advisory", results)
	}
	a := results[0].Advisories[0]
	if a.ID != "GHSA-test-1" {
		t.Errorf("id = %q, want GHSA-test-1", a.ID)
	}
	if a.Raw == nil || len(a.Raw) == 0 {
		t.Fatal("Raw advisory bytes not captured")
	}
	// Raw must be byte-exact upstream JSON, including fields the decoded
	// subset drops (database_specific, credits).
	rawStr := string(a.Raw)
	if !strings.Contains(rawStr, `"database_specific"`) || !strings.Contains(rawStr, `"CWE-79"`) {
		t.Errorf("Raw missing database_specific: %s", rawStr)
	}
	if !strings.Contains(rawStr, `"credits"`) {
		t.Errorf("Raw missing credits: %s", rawStr)
	}
	// The request body must use the querybatch envelope.
	qs, ok := gotBody["queries"].([]any)
	if !ok || len(qs) != 1 {
		t.Fatalf("request body = %v, want queries: [package query]", gotBody)
	}
}

func TestQueryBatch_BatchesAndPreservesOrder(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct {
			Queries []Query `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode: %v", err)
		}
		var resultLists [][]map[string]any
		for _, q := range body.Queries {
			resultLists = append(resultLists, []map[string]any{{
				"id": "GHSA-" + q.Package.Name, "summary": "advisory for " + q.Package.Name,
			}})
		}
		w.Write(querybatchResponse(resultLists...))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, BatchSize: 2})
	queries := []Query{queryFor("a"), queryFor("b"), queryFor("c"), queryFor("d"), queryFor("e")}
	results, err := c.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if requests != 3 {
		t.Errorf("http requests = %d, want 3 (chunks of 2)", requests)
	}
	if len(results) != 5 {
		t.Fatalf("results = %d, want 5", len(results))
	}
	for i, r := range results {
		if len(r.Advisories) != 1 || r.Advisories[0].ID != "GHSA-"+string(rune('a'+i)) {
			t.Errorf("result %d = %+v, want advisory GHSA-%c", i, r.Advisories, 'a'+i)
		}
	}
}

func TestQueryBatch_CacheHitsSkipNetwork(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Echo one result per query so the result count matches the query
		// count (the client validates the 1:1 correspondence).
		var req struct {
			Queries []json.RawMessage `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		lists := make([][]map[string]any, len(req.Queries))
		for i := range lists {
			lists[i] = []map[string]any{cannedAdvisory("GHSA-cached-1", "2024-01-01T00:00:00Z")}
		}
		w.Write(querybatchResponse(lists...))
	}))
	defer srv.Close()

	clock := time.Unix(1_000_000, 0)
	now := func() time.Time { return clock }
	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, BatchSize: 5, CacheTTL: time.Hour, Now: now})

	queries := []Query{queryFor("b"), queryFor("a")} // order swapped second time
	if _, err := c.QueryBatch(context.Background(), queries); err != nil {
		t.Fatalf("first QueryBatch: %v", err)
	}
	// Same content, different order, within TTL: cache hit for both chunks.
	if _, err := c.QueryBatch(context.Background(), []Query{queryFor("a"), queryFor("b")}); err != nil {
		t.Fatalf("second QueryBatch: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("http requests = %d, want 1 (second call served from cache)", hits.Load())
	}
	// After TTL expiry the cache misses and refetches.
	clock = clock.Add(2 * time.Hour)
	if _, err := c.QueryBatch(context.Background(), []Query{queryFor("a")}); err != nil {
		t.Fatalf("third QueryBatch: %v", err)
	}
	if hits.Load() != 2 {
		t.Errorf("http requests = %d, want 2 (TTL expired)", hits.Load())
	}
}

func TestQueryBatch_429IsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"code":1,"message":"rate limited"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if !IsRetryable(err) {
		t.Errorf("429 error %v should be retryable", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusTooManyRequests {
		t.Errorf("error = %#v, want *HTTPError with status 429", err)
	}
}

func TestQueryBatch_500IsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !IsRetryable(err) {
		t.Errorf("500 error %v should be retryable", err)
	}
}

func TestQueryBatch_400NotRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":3,"message":"bad request"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if IsRetryable(err) {
		t.Errorf("400 error %v should NOT be retryable", err)
	}
}

func TestQueryBatch_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results": [{"vulns": [{"id": `)) // truncated JSON
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for malformed body")
	}
	if IsRetryable(err) {
		t.Errorf("malformed-body error %v should NOT be retryable (not an HTTP status failure)", err)
	}
}

func TestQueryBatch_ShortResultsMalformedNotRetryable(t *testing.T) {
	// OSV returns fewer results than the queries sent — a silently truncated
	// response that must be surfaced as a non-retryable malformed-response
	// error so the poll aborts instead of advancing its watermark while
	// dropping advisories (malformed-response guard).
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// 2 queries in, but only 1 result out.
		w.Write(querybatchResponse([]map[string]any{cannedAdvisory("GHSA-short-1", "2024-01-01T00:00:00Z")}))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, BatchSize: 10, CacheTTL: time.Hour})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("a"), queryFor("b")})
	if err == nil {
		t.Fatal("expected error for short results array")
	}
	if !errors.Is(err, ErrMalformedResponse) {
		t.Errorf("error %v does not wrap ErrMalformedResponse", err)
	}
	if IsRetryable(err) {
		t.Errorf("short-results error %v should NOT be retryable", err)
	}
}

func TestQueryBatch_TransportFailureIsRetryable(t *testing.T) {
	// A server that accepts the connection and slams it shut yields a
	// transport-level error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !IsRetryable(err) {
		t.Errorf("transport error %v should be retryable", err)
	}
}

func TestOSVEcosystemMapping(t *testing.T) {
	cases := map[string]string{
		"Go": "Go", "golang": "Go",
		"npm": "npm", "NPM": "npm", "node": "npm",
		"pypi": "PyPI", "PYPI": "PyPI", "python": "PyPI",
		"Maven": "Maven", "maven": "Maven", "java": "Maven",
		"Debian": "Debian", "debian": "Debian",
		"crates.io": "crates.io", "crates": "crates.io", "cargo": "crates.io",
		"RubyGems": "RubyGems", "rubygems": "RubyGems", "gem": "RubyGems",
		"alpine": "alpine", // unknown passes through
		"":       "",
	}
	for in, want := range cases {
		if got := OSVEcosystem(in); got != want {
			t.Errorf("OSVEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQueryBatch_CacheKeyIgnoresQueryOrder(t *testing.T) {
	a := cacheKey([]Query{queryFor("b"), queryFor("a")})
	b := cacheKey([]Query{queryFor("a"), queryFor("b")})
	if a != b {
		t.Errorf("cache keys differ for reordered same-content batches: %s vs %s", a, b)
	}
}

func TestResponseCache_BoundedOnPutEvictsOldest(t *testing.T) {
	// Whole-branch review Minor finding: the cache must be bounded so batch
	// keys that are never re-queried after expiry cannot grow without limit.
	// With maxEntries = 2, inserting a third entry evicts the oldest.
	clock := time.Unix(1_000_000, 0)
	c := &responseCache{
		ttl:        time.Hour,
		now:        func() time.Time { return clock },
		maxEntries: 2,
		entries:    map[string]cacheEntry{},
	}
	c.put("a", []byte("1"))
	c.put("b", []byte("2"))
	c.put("c", []byte("3")) // over budget: evicts oldest ("a")

	if len(c.entries) != 2 {
		t.Fatalf("entries after evict = %d, want 2", len(c.entries))
	}
	if _, ok := c.get("a"); ok {
		t.Errorf("oldest entry 'a' must be evicted once over the cap")
	}
	if _, ok := c.get("b"); !ok {
		t.Errorf("'b' must survive")
	}
	if _, ok := c.get("c"); !ok {
		t.Errorf("'c' must survive")
	}

	// Expired entries are swept first: pushing the clock past the TTL and
	// adding one more entry drops the expired remainder to stay bounded.
	clock = clock.Add(2 * time.Hour) // b and c now expired
	c.put("d", []byte("4"))
	if len(c.entries) > 2 {
		t.Errorf("entries after expiry sweep = %d, want <= 2", len(c.entries))
	}
	if _, ok := c.get("d"); !ok {
		t.Errorf("newest entry 'd' must survive the expiry sweep")
	}
}

func TestResponseCache_RePutExistingKeyDoesNotEvict(t *testing.T) {
	c := &responseCache{
		ttl:        time.Hour,
		now:        time.Now,
		maxEntries: 1,
		entries:    map[string]cacheEntry{},
	}
	c.put("a", []byte("1"))
	c.put("a", []byte("2")) // refresh existing key — no eviction needed
	if len(c.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(c.entries))
	}
	if got, _ := c.get("a"); string(got) != "2" {
		t.Errorf("refreshed value = %q, want \"2\"", got)
	}
}
