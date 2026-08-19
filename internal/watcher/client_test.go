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
// advisory ID lists, mirroring the real OSV envelope. querybatch returns only
// id+modified per match — the full record comes from a separate GET.
func querybatchResponse(idLists ...[]map[string]any) []byte {
	var results []map[string]any
	for _, vulns := range idLists {
		results = append(results, map[string]any{"vulns": vulns})
	}
	b, _ := json.Marshal(map[string]any{"results": results})
	return b
}

func queryFor(name string) Query {
	return Query{Package: QueryPackage{Ecosystem: "npm", Name: name}}
}

// mockOSV builds a two-phase fake OSV server: POST <endpoint> answers the
// querybatch request (returning the matched ID per query via idFor, defaulting
// to "GHSA-"+name), and GET <endpoint>/v1/vulns/{id} returns the full advisory
// record from registry. It returns the server plus counters of POST (querybatch)
// and GET (full-record) requests so tests can assert caching and dedup.
func mockOSV(t *testing.T, registry map[string]map[string]any, idFor func(name string) string) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	if idFor == nil {
		idFor = func(name string) string { return "GHSA-" + name }
	}
	var posts, gets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			posts.Add(1)
			var body struct {
				Queries []Query `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode querybatch body: %v", err)
				return
			}
			var idLists [][]map[string]any
			for _, q := range body.Queries {
				idLists = append(idLists, []map[string]any{{
					"id": idFor(q.Package.Name), "modified": "2024-01-01T00:00:00Z",
				}})
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(querybatchResponse(idLists...))
		case r.Method == http.MethodGet:
			gets.Add(1)
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			adv, ok := registry[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			b, _ := json.Marshal(adv)
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		default:
			t.Errorf("unexpected method %s on %s", r.Method, r.URL.Path)
		}
	}))
	return srv, &posts, &gets
}

func TestQueryBatch_OKParsesAndCapturesRawBytes(t *testing.T) {
	databaseSpecific := map[string]any{"cwe_ids": []string{"CWE-79"}, "credits": map[string]any{"a": "b"}}
	advisory := cannedAdvisory("GHSA-test-1", "2024-01-01T00:00:00Z")
	advisory["database_specific"] = databaseSpecific
	advisory["credits"] = []map[string]string{{"name": "nobody"}}

	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("content-type = %q, want application/json", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Errorf("decode request body: %v", err)
			}
			// querybatch returns only the matched ID (id+modified), not the
			// full record — the full advisory is fetched via GET /v1/vulns/{id}.
			w.Header().Set("Content-Type", "application/json")
			w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-test-1", "modified": "2024-01-01T00:00:00Z"}}))
		case r.Method == http.MethodGet:
			b, _ := json.Marshal(advisory)
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		default:
			t.Errorf("method = %s, want POST or GET", r.Method)
		}
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}", BatchSize: 10})
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
	// The full record (from the GET) must populate the structured fields.
	if len(a.Affected) != 1 || a.Affected[0].Ecosystem != "npm" {
		t.Errorf("affected = %+v, want npm ecosystem populated from full record", a.Affected)
	}
	if len(a.Aliases) != 1 || a.Aliases[0] != "CVE-2024-0001" {
		t.Errorf("aliases = %+v, want populated from full record", a.Aliases)
	}
	if len(a.Severity) != 1 || a.Severity[0].Score == "" {
		t.Errorf("severity = %+v, want populated from full record", a.Severity)
	}
	if a.Raw == nil || len(a.Raw) == 0 {
		t.Fatal("Raw advisory bytes not captured")
	}
	// Raw must be byte-exact upstream JSON (from the full GET record),
	// including fields the decoded subset drops (database_specific, credits).
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
	registry := map[string]map[string]any{}
	for _, c := range []string{"a", "b", "c", "d", "e"} {
		registry["GHSA-"+c] = cannedAdvisory("GHSA-"+c, "2024-01-01T00:00:00Z")
	}
	srv, posts, gets := mockOSV(t, registry, nil)
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}", BatchSize: 2})
	queries := []Query{queryFor("a"), queryFor("b"), queryFor("c"), queryFor("d"), queryFor("e")}
	results, err := c.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	// 5 queries at BatchSize 2 => 3 querybatch POSTs (chunks of 2, 2, 1).
	if posts.Load() != 3 {
		t.Errorf("querybatch posts = %d, want 3 (chunks of 2)", posts.Load())
	}
	// 5 distinct matched IDs => 5 full-record GETs.
	if gets.Load() != 5 {
		t.Errorf("full-record gets = %d, want 5 (one per distinct id)", gets.Load())
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

func TestQueryBatch_CacheHitsSkipQuerybatchNetwork(t *testing.T) {
	// Both queries resolve to the SAME advisory id, exercising both the
	// querybatch cache (second identical call within TTL is a no-op) and
	// full-record dedup (a shared id is fetched exactly once per poll).
	registry := map[string]map[string]any{"GHSA-cached-1": cannedAdvisory("GHSA-cached-1", "2024-01-01T00:00:00Z")}
	srv, posts, gets := mockOSV(t, registry, func(name string) string { return "GHSA-cached-1" })
	defer srv.Close()

	clock := time.Unix(1_000_000, 0)
	now := func() time.Time { return clock }
	c := NewHTTPClient(HTTPClientConfig{
		Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}",
		BatchSize: 5, CacheTTL: time.Hour, Now: now,
	})

	queries := []Query{queryFor("b"), queryFor("a")} // order swapped second time
	if _, err := c.QueryBatch(context.Background(), queries); err != nil {
		t.Fatalf("first QueryBatch: %v", err)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("after first call: posts=%d gets=%d, want 1 and 1", posts.Load(), gets.Load())
	}
	// Same content, different order, within TTL: querybatch cache hit, so no
	// new POST. The full-record GET is NOT cached by querybatch and re-runs —
	// that is correct (each poll refetches full records for freshness).
	if _, err := c.QueryBatch(context.Background(), []Query{queryFor("a"), queryFor("b")}); err != nil {
		t.Fatalf("second QueryBatch: %v", err)
	}
	if posts.Load() != 1 {
		t.Errorf("querybatch posts = %d, want 1 (second call served from querybatch cache)", posts.Load())
	}
	if gets.Load() != 2 {
		t.Errorf("full-record gets = %d, want 2 (full records re-fetched each poll)", gets.Load())
	}
	// After TTL expiry the querybatch cache misses and refetches.
	clock = clock.Add(2 * time.Hour)
	if _, err := c.QueryBatch(context.Background(), []Query{queryFor("a")}); err != nil {
		t.Fatalf("third QueryBatch: %v", err)
	}
	if posts.Load() != 2 {
		t.Errorf("querybatch posts = %d, want 2 (TTL expired)", posts.Load())
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
		w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-short-1"}}))
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

// The querybatch phase succeeded (returning an id) but the full-record GET
// failed. The full-record GET must obey the same error taxonomy.
func TestQueryBatch_VulnGET429IsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-get-429"}}))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"code":1,"message":"rate limited"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}"})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for 429 on full-record GET")
	}
	if !IsRetryable(err) {
		t.Errorf("429 GET error %v should be retryable", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusTooManyRequests {
		t.Errorf("error = %#v, want *HTTPError with status 429", err)
	}
}

func TestQueryBatch_VulnGET500IsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-get-500"}}))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}"})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for 500 on full-record GET")
	}
	if !IsRetryable(err) {
		t.Errorf("500 GET error %v should be retryable", err)
	}
}

func TestQueryBatch_VulnGET400NotRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-get-400"}}))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":3,"message":"bad request"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}"})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for 400 on full-record GET")
	}
	if IsRetryable(err) {
		t.Errorf("400 GET error %v should NOT be retryable", err)
	}
}

func TestQueryBatch_VulnGETMalformedNotRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-get-malformed"}}))
			return
		}
		w.Write([]byte(`{"id": `)) // truncated full record
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}"})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	if err == nil {
		t.Fatal("expected error for malformed full-record GET")
	}
	if !errors.Is(err, ErrMalformedResponse) {
		t.Errorf("error %v does not wrap ErrMalformedResponse", err)
	}
	if IsRetryable(err) {
		t.Errorf("malformed GET error %v should NOT be retryable", err)
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
