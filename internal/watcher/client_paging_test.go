package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestQueryBatch_FollowsNextPageToken(t *testing.T) {
	var posts atomic.Int32
	var secondBody []Query
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
			return
		}
		var body struct {
			Queries []Query `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode querybatch body: %v", err)
			return
		}
		if posts.Add(1) == 2 {
			secondBody = body.Queries
		}
		results := make([]map[string]any, 0, len(body.Queries))
		for _, q := range body.Queries {
			switch {
			case q.Package.Name == "big" && q.PageToken == "":
				results = append(results, map[string]any{
					"vulns":           []map[string]string{{"id": "GHSA-big-1"}},
					"next_page_token": "page-2",
				})
			case q.Package.Name == "big" && q.PageToken == "page-2":
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-big-2"}}})
			default:
				results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-" + q.Package.Name}}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL, VulnEndpoint: srv.URL + "/v1/vulns/{id}"})
	got, err := c.QueryBatch(context.Background(), []Query{queryFor("small"), queryFor("big")})
	if err != nil {
		t.Fatalf("QueryBatch: %v", err)
	}
	if posts.Load() != 2 {
		t.Fatalf("querybatch posts = %d, want 2 (first page plus one follow-up)", posts.Load())
	}
	if len(secondBody) != 1 || secondBody[0].Package.Name != "big" || secondBody[0].PageToken != "page-2" {
		t.Errorf("follow-up queries = %+v, want only big with page_token page-2", secondBody)
	}
	var smallIDs, bigIDs []string
	for _, a := range got[0].Advisories {
		smallIDs = append(smallIDs, a.ID)
	}
	for _, a := range got[1].Advisories {
		bigIDs = append(bigIDs, a.ID)
	}
	if strings.Join(smallIDs, ",") != "GHSA-small" {
		t.Errorf("small advisories = %v, want [GHSA-small]", smallIDs)
	}
	if strings.Join(bigIDs, ",") != "GHSA-big-1,GHSA-big-2" {
		t.Errorf("big advisories = %v, want both pages", bigIDs)
	}
}

func TestQueryBatch_EndlessPagingIsMalformed(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := posts.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{
			"vulns":           []map[string]string{},
			"next_page_token": "page-" + strconv.Itoa(int(n)),
		}}})
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("loop")})
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("err = %v, want ErrMalformedResponse", err)
	}
	if posts.Load() != maxQueryBatchPages {
		t.Errorf("querybatch posts = %d, want %d", posts.Load(), maxQueryBatchPages)
	}
}
