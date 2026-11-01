package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// An identifier chosen by a model or typed on the command line can carry "/",
// "?" and "..". The client must keep it inside its own path segment so the
// request cannot be steered to another route or get an injected query string.
// This test turns red when url.PathEscape is removed from GetFinding,
// GetWaiver or ToggleWaiver.
func TestIdentifiersStayInTheirPathSegment(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, WithToken("k"))

	hostile := "../projects/other/members?x=1#f"
	if _, err := c.GetFinding(hostile); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetWaiver("p/../q", hostile); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ToggleWaiver("p", hostile); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /api/v1/findings/..%2Fprojects%2Fother%2Fmembers%3Fx=1%23f",
		"GET /api/v1/projects/p%2F..%2Fq/waivers/..%2Fprojects%2Fother%2Fmembers%3Fx=1%23f",
		"POST /api/v1/projects/p/waivers/..%2Fprojects%2Fother%2Fmembers%3Fx=1%23f/toggle",
	}
	if len(got) != len(want) {
		t.Fatalf("requests = %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d = %q, want %q", i, got[i], want[i])
		}
	}
}
