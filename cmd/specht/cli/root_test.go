package cli

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/xMinhx/specht/internal/client"
)

func TestRootRegistersProjectTeams(t *testing.T) {
	var gotPath string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`[{"project_id":"p1","team_id":"t1","team_name":"Backend","role":"viewer"}]`)),
			Header:     make(http.Header),
		}, nil
	})
	var out bytes.Buffer
	d := Deps{
		NewClient: func() (*client.Client, error) {
			return client.New("http://test", client.WithHTTPClient(&http.Client{Transport: transport})), nil
		},
		Out:  &out,
		ErrW: io.Discard,
	}

	if err := runCmd(t, d, "project-teams", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/projects/demo/teams" {
		t.Fatalf("request path = %q", gotPath)
	}
	if got := out.String(); got != "Backend\tt1\tviewer\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
