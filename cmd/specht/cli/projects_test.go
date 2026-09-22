package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
)

func testDeps(t *testing.T, mux *http.ServeMux) (Deps, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	var out, errW bytes.Buffer
	return Deps{
		NewClient: func() (*client.Client, error) {
			return client.New(srv.URL, client.WithToken("test")), nil
		},
		Out:  &out,
		ErrW: &errW,
	}, &out, &errW
}

func runCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	root := NewRootCmd(d)
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

func TestProjectsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"slug":"demo","name":"Demo","description":"d"}]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "list"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "demo\tDemo\td") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectsListEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "list"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "No projects found.") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectsGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"slug":"demo","name":"Demo","description":"d"}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "get", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "Slug:       demo") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestProjectsGetMissingArg(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "projects", "get"); err == nil {
		t.Fatal("expected arg error")
	}
}
