package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runPrCmd executes the pr subtree on a test root that mirrors NewRootCmd's
// persistent --format wiring. (NewRootCmd does not register pr yet; root.go
// is out of scope for this change.)
func runPrCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newPrCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

const prPreviewBody = `{"provider":"github","commit_sha":"abc123","conclusion":"success",` +
	`"title":"No blocking findings","summary":"All clear",` +
	`"annotations":[{"external_id":"e1","finding_id":"f1","file":"go.mod",` +
	`"start_line":3,"end_line":3,"level":"warning","title":"bump x","message":"m"}]}`

func TestPrPreviewHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/pr-check", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("commit"); got != "abc123" {
			t.Errorf("commit = %q, want abc123", got)
		}
		w.Write([]byte(prPreviewBody))
	})
	d, out, _ := testDeps(t, mux)
	if err := runPrCmd(t, d, "pr", "preview", "--project", "demo", "--commit", "abc123"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "check success: No blocking findings\nAll clear\n") {
		t.Fatalf("unexpected output: %q", got)
	}
	if !strings.Contains(got, "  go.mod:3 bump x\n") {
		t.Fatalf("missing annotation line: %q", got)
	}
}

func TestPrPreviewJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/pr-check", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(prPreviewBody))
	})
	d, out, _ := testDeps(t, mux)
	if err := runPrCmd(t, d, "pr", "preview", "--project", "demo", "--commit", "abc123", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `"conclusion": "success"`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPrPreviewMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPrCmd(t, d, "pr", "preview", "--commit", "abc123")
	if err == nil || !strings.Contains(err.Error(), "--project is required for pr preview") {
		t.Fatalf("expected missing project error, got %v", err)
	}
}

func TestPrPreviewMissingCommit(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPrCmd(t, d, "pr", "preview", "--project", "demo")
	if err == nil || !strings.Contains(err.Error(), "--commit is required for pr preview") {
		t.Fatalf("expected missing commit error, got %v", err)
	}
}

func TestPrPreviewInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPrCmd(t, d, "pr", "preview", "--project", "demo", "--commit", "abc123", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}

func TestPrPreviewClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/pr-check", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runPrCmd(t, d, "pr", "preview", "--project", "demo", "--commit", "abc123"); err == nil {
		t.Fatal("expected client error")
	}
}
