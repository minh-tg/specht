package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runPatchCmd executes the patch subtree on a test root that mirrors
// NewRootCmd's persistent --format wiring. (Root registration happens
// centrally in root.go, which is out of scope for this change.)
func runPatchCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newPatchCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

const patchPreviewBody = `{"supported":true,"proposal":{"id":"p1","finding_id":"f1",` +
	`"class":"dependency-bump","confidence":"high","rationale":"bump x",` +
	`"evidence":{},"edits":[{"operation":"set-dependency-version","file":"go.mod",` +
	`"package":"example.com/x","from_version":"1.0.0","to_version":"1.0.1"}],` +
	`"apply_mode":"manual","verify_by":"rescan"}}`

func TestPatchPreviewHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/patch-preview", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(patchPreviewBody)); err != nil {
			t.Errorf("write patch preview response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPatchCmd(t, d, "patch", "preview", "--finding", "f1"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "patch p1 (dependency-bump, confidence high)\nbump x\n") {
		t.Fatalf("unexpected output: %q", got)
	}
	if !strings.Contains(got, "  set-dependency-version go.mod example.com/x 1.0.0 -> 1.0.1\n") {
		t.Fatalf("missing edit line: %q", got)
	}
	if !strings.Contains(got, "verify: rescan\n") {
		t.Fatalf("missing verify line: %q", got)
	}
}

func TestPatchPreviewUnsupported(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/patch-preview", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"supported":false,"reason":"no deterministic transformation"}`)); err != nil {
			t.Errorf("write unsupported patch response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPatchCmd(t, d, "patch", "preview", "--finding", "f1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "no patch: no deterministic transformation\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPatchPreviewJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/patch-preview", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(patchPreviewBody)); err != nil {
			t.Errorf("write patch preview response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runPatchCmd(t, d, "patch", "preview", "--finding", "f1", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"supported": true`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestPatchPreviewMissingFinding(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPatchCmd(t, d, "patch", "preview")
	if err == nil || !strings.Contains(err.Error(), "--finding is required for patch preview") {
		t.Fatalf("expected missing finding error, got %v", err)
	}
}

func TestPatchPreviewInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runPatchCmd(t, d, "patch", "preview", "--finding", "f1", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}

func TestPatchPreviewClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/patch-preview", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runPatchCmd(t, d, "patch", "preview", "--finding", "f1"); err == nil {
		t.Fatal("expected client error")
	}
}
