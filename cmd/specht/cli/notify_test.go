package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runNotifyCmd executes the notify subtree on a test root that mirrors
// NewRootCmd's persistent --format wiring. (NewRootCmd does not register
// notify yet; root.go is out of scope for this change.)
func runNotifyCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newNotifyCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

const notifyPreviewBody = `{"supported":true,"plan":{"id":"n1","channel":"issue",` +
	`"target":"ORG/REPO","action":"open_issue","title":"Fix CVE-2024-1",` +
	`"body":"See finding f1","dedupe_key":"fp1:issue:ORG/REPO","reason":"policy"}}`

const notifyUnsupportedBody = `{"supported":false,"reason":"unsupported channel"}`

func TestNotifyPreviewHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/notify-preview", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("channel"); got != "issue" {
			t.Errorf("channel = %q, want issue", got)
		}
		if got := q.Get("target"); got != "ORG/REPO" {
			t.Errorf("target = %q, want ORG/REPO", got)
		}
		if _, err := w.Write([]byte(notifyPreviewBody)); err != nil {
			t.Errorf("write notify preview response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue", "--target", "ORG/REPO"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "notify n1 (issue -> ORG/REPO): Fix CVE-2024-1\nSee finding f1\n") {
		t.Fatalf("unexpected output: %q", got)
	}
	if !strings.Contains(got, "dedupe: fp1:issue:ORG/REPO\n") {
		t.Fatalf("missing dedupe line: %q", got)
	}
}

func TestNotifyPreviewLinked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/notify-preview", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("linked"); got != "1" {
			t.Errorf("linked = %q, want 1", got)
		}
		if _, err := w.Write([]byte(notifyPreviewBody)); err != nil {
			t.Errorf("write notify preview response: %v", err)
		}
	})
	d, _, _ := testDeps(t, mux)
	if err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue", "--target", "ORG/REPO", "--linked"); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyPreviewUnsupported(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/notify-preview", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(notifyUnsupportedBody)); err != nil {
			t.Errorf("write unsupported notify response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue", "--target", "ORG/REPO"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "no notification: unsupported channel\n") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestNotifyPreviewJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/notify-preview", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(notifyPreviewBody)); err != nil {
			t.Errorf("write notify preview response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue", "--target", "ORG/REPO", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"dedupe_key": "fp1:issue:ORG/REPO"`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestNotifyPreviewMissingFinding(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runNotifyCmd(t, d, "notify", "preview", "--channel", "issue", "--target", "ORG/REPO")
	if err == nil || !strings.Contains(err.Error(), "--finding is required for notify preview") {
		t.Fatalf("expected missing finding error, got %v", err)
	}
}

func TestNotifyPreviewMissingChannel(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--target", "ORG/REPO")
	if err == nil || !strings.Contains(err.Error(), "--channel is required for notify preview") {
		t.Fatalf("expected missing channel error, got %v", err)
	}
}

func TestNotifyPreviewMissingTarget(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue")
	if err == nil || !strings.Contains(err.Error(), "--target is required for notify preview") {
		t.Fatalf("expected missing target error, got %v", err)
	}
}

func TestNotifyPreviewInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue", "--target", "ORG/REPO", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}

func TestNotifyPreviewClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/notify-preview", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runNotifyCmd(t, d, "notify", "preview", "--finding", "f1", "--channel", "issue", "--target", "ORG/REPO"); err == nil {
		t.Fatal("expected client error")
	}
}
