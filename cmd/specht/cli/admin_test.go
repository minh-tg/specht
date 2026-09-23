package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runAdminCmd executes the admin subtree on a test root that mirrors
// NewRootCmd's persistent --format wiring. (NewRootCmd does not register
// admin yet; root.go is out of scope for this change.)
func runAdminCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newAdminCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

const adminStatusBody = `{"projects":2,"users":3,"open_findings":5,"reports":7}`

func TestAdminStatusHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/status", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(adminStatusBody)); err != nil {
			t.Errorf("write admin status response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "status"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "projects=2 users=3 open_findings=5 reports=7\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestAdminStatusJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/status", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(adminStatusBody)); err != nil {
			t.Errorf("write admin status response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "status", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"projects": 2`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestAdminStatusInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runAdminCmd(t, d, "admin", "status", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}

func TestAdminStatusClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/status", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "status"); err == nil {
		t.Fatal("expected client error")
	}
}

func TestAdminRetentionPreviewHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("days"); got != "30" {
			t.Errorf("days = %q, want 30", got)
		}
		if _, err := w.Write([]byte(`{"older_than_days":30,"cutoff":"2026-01-01T00:00:00Z","stale_reports":4}`)); err != nil {
			t.Errorf("write retention preview response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "retention", "preview", "--days", "30"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "4 settled report(s) older than 30 day(s) would be deleted\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestAdminRetentionPreviewJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"older_than_days":30,"cutoff":"2026-01-01T00:00:00Z","stale_reports":4}`)); err != nil {
			t.Errorf("write retention preview response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "retention", "preview", "--days", "30", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"stale_reports": 4`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestAdminRetentionPurgeHuman(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/retention/purge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if _, err := w.Write([]byte(`{"older_than_days":30,"cutoff":"2026-01-01T00:00:00Z","deleted_reports":4}`)); err != nil {
			t.Errorf("write retention purge response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "retention", "purge", "--days", "30"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "deleted 4 settled report(s) older than 30 day(s)\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestAdminRetentionPurgeJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/retention/purge", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"older_than_days":30,"cutoff":"2026-01-01T00:00:00Z","deleted_reports":4}`)); err != nil {
			t.Errorf("write retention purge response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "retention", "purge", "--days", "30", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"deleted_reports": 4`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestAdminRetentionMissingDays(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	for _, sub := range []string{"preview", "purge"} {
		err := runAdminCmd(t, d, "admin", "retention", sub)
		if err == nil || !strings.Contains(err.Error(), "--days is required for admin retention (positive integer)") {
			t.Fatalf("%s: expected missing days error, got %v", sub, err)
		}
	}
}

func TestAdminRetentionInvalidDays(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runAdminCmd(t, d, "admin", "retention", "preview", "--days", "abc")
	if err == nil || !strings.Contains(err.Error(), `invalid --days "abc": want a positive integer`) {
		t.Fatalf("expected invalid days error, got %v", err)
	}
}

func TestAdminRetentionNonPositiveDays(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	for _, days := range []string{"0", "-5"} {
		err := runAdminCmd(t, d, "admin", "retention", "purge", "--days", days)
		if err == nil || !strings.Contains(err.Error(), "--days is required for admin retention (positive integer)") {
			t.Fatalf("days=%s: expected required days error, got %v", days, err)
		}
	}
}

func TestAdminRetentionInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runAdminCmd(t, d, "admin", "retention", "preview", "--days", "30", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}

func TestAdminRetentionPreviewClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "retention", "preview", "--days", "30"); err == nil {
		t.Fatal("expected client error")
	}
}

func TestAdminRetentionPurgeClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/retention/purge", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runAdminCmd(t, d, "admin", "retention", "purge", "--days", "30"); err == nil {
		t.Fatal("expected client error")
	}
}
