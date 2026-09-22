package cli

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runGateCmd executes the gate subtree on a test root that mirrors
// NewRootCmd's persistent --format wiring. (NewRootCmd does not register
// gate yet; root.go is out of scope for this change.)
func runGateCmd(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	root := &cobra.Command{Use: "specht"}
	root.PersistentFlags().StringVar(&s.format, "format", "", "output format: human or json")
	root.AddCommand(newGateCmd(d, s))
	root.SetArgs(args)
	root.SetOut(d.Out)
	root.SetErr(d.ErrW)
	return root.Execute()
}

func TestGateCheckPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/gate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"threshold_breached":false,"blocking_count":0}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runGateCmd(t, d, "gate", "check", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "gate PASSED: no blocking findings\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestGateCheckBreach(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/gate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"threshold_breached":true,"blocking_count":2,` +
			`"blocked_by":["id-1","id-2"],` +
			`"blocked_by_reachability":{"id-1":"reachable"},"waived_count":1}`))
	})
	d, out, errW := testDeps(t, mux)
	err := runGateCmd(t, d, "gate", "check", "--project", "demo")
	if !errors.Is(err, ErrThresholdBreached) {
		t.Fatalf("expected ErrThresholdBreached, got %v", err)
	}
	if errW.String() != "" {
		t.Fatalf("expected no stderr noise on breach, got %q", errW.String())
	}
	want := "gate FAILED: 2 blocking finding(s)\n" +
		"  blocked by: id-1 (reachability: reachable)\n" +
		"  blocked by: id-2 (reachability: unknown)\n" +
		"  waived: 1 finding(s) excluded by active waivers\n"
	if got := out.String(); got != want {
		t.Fatalf("unexpected output:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestGateCheckJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/gate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"threshold_breached":false,"blocking_count":0}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runGateCmd(t, d, "gate", "check", "--project", "demo", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"threshold_breached":false`) {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestGateCheckIntroducedOnly(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/gate", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("introduced_only") != "1" || q.Get("report_id") != "r1" {
			t.Errorf("query = %q, want introduced_only=1&report_id=r1", r.URL.RawQuery)
		}
		w.Write([]byte(`{"threshold_breached":false,"blocking_count":0}`))
	})
	d, out, _ := testDeps(t, mux)
	args := []string{"gate", "check", "--project", "demo", "--introduced-only", "--report-id", "r1"}
	if err := runGateCmd(t, d, args...); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "gate PASSED: no blocking findings\n" {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestGateCheckMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runGateCmd(t, d, "gate", "check")
	if err == nil || !strings.Contains(err.Error(), "--project is required for gate check") {
		t.Fatalf("expected missing project error, got %v", err)
	}
}

func TestGateCheckIntroducedOnlyMissingReport(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runGateCmd(t, d, "gate", "check", "--project", "demo", "--introduced-only")
	if err == nil || !strings.Contains(err.Error(), "--report-id is required with --introduced-only") {
		t.Fatalf("expected missing report-id error, got %v", err)
	}
}

func TestGateCheckInvalidFormat(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	err := runGateCmd(t, d, "gate", "check", "--project", "demo", "--format", "yaml")
	if err == nil || !strings.Contains(err.Error(), `invalid --format "yaml": want human or json`) {
		t.Fatalf("expected invalid format error, got %v", err)
	}
}
