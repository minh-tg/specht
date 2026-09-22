package cli

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
)

func runStats(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	s := &settings{}
	cmd := newStatsCmd(d, s)
	cmd.SetArgs(args)
	cmd.SetOut(d.Out)
	cmd.SetErr(d.ErrW)
	return cmd.Execute()
}

func TestStatsShow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total_findings":10,"blocking_count":3,"waiver_count":1,"report_count":2,` +
			`"by_severity":[{"severity":"critical","count":2,"blocking_count":2}],` +
			`"latest_report":{"id":"r1","project_id":"p1","tool_name":"trivy","scan_type":"sca",` +
			`"status":"completed","created_at":"2026-01-01T00:00:00Z"}}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runStats(t, d, "show", "demo"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"Project Stats for demo:",
		"Total Findings:  10",
		"Blocking:        3",
		"Active Waivers:  1",
		"Reports:         2",
		"critical: 2 total, 2 blocking",
		"Latest Scan:     r1 by trivy (completed)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in output: %q", want, got)
		}
	}
}

func TestStatsShowNoLatestReport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"total_findings":0,"blocking_count":0,"waiver_count":0,"report_count":0,"by_severity":[]}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runStats(t, d, "show", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "Latest Scan:") {
		t.Fatalf("unexpected latest scan in output: %q", got)
	}
}

func TestStatsShowMissingArg(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runStats(t, d, "show"); err == nil {
		t.Fatal("expected arg error")
	}
}

func TestStatsShowClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/stats", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runStats(t, d, "show", "demo"); err == nil {
		t.Fatal("expected client error")
	}
}

func TestStatsAging(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/aging", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"buckets":[{"bucket":"0-7d","count":5,"overdue":1}],"overdue_total":1,` +
			`"overdue":[{"id":"f1","title":"CVE-2026-1","severity":"critical","age_days":10,` +
			`"sla_days":7,"due_date":"2026-02-01T00:00:00Z","reopened":true}],` +
			`"reopened":2,"new_per_week":[]}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runStats(t, d, "aging", "demo"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"Aging for demo (SLA: critical 7d, high 30d, medium 90d, low 180d):",
		"finding(s), 1 overdue",
		"reopened ever: 2",
		"Oldest overdue:",
		"CVE-2026-1 [critical] 10d (SLA 7d, due 2026-02-01) (reopened)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in output: %q", want, got)
		}
	}
}

func TestStatsAgingNoOverdue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/aging", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"buckets":[],"overdue_total":0,"overdue":[],"reopened":0,"new_per_week":[]}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runStats(t, d, "aging", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "Oldest overdue:") {
		t.Fatalf("unexpected overdue section in output: %q", got)
	}
}

func TestStatsAgingMissingArg(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runStats(t, d, "aging"); err == nil {
		t.Fatal("expected arg error")
	}
}

func TestStatsAgingClientError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/aging", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	d, _, _ := testDeps(t, mux)
	if err := runStats(t, d, "aging", "demo"); err == nil {
		t.Fatal("expected client error")
	}
}

func TestStatsUnknownSubcommand(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runStats(t, d, "bogus", "demo"); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
}

func TestStatsNewClientError(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	d.NewClient = func() (*client.Client, error) { return nil, errors.New("no client") }
	if err := runStats(t, d, "show", "demo"); err == nil {
		t.Fatal("expected client construction error")
	}
	if err := runStats(t, d, "aging", "demo"); err == nil {
		t.Fatal("expected client construction error")
	}
}
