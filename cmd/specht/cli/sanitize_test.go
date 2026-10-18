package cli

import (
	"net/http"
	"strings"
	"testing"
)

// A scanner supplies finding titles, so a title can carry an ANSI escape
// sequence or a bidi override. Both must be gone from what the terminal gets.
func TestFindingsListStripsTerminalControlsFromTitle(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"id":"f1","current_title":"safe\u001b[31m\u202egnihs","current_severity":"high","analysis_state":"unreviewed","gate_effect":"blocking"}]`)); err != nil {
			t.Errorf("write findings response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.ContainsAny(got, "\x1b\u202e") {
		t.Fatalf("output still holds terminal controls: %q", got)
	}
	if !strings.Contains(got, "safegnihs") {
		t.Fatalf("output lost the title text: %q", got)
	}
}

func TestReportsGetStripsTerminalControlsFromToolName(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports/r1", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"id":"r1","tool_name":"trivy\u001b[2J\u202e-extra","status":"completed","created_at":"2026-10-01T10:00:00Z"}`)); err != nil {
			t.Errorf("write report response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "reports", "get", "--id", "r1"); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.ContainsAny(got, "\x1b\u202e") {
		t.Fatalf("output still holds terminal controls: %q", got)
	}
	if !strings.Contains(got, "trivy-extra") {
		t.Fatalf("output lost the tool name: %q", got)
	}
}

// Plain text, tabs and newlines must survive the sanitizer.
func TestFindingsListKeepsPlainTextTabsAndNewlines(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"id":"f1","current_title":"plain title","current_severity":"high","analysis_state":"unreviewed","gate_effect":"blocking"}]`)); err != nil {
			t.Errorf("write findings response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "f1\thigh\tplain title\tunreviewed\tblocking\t\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
