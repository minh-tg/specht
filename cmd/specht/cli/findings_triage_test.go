package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestFindingsTriage(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s, want PATCH", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_, _ = w.Write([]byte(`{"finding_id":"f1","analysis_state":"false_positive","gate_effect":"ignored"}`))
	})
	d, out, _ := testDeps(t, mux)

	err := runCmd(t, d, "findings", "triage", "f1", "--state", "false_positive", "--reason", "test fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got["analysis_state"] != "false_positive" || got["reason"] != "test fixture" {
		t.Fatalf("body = %v", got)
	}
	if _, has := got["analysis_expires_at"]; has {
		t.Fatalf("no expiry was given, so none should be sent: %v", got)
	}
	if out.String() != "f1\tfalse_positive\tgate: ignored\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestFindingsTriageSendsAnExpiryAsAnEndOfDayTimestamp(t *testing.T) {
	var got map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"finding_id":"f1","analysis_state":"accepted_risk","gate_effect":"ignored"}`))
	})
	d, _, _ := testDeps(t, mux)

	err := runCmd(t, d, "findings", "triage", "f1", "--state", "accepted_risk", "--reason", "vendor patch due", "--expires", "2026-12-31")
	if err != nil {
		t.Fatal(err)
	}
	if got["analysis_expires_at"] != "2026-12-31T23:59:59Z" {
		t.Fatalf("expiry = %v", got["analysis_expires_at"])
	}
}

func TestFindingsTriageNeedsAStateAndAGoodExpiry(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1", func(http.ResponseWriter, *http.Request) { called = true })
	d, _, _ := testDeps(t, mux)

	if err := runCmd(t, d, "findings", "triage", "f1"); err == nil || !strings.Contains(err.Error(), "--state") {
		t.Fatalf("want an error naming --state, got %v", err)
	}
	if err := runCmd(t, d, "findings", "triage", "f1", "--state", "accepted_risk", "--expires", "soon"); err == nil || !strings.Contains(err.Error(), "--expires") {
		t.Fatalf("want an error naming --expires, got %v", err)
	}
	if called {
		t.Fatal("a command that failed validation must not call the server")
	}
}

func TestFindingsTriageShowsTheServersReasonWhenItRefuses(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"reason_required","message":"a reason is required for false_positive"}}`))
	})
	d, _, _ := testDeps(t, mux)

	err := runCmd(t, d, "findings", "triage", "f1", "--state", "false_positive")
	if err == nil || !strings.Contains(err.Error(), "a reason is required for false_positive") {
		t.Fatalf("want the server's message, got %v", err)
	}
}

func TestFindingsTriageJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"finding_id":"f1","analysis_state":"in_triage","gate_effect":"blocking"}`))
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "--format", "json", "findings", "triage", "f1", "--state", "in_triage"); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v["finding_id"] != "f1" {
		t.Fatalf("output is not the JSON result: %q (%v)", out.String(), err)
	}
}

func TestFindingsBulkTriage(t *testing.T) {
	var got struct {
		FindingIDs    []string `json:"finding_ids"`
		AnalysisState string   `json:"analysis_state"`
		Reason        string   `json:"reason"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/bulk-analysis", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"results":[{"finding_id":"a","analysis_state":"not_affected","gate_effect":"ignored"},{"finding_id":"b","analysis_state":"not_affected","gate_effect":"ignored"}]}`))
	})
	d, out, _ := testDeps(t, mux)

	err := runCmd(t, d, "findings", "bulk-triage", "--id", "a,b", "--id", "c", "--state", "not_affected", "--reason", "dev only")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.FindingIDs, ",") != "a,b,c" || got.AnalysisState != "not_affected" || got.Reason != "dev only" {
		t.Fatalf("body = %+v", got)
	}
	if out.String() != "a\tnot_affected\tgate: ignored\nb\tnot_affected\tgate: ignored\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestFindingsBulkTriageNeedsIDsAndAState(t *testing.T) {
	d, _, _ := testDeps(t, http.NewServeMux())
	if err := runCmd(t, d, "findings", "bulk-triage", "--state", "in_triage"); err == nil || !strings.Contains(err.Error(), "--id") {
		t.Fatalf("want an error naming --id, got %v", err)
	}
	if err := runCmd(t, d, "findings", "bulk-triage", "--id", "a"); err == nil || !strings.Contains(err.Error(), "--state") {
		t.Fatalf("want an error naming --state, got %v", err)
	}
}

func TestFindingsEvents(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/events", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q["type"]; len(got) != 2 || got[0] != "triage" || got[1] != "reopened" {
			t.Errorf("type = %v", got)
		}
		if q.Get("limit") != "5" {
			t.Errorf("limit = %q", q.Get("limit"))
		}
		_, _ = w.Write([]byte(`[{"id":"e1","finding_id":"f1","user_id":"u1","user_name":"Ada","event_type":"triage","old_value":"unanalyzed","new_value":"false_positive","comment":"fixture","created_at":"2026-10-01T10:00:00Z"}]`))
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "findings", "events", "f1", "--type", "triage,reopened", "--limit", "5"); err != nil {
		t.Fatal(err)
	}
	want := "2026-10-01T10:00:00Z\ttriage\tAda\tunanalyzed -> false_positive\tfixture\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestFindingsEventsWhenThereAreNone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/events", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "events", "f1"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No events.\n" {
		t.Fatalf("output = %q", out.String())
	}
}
