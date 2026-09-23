package cli

import (
	"net/http"
	"strings"
	"testing"
)

func TestFindingsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"id":"f1","current_title":"T","current_severity":"high","current_score":7.5,"state":"open","analysis_state":"unreviewed","gate_effect":"blocking","fingerprint":"fp","finding_kind":"sca"}]`)); err != nil {
			t.Errorf("write findings response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "f1\thigh\tT\tunreviewed\tblocking\t7.5") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFindingsListEmpty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("write findings response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "No findings found.") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFindingsListMissingProject(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list"); err == nil {
		t.Fatal("expected --project error")
	}
}

func TestFindingsListInvalidLimit(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo", "--limit", "-1"); err == nil {
		t.Fatal("expected --limit error")
	}
}

func TestFindingsGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"id":"f1","current_title":"T","current_severity":"high","current_score":7.5,"state":"open","analysis_state":"unreviewed","gate_effect":"blocking","fingerprint":"fp","finding_kind":"sca","introduced_commit_sha":"abc"}`)); err != nil {
			t.Errorf("write finding response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "get", "f1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "ID:           f1") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFindingsGetMissingArg(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "get"); err == nil {
		t.Fatal("expected arg error")
	}
}

func TestFindingsVerify(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/verify", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"finding_id":"f1","outcome":"fixed","report_id":"r1","detail":"gone"}`)); err != nil {
			t.Errorf("write verify response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "verify", "f1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "finding f1: fixed") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFindingsReachabilityList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/findings/f1/reachability", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`[{"id":"a1","finding_id":"f1","state":"reachable","evidence":"e","assessed_by":"u","created_at":"t","updated_at":"t"}]`)); err != nil {
			t.Errorf("write reachability response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "reachability", "--finding", "f1"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "reachable") {
		t.Fatalf("unexpected output: %q", got)
	}
}

func TestFindingsReachabilityMissingFinding(t *testing.T) {
	mux := http.NewServeMux()
	d, _, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "reachability"); err == nil {
		t.Fatal("expected --finding error")
	}
}
