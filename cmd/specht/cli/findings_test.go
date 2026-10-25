package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
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

// pagedFindingsHandler serves total findings the way the server does: 20 per
// page without a limit, at most 500 per page, and an offset to skip.
func pagedFindingsHandler(t *testing.T, total int, requests *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.URL.RawQuery)
		limit, offset := 20, 0
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, _ = strconv.Atoi(v)
		}
		limit = min(limit, 500)
		if v := r.URL.Query().Get("offset"); v != "" {
			offset, _ = strconv.Atoi(v)
		}
		page := []map[string]string{}
		for i := offset; i < min(offset+limit, total); i++ {
			page = append(page, map[string]string{"id": fmt.Sprintf("f%d", i)})
		}
		if err := json.NewEncoder(w).Encode(page); err != nil {
			t.Errorf("write findings page: %v", err)
		}
	}
}

func listedFindingIDs(t *testing.T, raw string) []string {
	t.Helper()
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("decode output: %v: %q", err, raw)
	}
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func TestFindingsListPagesThroughEveryFinding(t *testing.T) {
	var requests []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", pagedFindingsHandler(t, 1203, &requests))
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	ids := listedFindingIDs(t, out.String())
	if len(ids) != 1203 {
		t.Fatalf("want 1203 findings, got %d (requests %v)", len(ids), requests)
	}
	for i, id := range ids {
		if id != fmt.Sprintf("f%d", i) {
			t.Fatalf("row %d is %s: pages overlap or skip", i, id)
		}
	}
	if len(requests) != 3 {
		t.Fatalf("want 3 page requests, got %v", requests)
	}
}

func TestFindingsListLimitCapsTheTotal(t *testing.T) {
	var requests []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", pagedFindingsHandler(t, 1203, &requests))
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo", "--format", "json", "--limit", "600"); err != nil {
		t.Fatal(err)
	}
	if ids := listedFindingIDs(t, out.String()); len(ids) != 600 || ids[599] != "f599" {
		t.Fatalf("want f0..f599, got %d rows (requests %v)", len(ids), requests)
	}
	if want := []string{"limit=500", "limit=100&offset=500"}; !slices.Equal(requests, want) {
		t.Fatalf("want requests %v, got %v", want, requests)
	}
}

func TestFindingsListExactPageEndsOnEmptyPage(t *testing.T) {
	var requests []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/findings", pagedFindingsHandler(t, 500, &requests))
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "findings", "list", "--project", "demo", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	if ids := listedFindingIDs(t, out.String()); len(ids) != 500 {
		t.Fatalf("want 500 findings, got %d", len(ids))
	}
	if len(requests) != 2 {
		t.Fatalf("want a full page then an empty one, got %v", requests)
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
