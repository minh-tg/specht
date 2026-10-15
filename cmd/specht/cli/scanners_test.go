package cli

import (
	"net/http"
	"strings"
	"testing"
)

func TestScannersList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scanners", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"semgrep","display_name":"Semgrep","formats":[
			{"name":"JSON","extensions":[".json"],"command":"semgrep scan --json -o semgrep.json","tested_with":"Semgrep 1.172.0"},
			{"name":"SARIF","extensions":[".json",".sarif"],"command":"semgrep scan --sarif -o semgrep.sarif","tested_with":"Semgrep 1.172.0","note":"Same findings."}]},
			{"name":"old","display_name":"old","formats":[]}]`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "scanners", "list"); err != nil {
		t.Fatal(err)
	}
	want := "semgrep\tSemgrep\n" +
		"  JSON (.json)\tsemgrep scan --json -o semgrep.json\n" +
		"  SARIF (.json, .sarif)\tsemgrep scan --sarif -o semgrep.sarif\n" +
		"old\told\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestScannersListExplainsWhyAKeyIsRefused(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scanners", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"session_required","message":"this route needs a signed-in session"}}`))
	})
	d, _, _ := testDeps(t, mux)
	err := runCmd(t, d, "scanners", "list")
	if err == nil || !strings.Contains(err.Error(), "signed-in session") {
		t.Fatalf("want the server's reason, got %v", err)
	}
}
