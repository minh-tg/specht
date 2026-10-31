package cli

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
)

func TestReportsUploadDeclaresTheScanFilter(t *testing.T) {
	t.Setenv("TRIVY_SEVERITY", "")
	t.Setenv("TRIVY_IGNORE_UNFIXED", "")
	var got client.IngestPayload
	d, _, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":0}`))
	file := writeTemp(t, "trivy.json", `{"Results":[]}`)

	err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file,
		"--scan-severities", "HIGH,critical", "--fixable-only")
	if err != nil {
		t.Fatal(err)
	}
	want := &client.ScanFilter{Severities: []string{"HIGH", "critical"}, FixableOnly: true}
	if !reflect.DeepEqual(got.ScanFilter, want) {
		t.Fatalf("scan_filter = %+v, want %+v", got.ScanFilter, want)
	}
}

func TestReportsUploadFallsBackToTheTrivyEnvironment(t *testing.T) {
	t.Setenv("TRIVY_SEVERITY", "HIGH,CRITICAL")
	t.Setenv("TRIVY_IGNORE_UNFIXED", "true")
	var got client.IngestPayload
	d, _, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":0}`))
	file := writeTemp(t, "trivy.json", `{"Results":[]}`)

	if err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file); err != nil {
		t.Fatal(err)
	}
	want := &client.ScanFilter{Severities: []string{"HIGH", "CRITICAL"}, FixableOnly: true}
	if !reflect.DeepEqual(got.ScanFilter, want) {
		t.Fatalf("scan_filter = %+v, want %+v", got.ScanFilter, want)
	}

	// An explicit --fixable-only=false beats the environment.
	got = client.IngestPayload{}
	if err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file, "--fixable-only=false"); err != nil {
		t.Fatal(err)
	}
	want = &client.ScanFilter{Severities: []string{"HIGH", "CRITICAL"}}
	if !reflect.DeepEqual(got.ScanFilter, want) {
		t.Fatalf("scan_filter = %+v, want %+v", got.ScanFilter, want)
	}
}

func TestReportsUploadSendsNoScanFilterByDefault(t *testing.T) {
	t.Setenv("TRIVY_SEVERITY", "")
	t.Setenv("TRIVY_IGNORE_UNFIXED", "")
	var got client.IngestPayload
	d, _, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":0}`))
	file := writeTemp(t, "trivy.json", `{"Results":[]}`)

	if err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file); err != nil {
		t.Fatal(err)
	}
	if got.ScanFilter != nil {
		t.Fatalf("scan_filter = %+v, want none", got.ScanFilter)
	}
}

func TestReportsGetShowsTheScanFilter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports/r1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"r1","tool_name":"trivy","status":"completed","scan_type":"image","created_at":"2026-10-01T10:00:00Z","scan_filter":{"severities":["high","critical"],"fixable_only":true}}`))
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "reports", "get", "--id", "r1"); err != nil {
		t.Fatal(err)
	}
	if want := "Filter:    severities high,critical, fixable only true\n"; !strings.Contains(out.String(), want) {
		t.Fatalf("output lacks %q:\n%s", want, out.String())
	}
}
