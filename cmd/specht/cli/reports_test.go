package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
)

const reportJSON = `{"id":"r1","project_id":"p1","tool_name":"trivy","scan_type":"filesystem","status":"completed","total_findings":12,"commit_sha":"0123456789abcdef","created_at":"2026-10-01T10:00:00Z"}`

func TestReportsList(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/reports", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "5" {
			t.Errorf("limit = %q", r.URL.Query().Get("limit"))
		}
		_, _ = w.Write([]byte(`[` + reportJSON + `,{"id":"r2","tool_name":"gitleaks","status":"failed","created_at":"2026-10-02T10:00:00Z"}]`))
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "reports", "list", "--project", "demo", "--limit", "5"); err != nil {
		t.Fatal(err)
	}
	want := "r1\tcompleted\ttrivy\t12\t0123456\t2026-10-01T10:00:00Z\nr2\tfailed\tgitleaks\t-\t-\t2026-10-02T10:00:00Z\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestReportsListWhenThereAreNone(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/reports", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "reports", "list", "--project", "demo"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No reports.\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestReportsGet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports/r1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(reportJSON)) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "reports", "get", "--id", "r1"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ID:", "r1", "Tool:", "trivy", "Status:", "completed", "Findings:", "12", "Commit:", "0123456789abcdef"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestReportsDeleteSaysHowManyFindingsWereArchived(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/reports/r1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set("X-Archived-Findings", "2")
		w.WriteHeader(http.StatusNoContent)
	})
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "reports", "delete", "--project", "demo", "--id", "r1"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "report deleted; 2 findings archived\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestReportsDeleteWithNothingArchived(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/demo/reports/r1", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	d, out, _ := testDeps(t, mux)
	if err := runCmd(t, d, "reports", "delete", "--project", "demo", "--id", "r1"); err != nil {
		t.Fatal(err)
	}
	if out.String() != "report deleted\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func uploadServer(t *testing.T, got *client.IngestPayload, reply string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(got)
		_, _ = w.Write([]byte(reply))
	})
	return mux
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReportsUploadSendsTheFileAsIs(t *testing.T) {
	var got client.IngestPayload
	d, out, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":3,"threshold_breached":true,"scan_mode":"full"}`))
	file := writeTemp(t, "trivy.json", `{"Results":[{"Target":"x"}]}`)

	err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file,
		"--branch", "main", "--commit", "abc123", "--environment", "production", "--owner", "github://acme/app")
	if err != nil {
		t.Fatal(err)
	}
	if got.Project != "demo" || got.Scanner != "trivy" || got.Branch != "main" || got.CommitSha != "abc123" ||
		got.Environment != "production" || got.Owner != "github://acme/app" {
		t.Fatalf("payload = %+v", got)
	}
	if string(got.RawData) != `{"Results":[{"Target":"x"}]}` {
		t.Fatalf("raw_data = %s", got.RawData)
	}
	if out.String() != "report r9: 3 findings, gate blocked\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestReportsUploadSaysWhenItWasAlreadyIngested(t *testing.T) {
	var got client.IngestPayload
	d, out, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":1,"threshold_breached":false,"scan_mode":"full","replayed":true}`))
	file := writeTemp(t, "a.json", `{}`)
	if err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file); err != nil {
		t.Fatal(err)
	}
	if out.String() != "report r9: 1 finding, gate passed (already ingested)\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestReportsUploadReadsLineBasedFilesAsAnArray(t *testing.T) {
	var got client.IngestPayload
	d, _, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":2}`))
	file := writeTemp(t, "nuclei.jsonl", "{\"template-id\":\"a\"}\n\n{\"template-id\":\"b\"}\n")
	if err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "nuclei", "--file", file); err != nil {
		t.Fatal(err)
	}
	if string(got.RawData) != `[{"template-id":"a"},{"template-id":"b"}]` {
		t.Fatalf("raw_data = %s", got.RawData)
	}
}

func TestReportsUploadReadsStandardInput(t *testing.T) {
	var got client.IngestPayload
	d, _, _ := testDeps(t, uploadServer(t, &got, `{"report_id":"r9","total_findings":0}`))
	d.In = bytes.NewBufferString(`{"matches":[]}`)
	if err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "grype", "--file", "-"); err != nil {
		t.Fatal(err)
	}
	if string(got.RawData) != `{"matches":[]}` {
		t.Fatalf("raw_data = %s", got.RawData)
	}
}

func TestReportsUploadRefusesWhatItCanTellIsWrongBeforeCallingTheServer(t *testing.T) {
	called := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports", func(http.ResponseWriter, *http.Request) { called = true })
	d, _, _ := testDeps(t, mux)
	good := writeTemp(t, "ok.json", `{}`)
	bad := writeTemp(t, "bad.json", `not json`)
	badLine := writeTemp(t, "bad.jsonl", "{\"a\":1}\noops\n")
	empty := writeTemp(t, "empty.jsonl", "\n\n")

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no project":      {[]string{"--scanner", "trivy", "--file", good}, "--project"},
		"no scanner":      {[]string{"--project", "demo", "--file", good}, "--scanner"},
		"no file":         {[]string{"--project", "demo", "--scanner", "trivy"}, "--file"},
		"missing file":    {[]string{"--project", "demo", "--scanner", "trivy", "--file", "/no/such/file.json"}, "no/such/file.json"},
		"not json":        {[]string{"--project", "demo", "--scanner", "trivy", "--file", bad}, "not valid JSON"},
		"bad line":        {[]string{"--project", "demo", "--scanner", "nuclei", "--file", badLine}, "line 2"},
		"empty line file": {[]string{"--project", "demo", "--scanner", "nuclei", "--file", empty}, "empty"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCmd(t, d, append([]string{"reports", "upload"}, tc.args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
	if called {
		t.Fatal("nothing invalid may reach the server")
	}
}

func TestReportsUploadShowsTheServersAdviceWhenItRefusesTheFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/reports", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"unrecognized_format","message":"The file is not trivy output. It looks like grype output; choose grype as the scanner."}}`))
	})
	d, _, _ := testDeps(t, mux)
	file := writeTemp(t, "a.json", `{}`)
	err := runCmd(t, d, "reports", "upload", "--project", "demo", "--scanner", "trivy", "--file", file)
	if err == nil || !strings.Contains(err.Error(), "choose grype as the scanner") {
		t.Fatalf("want the server's advice, got %v", err)
	}
}

func TestReadScanFileHandlesWhatEditorsAndShellsWrite(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	utf16 := []byte{0xFF, 0xFE, '{', 0, '}', 0}

	t.Run("a UTF-8 byte order mark is dropped", func(t *testing.T) {
		raw, err := readScanFile(Deps{}, write("bom.json", append([]byte{0xEF, 0xBB, 0xBF}, `{"runs":[]}`...)))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `{"runs":[]}` {
			t.Fatalf("got %q", raw)
		}
	})
	t.Run("a BOM on a line-based file is dropped too", func(t *testing.T) {
		raw, err := readScanFile(Deps{}, write("bom.jsonl", append([]byte{0xEF, 0xBB, 0xBF}, "{\"a\":1}\n{\"a\":2}\n"...)))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `[{"a":1},{"a":2}]` {
			t.Fatalf("got %q", raw)
		}
	})
	t.Run("UTF-16 is named, with the way out", func(t *testing.T) {
		_, err := readScanFile(Deps{}, write("utf16.json", utf16))
		if err == nil || !strings.Contains(err.Error(), "UTF-16") || !strings.Contains(err.Error(), "UTF-8") {
			t.Fatalf("want an error naming UTF-16 and UTF-8, got %v", err)
		}
	})
	t.Run("an empty file says so", func(t *testing.T) {
		for _, content := range []string{"", " \n\t\n"} {
			_, err := readScanFile(Deps{}, write("empty.json", []byte(content)))
			if err == nil || !strings.Contains(err.Error(), "empty") {
				t.Fatalf("content %q: want an empty-file error, got %v", content, err)
			}
		}
	})
	t.Run("standard input is named as such", func(t *testing.T) {
		_, err := readScanFile(Deps{In: strings.NewReader("")}, "-")
		if err == nil || !strings.Contains(err.Error(), "standard input") {
			t.Fatalf("want an error naming standard input, got %v", err)
		}
	})
}
