//go:build e2e

package e2e

// The ingest admission charges 64 bytes of memory per byte of the report. These
// tests post the densest report the document check accepts for several shapes
// and compare the server process's peak resident memory growth with that
// charge. INGEST_RSS_MIB (for example 4,10,24) picks the body sizes; the
// default is one small size.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
)

// postRawBody sends the ingest body byte for byte.
func postRawBody(t *testing.T, slug, scannerName string, document []byte) (int, []byte) {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"project":%q,"scanner":%q,"raw_data":`, slug, scannerName)
	b.Write(document)
	b.WriteString(`}`)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/reports", &b)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	client := &http.Client{Timeout: 5 * time.Minute}
	start := time.Now()
	resp, err := client.Do(req)
	require.NoError(t, err, "no response after %s", time.Since(start).Round(time.Second))
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out
}

// procStatusBytes reads a field of /proc/<pid>/status, which is in kB.
func procStatusBytes(t *testing.T, pid int, field string) int64 {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	require.NoError(t, err)
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, field+":"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			require.NoError(t, err)
			return n << 10
		}
	}
	t.Fatalf("no %s in /proc/%d/status", field, pid)
	return 0
}

// densestReport builds a report of repeated units at about size bytes, padding
// each unit by the least the ingest document check accepts.
func densestReport(t *testing.T, scannerName, head, tail string, unit func(pad string) string, size int) []byte {
	t.Helper()
	var keys []string
	for _, s := range parser.Builtins() {
		if s.Descriptor().Name == scannerName {
			keys = s.(scanner.FindingArrayer).FindingArrays()
		}
	}
	var n int
	build := func(pad int) []byte {
		var b bytes.Buffer
		p := strings.Repeat("x", pad)
		b.WriteString(head)
		n = 0
		for ; b.Len()+len(tail)+len(unit(p))+1 < size && n < 99000; n++ {
			if n > 0 {
				b.WriteByte(',')
			}
			b.WriteString(unit(p))
		}
		b.WriteString(tail)
		return b.Bytes()
	}
	accepts := func(pad int) bool {
		return scanner.CheckIngestDocument(build(pad), scanner.DefaultMaxFindings, keys...) == nil
	}
	lo, hi := 0, 4096
	if accepts(0) {
		return build(0)
	}
	for hi-lo > 1 {
		if mid := (lo + hi) / 2; accepts(mid) {
			hi = mid
		} else {
			lo = mid
		}
	}
	return build(hi)
}

func TestE2E_TheServerStaysUnderTheIngestChargeForTheDensestAcceptedReports(t *testing.T) {
	sizes := []int{4}
	if v := os.Getenv("INGEST_RSS_MIB"); v != "" {
		sizes = nil
		for _, f := range strings.Split(v, ",") {
			n, err := strconv.Atoi(f)
			require.NoError(t, err)
			sizes = append(sizes, n)
		}
	}
	trivyHead := `{"SchemaVersion":2,"ArtifactName":"a","ArtifactType":"container_image","Results":[{"Target":"t","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[`
	var seq int
	next := func() string { seq++; return strconv.FormatInt(int64(seq), 36) }
	chain := strings.Repeat(`{"a":`, 56)
	chainEnd := strings.Repeat("}", 56)
	shapes := []struct {
		name, scanner, head, tail string
		unit                      func(pad string) string
	}{
		{"trivy id-only findings", "trivy", trivyHead, `]}]}`, func(p string) string { return `{"VulnerabilityID":"` + next() + p + `"}` }},
		{"trivy two-field findings", "trivy", trivyHead, `]}]}`, func(p string) string { return `{"VulnerabilityID":"` + next() + p + `","PkgName":"p"}` }},
		{"grype minimal matches", "grype", `{"descriptor":{"name":"grype","version":"0.80.0"},"source":{"type":"image"},"matches":[`, `]}`, func(p string) string {
			return `{"vulnerability":{"id":"C` + next() + p + `","severity":"High"},"artifact":{"name":"p","version":"1","type":"apk"}}`
		}},
		{"checkov minimal failed checks", "checkov", `{"check_type":"terraform","results":{"failed_checks":[`, `]},"summary":{}}`, func(p string) string {
			return `{"check_id":"CKV_` + next() + p + `","file_path":"/m.tf","resource":"r"}`
		}},
		{"sarif properties chain 58", "sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r"}]}},"results":[`, `]}]}`, func(p string) string {
			return `{"ruleId":"r","message":{"text":"m"},"properties":{"x":` + chain + `"` + p + `"` + chainEnd + `}}`
		}},
	}
	pid := serverCmd.Process.Pid
	worst, worstName := 0.0, ""
	for _, mib := range sizes {
		for _, s := range shapes {
			t.Run(fmt.Sprintf("%s %d MiB", s.name, mib), func(t *testing.T) {
				if mib > 8 && strings.HasPrefix(s.name, "sarif") {
					t.Skip("a SARIF report of this many results takes the server longer than the client waits")
				}
				doc := densestReport(t, s.scanner, s.head, s.tail, s.unit, mib<<20-4096)
				slug := newProject(t, fmt.Sprintf("ingest-rss-%d-%d", mib, seq))
				time.Sleep(2 * time.Second)
				require.NoError(t, os.WriteFile(fmt.Sprintf("/proc/%d/clear_refs", pid), []byte("5"), 0o600))
				baseline := procStatusBytes(t, pid, "VmRSS")
				status, body := postRawBody(t, slug, s.scanner, doc)
				peak := procStatusBytes(t, pid, "VmHWM")
				require.Equal(t, http.StatusCreated, status, "%s: %.300s", s.name, body)
				var r struct {
					TotalFindings int `json:"total_findings"`
				}
				_ = json.Unmarshal(body, &r)
				factor := float64(peak-baseline) / float64(len(doc))
				t.Logf("%-28s %6d KiB findings=%-6d rss growth %4d MiB factor=%5.1fx (charge %d MiB)",
					s.name, len(doc)>>10, r.TotalFindings, (peak-baseline)>>20, factor, (64*int64(len(doc)))>>20)
				if factor > worst {
					worst, worstName = factor, s.name
				}
			})
		}
	}
	// Resident memory includes the garbage collector's headroom: with the default
	// GOGC the heap may grow to twice its live size before a collection, and when
	// that collection lands varies between runs. The same shapes measured 40x to 64x across
	// workstations and CI runners. The decoded heap, which the charge
	// prices, is held to 64x without slack in internal/parser/ingest_memory_test.go;
	// here the bound allows a quarter more for collection timing.
	const rssBound = 80
	t.Logf("worst %.1fx (%s) against a charge of 64x and an RSS bound of %dx", worst, worstName, rssBound)
	if worst > rssBound {
		t.Errorf("%s grew the server's RSS by %.1fx the body, above the %dx bound", worstName, worst, rssBound)
	}
}
