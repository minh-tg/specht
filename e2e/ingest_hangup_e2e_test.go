//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bigTrivyReport builds a trivy document with n distinct vulnerabilities, each
// in its own package so every one is its own finding.
func bigTrivyReport(t *testing.T, n int) json.RawMessage {
	t.Helper()
	vulns := make([]any, n)
	for i := range vulns {
		vulns[i] = map[string]any{
			"VulnerabilityID":  fmt.Sprintf("CVE-2099-%05d", i),
			"PkgID":            fmt.Sprintf("libhang-%d@1.0.0-r0", i),
			"PkgName":          fmt.Sprintf("libhang-%d", i),
			"PkgIdentifier":    map[string]any{"PURL": fmt.Sprintf("pkg:apk/alpine/libhang-%d@1.0.0-r0", i)},
			"InstalledVersion": "1.0.0-r0",
			"Severity":         "HIGH",
			"Title":            fmt.Sprintf("hang-up %d", i),
		}
	}
	raw, err := json.Marshal(map[string]any{
		"SchemaVersion": 2, "ArtifactName": "alpine:3.20", "ArtifactType": "container_image",
		"Results": []any{map[string]any{"Target": "alpine:3.20 (alpine 3.20.3)", "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": vulns}},
	})
	require.NoError(t, err)
	return raw
}

// A CI runner that gives up while the server is storing findings must not
// leave a half-written ingest. The write phase finishes on its own, so the
// report ends completed with an occurrence for every finding; if it were cut
// off it would end failed with its unsupported findings removed. Either way no
// report is left in processing and no finding is left without evidence.
func TestE2E_AClientHangingUpMidIngestLeavesAConsistentState(t *testing.T) {
	slug := newProject(t, "hangup")
	key := mintKey(t, slug)
	body, err := json.Marshal(map[string]any{"project": slug, "scanner": "trivy", "raw_data": bigTrivyReport(t, 3000), "branch": "main"})
	require.NoError(t, err)

	addr := strings.TrimPrefix(baseURL, "http://")
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST /api/v1/reports HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", addr, key, len(body))
	req.Write(body)
	_, err = conn.Write(req.Bytes())
	require.NoError(t, err)

	db := openE2EDB(t)
	var reportID string
	eventually(t, 20*time.Second, "report row created", func() bool {
		return db.QueryRow(context.Background(),
			`SELECT r.id::text FROM reports r JOIN projects p ON p.id = r.project_id WHERE p.slug = $1`, slug).Scan(&reportID) == nil
	})
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, conn.Close())

	var status string
	eventually(t, 60*time.Second, "report leaves processing", func() bool {
		if err := db.QueryRow(context.Background(), `SELECT status FROM reports WHERE id = $1`, reportID).Scan(&status); err != nil {
			return false
		}
		return status != "processing"
	})

	var findings, unevidenced, occurrences int
	require.NoError(t, db.QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM finding_occurrences o WHERE o.finding_id = f.id))
		FROM findings f JOIN projects p ON p.id = f.project_id WHERE p.slug = $1`, slug).Scan(&findings, &unevidenced))
	require.NoError(t, db.QueryRow(context.Background(), `SELECT count(*) FROM finding_occurrences WHERE report_id = $1`, reportID).Scan(&occurrences))

	require.Zero(t, unevidenced, "no finding is left without an occurrence (report %s)", status)
	switch status {
	case "completed":
		require.Equal(t, 3000, findings, "a completed report holds every finding")
		require.Equal(t, 3000, occurrences)
	case "failed":
		require.Zero(t, findings, "a failed report leaves none of its findings")
	default:
		t.Fatalf("report ended %q", status)
	}
}
