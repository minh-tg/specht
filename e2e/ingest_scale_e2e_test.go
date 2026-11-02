//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sarifResultsInOneFile builds a SARIF run whose results all share one rule
// and one file, so they collapse into a single finding with one entry per
// result. Each message carries about 120 bytes of text, as a real one does, so
// the report stays above the density floor the ingest refuses below.
func sarifResultsInOneFile(n int) []byte {
	text := strings.Repeat("user input reaches a SQL query without escaping ", 3)
	var b bytes.Buffer
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"r"}]}},"results":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ruleId":"r","message":{"text":"%s(%d)"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":%d}}}]}`, text, i, i+1)
	}
	b.WriteString(`]}]}`)
	return b.Bytes()
}

// TestE2E_ALargeReportNamingOneFindingManyTimesIngestsInTime walks the story
// behind the ingest time of a report with tens of thousands of results in one
// file. Every result updated the same finding row inside the ingest
// transaction, each update slower than the last, so a 3 MiB report ran past
// the three minute request limit and the client saw the connection close. The
// finding is now written for its first and last result only.
func TestE2E_ALargeReportNamingOneFindingManyTimesIngestsInTime(t *testing.T) {
	const results = 23000
	slug := newProject(t, "many-results")
	doc := sarifResultsInOneFile(results)

	start := time.Now()
	status, body := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, map[string]any{
		"project": slug, "scanner": "sarif", "raw_data": json.RawMessage(doc),
	})
	elapsed := time.Since(start)

	require.Equal(t, http.StatusCreated, status, string(body))
	var resp ingestResponse
	require.NoError(t, json.Unmarshal(body, &resp))
	t.Logf("%d results, %d KiB, ingested in %s", results, len(doc)>>10, elapsed.Round(time.Millisecond))
	assert.Equal(t, results, resp.TotalFindings, "every result counts")
	assert.Equal(t, 1, resp.IntroducedCount, "the results are one finding")
	assert.Equal(t, results-1, resp.PreExistingCount)
	assert.Less(t, elapsed, time.Minute, "the ingest time may not grow with the square of the results")
}
