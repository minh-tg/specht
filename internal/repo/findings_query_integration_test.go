//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

type seededFinding struct {
	fingerprint string
	title       string
	severity    string
	rank        int16
	ageDays     int
	analysis    string
}

// seedFindings inserts findings with controlled severity, age and analysis
// state and returns the fingerprints in insertion order.
func seedFindings(t *testing.T, repos *Repos, projectID pgtype.UUID, rows []seededFinding) {
	t.Helper()
	ctx := context.Background()
	for _, row := range rows {
		seen := pgtype.Timestamptz{Time: time.Now().Add(-time.Duration(row.ageDays) * 24 * time.Hour), Valid: true}
		_, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
			ProjectID:    projectID,
			FindingKind:  "sca",
			Fingerprint:  row.fingerprint,
			CurrentTitle: row.title,
			Severity:     row.severity,
			SeverityRank: row.rank,
			FirstSeenAt:  seen,
			LastSeenAt:   seen,
		})
		require.NoError(t, err)
		if row.analysis != "" {
			_, err = repos.pool.Exec(ctx,
				`UPDATE findings SET analysis_state = $1 WHERE project_id = $2 AND fingerprint = $3`,
				row.analysis, projectID, row.fingerprint)
			require.NoError(t, err)
		}
	}
}

func fingerprints(findings []port.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Fingerprint
	}
	return out
}

func TestFindingsQuerySortFilterAndSearch(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	stores := NewPortStores(repos.pool)
	pid := toUUID(project.ID)

	seedFindings(t, repos, project.ID, []seededFinding{
		{"SCA:CVE-2025-0001:pkg:deb/openssh@9.6", "openssh-server: security issue", "critical", 4, 4, "in_triage"},
		{"SCA:CVE-2025-0002:pkg:deb/expat@2.5", "expat: security issue", "high", 3, 40, ""},
		{"SAST:jwt-secret:internal/auth/token.go", "Hardcoded JWT secret", "high", 3, 9, "exploitable"},
		{"SCA:CVE-2024-0003:pkg:deb/zlib@1.3", "zlib: heap overflow", "medium", 2, 21, "false_positive"},
		{"IAC:s3-encryption:infra/storage.tf", "100% S3_bucket without encryption", "low", 1, 77, ""},
	})

	list := func(p port.ListFindingsParams) []string {
		t.Helper()
		p.Limit = 50
		got, err := stores.Findings.ListByProject(ctx, pid, p)
		require.NoError(t, err)
		total, err := stores.Findings.CountByProject(ctx, pid, p)
		require.NoError(t, err)
		assert.Equal(t, int64(len(got)), total, "the count agrees with the unpaged list for %+v", p)
		return fingerprints(got)
	}
	const (
		openssh = "SCA:CVE-2025-0001:pkg:deb/openssh@9.6"
		expat   = "SCA:CVE-2025-0002:pkg:deb/expat@2.5"
		jwt     = "SAST:jwt-secret:internal/auth/token.go"
		zlib    = "SCA:CVE-2024-0003:pkg:deb/zlib@1.3"
		s3      = "IAC:s3-encryption:infra/storage.tf"
	)

	t.Run("default order is most severe first", func(t *testing.T) {
		got := list(port.ListFindingsParams{})
		assert.Equal(t, openssh, got[0])
		assert.Equal(t, s3, got[4])
		assert.Equal(t, got, list(port.ListFindingsParams{SortKey: "severity", SortDir: "desc"}))
	})

	t.Run("sort by severity ascending", func(t *testing.T) {
		got := list(port.ListFindingsParams{SortKey: "severity", SortDir: "asc"})
		assert.Equal(t, s3, got[0])
		assert.Equal(t, openssh, got[4])
	})

	t.Run("sort by first seen", func(t *testing.T) {
		assert.Equal(t, []string{s3, expat, zlib, jwt, openssh},
			list(port.ListFindingsParams{SortKey: "first_seen", SortDir: "asc"}), "oldest first")
		assert.Equal(t, []string{openssh, jwt, zlib, expat, s3},
			list(port.ListFindingsParams{SortKey: "first_seen", SortDir: "desc"}), "newest first")
	})

	t.Run("sort by title", func(t *testing.T) {
		got := list(port.ListFindingsParams{SortKey: "title", SortDir: "asc"})
		assert.Equal(t, s3, got[0], "100% ... sorts before letters")
		assert.Equal(t, zlib, got[4])
	})

	t.Run("analysis state filter, with unanalyzed for findings nobody looked at", func(t *testing.T) {
		assert.ElementsMatch(t, []string{openssh, jwt},
			list(port.ListFindingsParams{AnalysisStates: []string{"in_triage", "exploitable"}}))
		assert.ElementsMatch(t, []string{expat, s3},
			list(port.ListFindingsParams{AnalysisStates: []string{"unanalyzed"}}))
		_, err := repos.pool.Exec(ctx, `UPDATE findings SET analysis_state = '' WHERE fingerprint = $1`, expat)
		if err == nil {
			assert.Contains(t, list(port.ListFindingsParams{AnalysisStates: []string{"unanalyzed"}}), expat,
				"an empty stored state still counts as unanalyzed")
		}
	})

	t.Run("search matches title and fingerprint, case-insensitively", func(t *testing.T) {
		assert.Equal(t, []string{expat}, list(port.ListFindingsParams{Search: "EXPAT"}))
		assert.Equal(t, []string{openssh}, list(port.ListFindingsParams{Search: "cve-2025-0001"}), "the CVE id lives in the fingerprint")
		assert.Equal(t, []string{jwt}, list(port.ListFindingsParams{Search: "token.go"}))
		assert.Empty(t, list(port.ListFindingsParams{Search: "no such thing"}))
	})

	t.Run("search text is literal, not a pattern", func(t *testing.T) {
		// The caller escapes LIKE metacharacters; the repository passes the
		// pattern through. A raw percent would match everything.
		assert.Equal(t, []string{s3}, list(port.ListFindingsParams{Search: `100\%`}))
		assert.Equal(t, []string{s3}, list(port.ListFindingsParams{Search: `S3\_bucket`}))
		assert.Empty(t, list(port.ListFindingsParams{Search: `S3\_ucket`}), "an escaped underscore is not a wildcard")
	})

	t.Run("filters combine", func(t *testing.T) {
		assert.Equal(t, []string{expat, s3}, list(port.ListFindingsParams{
			AnalysisStates: []string{"unanalyzed"}, SortKey: "severity", SortDir: "desc",
		}))
		assert.Equal(t, []string{expat}, list(port.ListFindingsParams{
			AnalysisStates: []string{"unanalyzed"}, Severities: []string{"high"},
		}))
	})
}

// A page boundary must neither repeat nor skip a row, whatever the sort, even
// when many rows tie on the sort key.
func TestFindingsQueryPagingIsStable(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	stores := NewPortStores(repos.pool)
	pid := toUUID(project.ID)

	rows := make([]seededFinding, 0, 25)
	for i := 0; i < 25; i++ {
		rank := int16(1 + i%4)
		rows = append(rows, seededFinding{
			fingerprint: fmt.Sprintf("SCA:CVE-2025-%04d:pkg", i), title: fmt.Sprintf("finding %02d", i%5),
			severity: [...]string{"low", "medium", "high", "critical"}[rank-1], rank: rank, ageDays: i % 3,
		})
	}
	seedFindings(t, repos, project.ID, rows)

	for _, sort := range []string{"severity", "first_seen", "last_seen", "title"} {
		for _, dir := range []string{"asc", "desc"} {
			t.Run(sort+" "+dir, func(t *testing.T) {
				seen := map[string]bool{}
				var order []string
				for offset := int32(0); offset < 25; offset += 7 {
					page, err := stores.Findings.ListByProject(ctx, pid, port.ListFindingsParams{
						SortKey: sort, SortDir: dir, Limit: 7, Offset: offset,
					})
					require.NoError(t, err)
					for _, f := range page {
						assert.False(t, seen[f.Fingerprint], "%s repeated across pages", f.Fingerprint)
						seen[f.Fingerprint] = true
						order = append(order, f.Fingerprint)
					}
				}
				assert.Len(t, order, 25, "no row is skipped")

				again, err := stores.Findings.ListByProject(ctx, pid, port.ListFindingsParams{
					SortKey: sort, SortDir: dir, Limit: 25,
				})
				require.NoError(t, err)
				assert.Equal(t, order, fingerprints(again), "paged and unpaged orders agree")
			})
		}
	}
}
