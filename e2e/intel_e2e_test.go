//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Read-time intel enrichment: the finding detail embeds EPSS/KEV intel,
// resolved on the read path from the configured feeds.

type intelBlock struct {
	CVEID     string   `json:"cve_id"`
	EPSS      *float64 `json:"epss"`
	EPSSDate  string   `json:"epss_date"`
	KEV       bool     `json:"kev"`
	KEVAdded  string   `json:"kev_added"`
	Sources   []string `json:"sources"`
	FetchedAt string   `json:"fetched_at"`
	Stale     bool     `json:"stale"`
}

type findingDetail struct {
	ID    string      `json:"id"`
	Title string      `json:"current_title"`
	Intel *intelBlock `json:"intel"`
}

func getFindingDetail(t *testing.T, id string) findingDetail {
	t.Helper()
	return request[findingDetail](t, http.MethodGet, "/api/v1/findings/"+id,
		adminToken, nil, http.StatusOK)
}

// awaitDetailIntel re-reads the given finding details until one carries intel
// that match accepts, and returns that detail. A read schedules the refresh
// that fills the cache, so the first reads may still come back without intel.
func awaitDetailIntel(t *testing.T, ids []string, match func(*intelBlock) bool) findingDetail {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, id := range ids {
			if d := getFindingDetail(t, id); d.Intel != nil && match(d.Intel) {
				return d
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("background intel refresh did not land within 10s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestE2E_FindingIntelOnDetail(t *testing.T) {
	t.Run("armed CVE carries epss and kev, unknown siblings stay bare", func(t *testing.T) {
		slug := newProject(t, "intel-detail")
		// alpine-scan reports CVE-2024-9143 and CVE-2024-8888.
		ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", nil)
		fakes.intel.armEPSS("CVE-2024-9143", 0.97)
		fakes.intel.armKEV("CVE-2024-9143", "2026-01-05")
		defer fakes.intel.disarm()

		findings := listScanFindings(t, slug)
		require.Len(t, findings, 2)

		ids := make([]string, 0, len(findings))
		for _, f := range findings {
			ids = append(ids, f.ID)
		}
		// The KEV catalog is reused for the intel TTL, so a catalog fetched
		// for an earlier subtest, before this CVE was armed, can still be
		// served. Wait for the refresh after it expires to carry both signals.
		armed := awaitDetailIntel(t, ids, func(in *intelBlock) bool { return in.EPSS != nil && in.KEV })
		var bare *findingDetail
		for _, id := range ids {
			if id != armed.ID {
				dd := getFindingDetail(t, id)
				bare = &dd
			}
		}
		require.NotNil(t, bare, "the unknown CVE's detail stays bare")
		require.Nil(t, bare.Intel, "the unknown CVE's detail stays bare")

		require.Equal(t, "CVE-2024-9143", armed.Intel.CVEID)
		require.NotNil(t, armed.Intel.EPSS)
		require.InDelta(t, 0.97, *armed.Intel.EPSS, 0.0001)
		require.Equal(t, "2026-09-01", armed.Intel.EPSSDate)
		require.True(t, armed.Intel.KEV)
		require.Equal(t, "2026-01-05", armed.Intel.KEVAdded)
		require.ElementsMatch(t, []string{"epss", "kev"}, armed.Intel.Sources)
		require.NotEmpty(t, armed.Intel.FetchedAt)
		require.False(t, armed.Intel.Stale)
	})

	t.Run("findings without a CVE dimension carry no intel", func(t *testing.T) {
		slug := newProject(t, "intel-noncve")
		ingestFixture(t, slug, adminToken, "high.sarif.json")
		findings := listScanFindings(t, slug)
		require.NotEmpty(t, findings)
		for _, f := range findings {
			require.Nil(t, getFindingDetail(t, f.ID).Intel,
				"non-CVE findings never resolve intel")
		}
	})

	t.Run("a feed outage degrades to the stale cached record", func(t *testing.T) {
		slug := newProject(t, "intel-outage")
		ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", nil)
		fakes.intel.armEPSS("CVE-2024-9143", 0.42)
		fakes.intel.armKEV("CVE-2024-9143", "2026-01-05")
		defer fakes.intel.disarm()

		// Expire whatever an earlier subtest cached for this CVE, then
		// prime with a fresh value — a re-read after TTL picking up 0.42
		// proves re-reads pull the latest feed data.
		time.Sleep(1500 * time.Millisecond)
		ids := make([]string, 0)
		for _, f := range listScanFindings(t, slug) {
			ids = append(ids, f.ID)
		}
		// The read after expiry serves the stale record and refreshes it in
		// the background, so poll until the new feed value lands.
		fresh := awaitDetailIntel(t, ids, func(in *intelBlock) bool {
			return in.EPSS != nil && *in.EPSS > 0.41 && *in.EPSS < 0.43 && !in.Stale
		})
		target := fresh.ID
		require.NotEmpty(t, target, "the armed CVE resolved")

		// Let the cache expire while both feeds are down.
		time.Sleep(1500 * time.Millisecond)
		fakes.intel.setFail(true)
		defer fakes.intel.setFail(false)

		d := getFindingDetail(t, target)
		require.NotNil(t, d.Intel, "an outage never blanks the detail")
		require.True(t, d.Intel.Stale, "the expired record is served flagged stale")
		require.NotNil(t, d.Intel.EPSS)
		require.InDelta(t, 0.42, *d.Intel.EPSS, 0.0001, "the last known value survives")
	})
}
