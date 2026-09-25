//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ADR-023's first wiring (BP-50): the finding detail embeds EPSS/KEV
// intel, resolved on the read path from the configured feeds.

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

		var armed, bare *findingDetail
		for _, f := range findings {
			d := getFindingDetail(t, f.ID)
			if d.Intel != nil {
				dd := d
				armed = &dd
			} else {
				dd := d
				bare = &dd
			}
		}
		require.NotNil(t, armed, "the armed CVE's detail carries intel")
		require.NotNil(t, bare, "the unknown CVE's detail stays bare")

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
		var target string
		for _, f := range listScanFindings(t, slug) {
			if d := getFindingDetail(t, f.ID); d.Intel != nil {
				target = f.ID
				require.InDelta(t, 0.42, *d.Intel.EPSS, 0.0001,
					"a re-read after TTL expiry picks up the new feed value")
				require.False(t, d.Intel.Stale)
			}
		}
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
