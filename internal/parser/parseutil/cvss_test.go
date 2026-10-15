package parseutil

import (
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCVSSRecordTakesVersionFromPrefix(t *testing.T) {
	tests := []struct {
		name        string
		vector      string
		wantVersion string
		wantVector  string
		wantOK      bool
	}{
		{"v3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", true},
		{"v3.0 is not relabelled 3.1", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", true},
		{"v4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", true},
		{"v2 with prefix", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "2.0", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", true},
		{"bare v2 gains the prefix", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "2.0", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", true},
		{"bare v2 in parentheses", "(AV:N/AC:L/Au:N/C:P/I:P/A:P)", "2.0", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", true},
		{"surrounding space", "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N ", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", true},
		{"empty", "", "", "", false},
		{"score only", "7.5", "", "", false},
		{"unknown version", "CVSS:9.9/AV:N", "", "", false},
		{"prefix without metrics", "CVSS:3.1/", "", "", false},
		{"prefix without slash", "CVSS:3.1", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, ok := NewCVSSRecord(tt.vector, 7.5, "nvd")
			require.Equal(t, tt.wantOK, ok)
			if !ok {
				return
			}
			assert.Equal(t, tt.wantVersion, rec.Version)
			assert.Equal(t, tt.wantVector, rec.Vector)
			assert.InDelta(t, 7.5, rec.Score, 0)
			assert.Equal(t, "nvd", rec.Source)
		})
	}
}

func TestAddCVSSDedupesAndCaps(t *testing.T) {
	var list []domain.CVSSRecord
	rec := domain.CVSSRecord{Version: "3.1", Vector: "CVSS:3.1/AV:N", Score: 5, Source: "nvd"}
	list = AddCVSS(list, rec)
	list = AddCVSS(list, rec)
	require.Len(t, list, 1, "an identical version, vector and source is kept once")

	other := rec
	other.Source = "redhat"
	list = AddCVSS(list, other)
	require.Len(t, list, 2, "the same vector from another source is a separate datum")

	for i := range domain.MaxCVSSRecords + 3 {
		list = AddCVSS(list, domain.CVSSRecord{Version: "3.1", Vector: "CVSS:3.1/AV:N/" + strings.Repeat("x", i)})
	}
	assert.Len(t, list, domain.MaxCVSSRecords)
	assert.Equal(t, "nvd", list[0].Source, "the first records win when the cap is hit")
}

func TestHardenFindingBoundsCVSSAll(t *testing.T) {
	long := "CVSS:3.1/AV:N/" + strings.Repeat("A", 400)
	var recs []domain.CVSSRecord
	for range domain.MaxCVSSRecords + 4 {
		recs = append(recs, domain.CVSSRecord{Version: "3.1", Vector: long, Score: 99, Source: "n\x00vd"})
	}
	got := HardenFinding(domain.NormalizedFinding{CVSSAll: recs})
	require.Len(t, got.CVSSAll, domain.MaxCVSSRecords)
	for _, r := range got.CVSSAll {
		assert.LessOrEqual(t, len(r.Vector), domain.MaxCVSSVectorLength)
		assert.LessOrEqual(t, r.Score, 10.0)
		assert.NotContains(t, r.Source, "\x00")
	}
}
