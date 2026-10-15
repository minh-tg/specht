package parseutil

import (
	"strings"

	"github.com/minh-tg/specht/internal/domain"
)

// cvssVersions lists the CVSS versions a vector prefix may name.
var cvssVersions = map[string]struct{}{"2.0": {}, "3.0": {}, "3.1": {}, "4.0": {}}

// NewCVSSRecord builds a CVSSRecord from a raw vector. The version comes from
// the vector prefix, never from a label the scanner printed next to it, so a
// CVSS:3.0/ vector is never reported as 3.1. A bare v2 vector (AV:N/..., with
// or without parentheses) gains the CVSS:2.0/ prefix. It reports false for an
// empty vector, a bare score, an unknown version or a prefix with no metrics.
func NewCVSSRecord(vector string, score float64, source string) (domain.CVSSRecord, bool) {
	v := strings.TrimSpace(vector)
	if strings.HasPrefix(v, "(") && strings.HasSuffix(v, ")") {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if strings.HasPrefix(v, "AV:") {
		v = "CVSS:2.0/" + v
	}
	rest, ok := strings.CutPrefix(v, "CVSS:")
	if !ok {
		return domain.CVSSRecord{}, false
	}
	version, metrics, ok := strings.Cut(rest, "/")
	if _, known := cvssVersions[version]; !ok || !known || metrics == "" {
		return domain.CVSSRecord{}, false
	}
	return domain.CVSSRecord{Version: version, Vector: v, Score: score, Source: source}, true
}

// AddCVSS appends rec unless the list already holds the same version, vector
// and source, and never grows the list past domain.MaxCVSSRecords. Parsers add
// records in preference order, so the cap drops the least preferred ones.
func AddCVSS(list []domain.CVSSRecord, rec domain.CVSSRecord) []domain.CVSSRecord {
	if len(list) >= domain.MaxCVSSRecords {
		return list
	}
	for _, have := range list {
		if have.Version == rec.Version && have.Vector == rec.Vector && have.Source == rec.Source {
			return list
		}
	}
	return append(list, rec)
}

// hardenCVSSAll sanitizes and bounds the CVSS record list of a finding.
func hardenCVSSAll(in []domain.CVSSRecord) []domain.CVSSRecord {
	if len(in) == 0 {
		return nil
	}
	n := min(len(in), domain.MaxCVSSRecords)
	out := make([]domain.CVSSRecord, n)
	for i := range n {
		out[i] = domain.CVSSRecord{
			Version: SanitizeText(in[i].Version, 32),
			Vector:  SanitizeText(in[i].Vector, domain.MaxCVSSVectorLength),
			Score:   SafeScore(in[i].Score),
			Source:  SanitizeText(in[i].Source, 64),
		}
	}
	return out
}
