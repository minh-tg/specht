package cvedetail

import (
	"strings"

	"github.com/minh-tg/specht/internal/cvss"
)

// Metric is one metric of a CVSS vector in the order the vector lists it. The
// server sends keys and values as the vector spells them; the UI owns the
// plain-language labels.
type Metric struct {
	Group string `json:"group"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Metric groups.
const (
	GroupBase          = "base"
	GroupTemporal      = "temporal"
	GroupThreat        = "threat"
	GroupEnvironmental = "environmental"
	GroupSupplemental  = "supplemental"
)

// NormalizeVector trims a vector and gives a bare CVSS v2 vector, as
// scanners print it ("AV:N/AC:L/..." or "(AV:N/...)"), the "CVSS:2.0/" prefix
// that internal/cvss expects. Other vectors come back trimmed.
func NormalizeVector(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "(") && strings.HasSuffix(v, ")") {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if strings.HasPrefix(v, "AV:") {
		return "CVSS:2.0/" + v
	}
	return v
}

// VectorVersion returns the CVSS version a normalized vector declares, or ""
// when the prefix is unknown. The version always comes from the vector, never
// from a separate label a scanner may have set wrong.
func VectorVersion(v string) string {
	for _, version := range []string{"4.0", "3.1", "3.0", "2.0"} {
		if strings.HasPrefix(v, "CVSS:"+version+"/") {
			return version
		}
	}
	return ""
}

// ScoreVector validates a normalized vector and returns its base score as
// internal/cvss computes it.
func ScoreVector(v string) (float64, bool) {
	if len(v) > maxVectorLen {
		return 0, false
	}
	score, err := cvss.Calculate(v)
	if err != nil {
		return 0, false
	}
	return score, true
}

// Metrics splits a normalized vector into its metrics, in vector order, each
// tagged with its group for the vector's version. It does not validate; call
// ScoreVector first.
func Metrics(v string) []Metric {
	version := VectorVersion(v)
	if version == "" {
		return nil
	}
	body := strings.TrimPrefix(v, "CVSS:"+version+"/")
	parts := strings.Split(body, "/")
	out := make([]Metric, 0, len(parts))
	for _, part := range parts {
		key, value, ok := strings.Cut(part, ":")
		if !ok || key == "" {
			continue
		}
		out = append(out, Metric{Group: metricGroup(version, key), Key: key, Value: value})
	}
	return out
}

var (
	v2Temporal = set("E", "RL", "RC")
	v2Env      = set("CDP", "TD", "CR", "IR", "AR")
	v3Temporal = set("E", "RL", "RC")
	v3Env      = set("CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")
	v4Threat   = set("E")
	v4Env      = set("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")
	v4Supp     = set("S", "AU", "R", "V", "RE", "U")
)

func metricGroup(version, key string) string {
	switch version {
	case "2.0":
		return pick(key, v2Temporal, GroupTemporal, v2Env, GroupEnvironmental, nil, "")
	case "3.0", "3.1":
		return pick(key, v3Temporal, GroupTemporal, v3Env, GroupEnvironmental, nil, "")
	default:
		return pick(key, v4Threat, GroupThreat, v4Env, GroupEnvironmental, v4Supp, GroupSupplemental)
	}
}

func pick(key string, a map[string]bool, ga string, b map[string]bool, gb string, c map[string]bool, gc string) string {
	switch {
	case a[key]:
		return ga
	case b[key]:
		return gb
	case c[key]:
		return gc
	default:
		return GroupBase
	}
}

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// SeverityBand names the qualitative band of a base score. CVSS v3 and v4
// use none, low, medium, high and critical; NVD's v2 bands stop at high.
func SeverityBand(version string, score float64) string {
	if version == "2.0" {
		switch {
		case score >= 7:
			return "high"
		case score >= 4:
			return "medium"
		default:
			return "low"
		}
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}
