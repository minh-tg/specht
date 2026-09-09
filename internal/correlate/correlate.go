// Package correlate groups equivalent findings observed by different
// scanners without merging rows: finding identity (fingerprints, states,
// gate effects) is untouched. Correlation is a read-only view used for
// triage and display.
//
// Rules, per //   - A group key always combines the vulnerability/rule identity with the
//
//	  affected subject (package, file, target, resource). A shared
//	  vulnerability identifier alone never groups two findings.
//	- SCA findings converge across tools through alias expansion: two
//	  observations share a key when their identifier sets intersect on a
//	  canonical id and the ecosystem/package match.
//	- SAST keys exclude line numbers (they shift between scans); IaC keys
//	  use rule + resource; secret keys use rule + target.
//	- Near misses (same rule, different subject) are reported as Uncertain
//	  candidates for human review, never auto-grouped.
//	- Groups and members are sorted; output is deterministic for the same
//	  input regardless of order.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/xMinhx/specht/internal/domain"
)

// Confidence grades a correlation.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
)

// Group is one set of equivalent observations.
type Group struct {
	// ID is the deterministic group identity: corr:<sha256(key)[:16]>.
	ID string `json:"id"`
	// Key is the human-readable correlation key.
	Key        string     `json:"key"`
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
	// Members are indices into the input slice, sorted.
	Members []int `json:"members"`
}

// Candidate is a near miss: shared signal, different subject. For review
// only; never an automatic group.
type Candidate struct {
	Reason  string `json:"reason"`
	Members []int  `json:"members"`
}

// Result is the correlation outcome for one input set.
type Result struct {
	Groups    []Group     `json:"groups"`
	Uncertain []Candidate `json:"uncertain,omitempty"`
}

// Correlate groups equivalent findings in observations.
func Correlate(observations []domain.NormalizedFinding) Result {
	var res Result
	byKey := map[string][]int{}
	meta := map[string]struct {
		confidence Confidence
		reason     string
	}{}
	near := map[string][]int{}

	keys := make([]groupKey, len(observations))
	for i, f := range observations {
		keys[i] = keyFor(f)
	}
	for i, k := range keys {
		if k.key == "" {
			continue
		}
		byKey[k.key] = append(byKey[k.key], i)
		if _, ok := meta[k.key]; !ok {
			meta[k.key] = struct {
				confidence Confidence
				reason     string
			}{k.confidence, k.reason}
		}
		if k.near != "" {
			near[k.near] = append(near[k.near], i)
		}
	}

	for key, members := range byKey {
		if len(members) < 2 {
			continue
		}
		sort.Ints(members)
		m := meta[key]
		sum := sha256.Sum256([]byte(key))
		res.Groups = append(res.Groups, Group{
			ID:  "corr:" + hex.EncodeToString(sum[:])[:16],
			Key: key, Confidence: m.confidence, Reason: m.reason,
			Members: members,
		})
	}
	sort.Slice(res.Groups, func(i, j int) bool { return res.Groups[i].Key < res.Groups[j].Key })

	grouped := map[int]bool{}
	for _, g := range res.Groups {
		for _, m := range g.Members {
			grouped[m] = true
		}
	}
	for key, members := range near {
		var free []int
		for _, m := range members {
			if !grouped[m] {
				free = append(free, m)
			}
		}
		if len(free) < 2 {
			continue
		}
		sort.Ints(free)
		res.Uncertain = append(res.Uncertain, Candidate{
			Reason:  "shared " + key + " across different subjects",
			Members: free,
		})
	}
	sort.Slice(res.Uncertain, func(i, j int) bool { return res.Uncertain[i].Reason < res.Uncertain[j].Reason })
	return res
}

type groupKey struct {
	key        string
	near       string
	confidence Confidence
	reason     string
}

func keyFor(f domain.NormalizedFinding) groupKey {
	dims := map[string]string{}
	for _, d := range f.Dimensions {
		if _, ok := dims[d.Key]; !ok {
			dims[d.Key] = d.Value
		}
	}
	switch f.FindingKind {
	case "sca":
		return scaKey(f, dims)
	case "sast":
		rule := dims[domain.DimRuleID]
		file := dims[domain.DimFile]
		if f.CodeLocation != nil && f.CodeLocation.File != "" {
			file = f.CodeLocation.File
		}
		if rule == "" || file == "" {
			return groupKey{}
		}
		return groupKey{
			key:        "sast:" + rule + ":" + file,
			near:       "rule " + rule,
			confidence: ConfidenceHigh,
			reason:     "same SAST rule on the same file (line shifts ignored)",
		}
	case "iac":
		rule := dims[domain.DimRuleID]
		resource := dims[domain.DimResource]
		if resource == "" {
			resource = f.Resource
		}
		if rule == "" || resource == "" {
			return groupKey{}
		}
		return groupKey{
			key:        "iac:" + rule + ":" + resource,
			near:       "rule " + rule,
			confidence: ConfidenceHigh,
			reason:     "same IaC rule on the same resource",
		}
	case "secret":
		rule := dims[domain.DimRuleID]
		if rule == "" || f.Location == "" {
			return groupKey{}
		}
		return groupKey{
			key:        "secret:" + rule + ":" + f.Location,
			near:       "rule " + rule,
			confidence: ConfidenceHigh,
			reason:     "same secret rule on the same target",
		}
	default:
		return groupKey{}
	}
}

func scaKey(f domain.NormalizedFinding, dims map[string]string) groupKey {
	vuln := dims[domain.DimVulnerabilityID]
	pkg := dims[domain.DimPackageName]
	eco := dims[domain.DimEcosystem]
	if vuln == "" || pkg == "" {
		return groupKey{}
	}
	ids := map[string]bool{vuln: true}
	for _, a := range f.Aliases {
		ids[a] = true
	}
	canonical := canonicalVulnID(ids)
	key := "sca:" + eco + ":" + pkg + ":" + canonical
	conf := ConfidenceHigh
	reason := "same vulnerability on the same package"
	if eco == "" {
		conf = ConfidenceMedium
		reason = "same vulnerability on the same package (ecosystem unknown)"
	}
	return groupKey{key: key, near: "vulnerability " + canonical, confidence: conf, reason: reason}
}

// canonicalVulnID picks the stable representative of an identifier set:
// the lexicographically smallest CVE id, else the smallest id overall.
func canonicalVulnID(ids map[string]bool) string {
	var cves []string
	var rest []string
	for id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		} else {
			rest = append(rest, id)
		}
	}
	sort.Strings(cves)
	sort.Strings(rest)
	if len(cves) > 0 {
		return cves[0]
	}
	if len(rest) > 0 {
		return rest[0]
	}
	return ""
}
