package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Definition keys a template or override may set.
const (
	// KeySeverityFloor floors gate-blocking severity:
	// critical|high|medium|low.
	KeySeverityFloor = "severity_floor"
	// KeyWatcherGate admits watcher findings:
	// immediate|off|require_triage.
	KeyWatcherGate = "watcher_gate"
	// KeyManualCloseScanners names the scanners whose clean scans do not close
	// findings, as a comma-separated list. Empty keeps none manual.
	KeyManualCloseScanners = "manual_close_scanners"
)

// Provenance names where an effective value came from.
const (
	SourceDefault  = "default"
	SourceTemplate = "template"
	SourceOverride = "override"
)

// Defaults are the built-in baseline when neither template nor override
// sets a key.
const (
	DefaultSeverityFloor = "high"
	// DefaultWatcherGate holds watcher findings out of the gate until someone
	// has triaged them. Before this was the policy default, the gate read a
	// separate project column with this same default, so the policy screen
	// and the gate disagreed.
	DefaultWatcherGate = "require_triage"
)

var validValues = map[string][]string{
	KeySeverityFloor: {"critical", "high", "medium", "low"},
	KeyWatcherGate:   {"immediate", "off", "require_triage"},
}

// Effective is one project's resolved policy with per-key provenance.
type Effective struct {
	TemplateName    *string `json:"template_name"`
	TemplateVersion int     `json:"template_version"`
	SeverityFloor   string  `json:"severity_floor"`
	SeveritySource  string  `json:"severity_source"`
	WatcherGate     string  `json:"watcher_gate"`
	WatcherSource   string  `json:"watcher_source"`
	// ManualCloseScanners lists the scanners whose clean scans leave findings
	// open, and ManualCloseSource where that list came from.
	ManualCloseScanners []string `json:"manual_close_scanners"`
	ManualCloseSource   string   `json:"manual_close_source"`
}

// ParseDefinition validates a template or override definition: known keys
// with known values only. Values normalize to lowercase; unknown keys or
// values are rejected, never ignored — a silently dropped policy key
// would weaken enforcement without anyone noticing.
func ParseDefinition(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	var loose map[string]any
	if err := json.Unmarshal(raw, &loose); err != nil {
		return nil, fmt.Errorf("invalid policy definition: %w", err)
	}
	out := make(map[string]string, len(loose))
	for k, v := range loose {
		allowed, ok := validValues[k]
		if !ok && k != KeyManualCloseScanners {
			return nil, fmt.Errorf("unknown policy key %q", k)
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("policy key %q must be a string", k)
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if k == KeyManualCloseScanners {
			names, err := parseScannerList(s)
			if err != nil {
				return nil, err
			}
			out[k] = strings.Join(names, ",")
			continue
		}
		valid := false
		for _, a := range allowed {
			if s == a {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("policy key %q has invalid value %q", k, s)
		}
		out[k] = s
	}
	return out, nil
}

// parseScannerList reads a comma-separated list of scanner names into a sorted
// list without duplicates. Whether each name exists is the caller's question:
// this package does not know the scanner registry.
func parseScannerList(raw string) ([]string, error) {
	seen := map[string]bool{}
	names := []string{}
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name == "" || seen[name] {
			continue
		}
		if strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return nil, fmt.Errorf("policy key %q has invalid scanner name %q", KeyManualCloseScanners, name)
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// ScannerList splits a stored manual_close_scanners value. The value was
// validated on the way in, and nothing that fails to parse keeps a scanner manual.
func ScannerList(value string) []string {
	names, err := parseScannerList(value)
	if err != nil {
		return []string{}
	}
	return names
}

// Resolve merges template, overrides, and defaults with precedence:
// project overrides beat the template, the template beats built-ins.
// Every returned key carries its provenance.
func Resolve(templateName *string, templateVersion int, template, overrides map[string]string) Effective {
	eff := Effective{TemplateName: templateName, TemplateVersion: templateVersion}
	eff.SeverityFloor, eff.SeveritySource = resolveKey(template, overrides, KeySeverityFloor, DefaultSeverityFloor)
	eff.WatcherGate, eff.WatcherSource = resolveKey(template, overrides, KeyWatcherGate, DefaultWatcherGate)
	var manual string
	manual, eff.ManualCloseSource = resolveKey(template, overrides, KeyManualCloseScanners, "")
	eff.ManualCloseScanners = ScannerList(manual)
	return eff
}

func resolveKey(template, overrides map[string]string, key, def string) (string, string) {
	if v, ok := overrides[key]; ok {
		return v, SourceOverride
	}
	if v, ok := template[key]; ok {
		return v, SourceTemplate
	}
	return def, SourceDefault
}

// SeverityRank maps a floor to the gate rank. Unknown floors default to
// high — fail-closed toward blocking, never toward passing.
func SeverityRank(floor string) int16 {
	switch strings.ToLower(strings.TrimSpace(floor)) {
	case "critical":
		return 4
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 3
	}
}

// LowestListedRank resolves a list of severity labels, as a gate request
// names them, to the LOWEST rank named, so every listed severity blocks.
// Labels are trimmed and lowercased; unknown labels are skipped. It returns 0
// when no label is known, and the caller picks its own default.
func LowestListedRank(labels []string) int16 {
	minRank := int16(0)
	for _, label := range labels {
		var rank int16
		switch strings.ToLower(strings.TrimSpace(label)) {
		case "critical":
			rank = 4
		case "high":
			rank = 3
		case "medium":
			rank = 2
		case "low":
			rank = 1
		default:
			continue
		}
		if minRank == 0 || rank < minRank {
			minRank = rank
		}
	}
	return minRank
}

// Keys returns the sorted definition keys, for stable error messages and
// documentation.
func Keys() []string {
	out := []string{KeyManualCloseScanners, KeySeverityFloor, KeyWatcherGate}
	sort.Strings(out)
	return out
}
