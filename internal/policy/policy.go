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
	DefaultWatcherGate   = "immediate"
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
		if !ok {
			return nil, fmt.Errorf("unknown policy key %q", k)
		}
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("policy key %q must be a string", k)
		}
		s = strings.ToLower(strings.TrimSpace(s))
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

// Resolve merges template, overrides, and defaults with precedence:
// project overrides beat the template, the template beats built-ins.
// Every returned key carries its provenance.
func Resolve(templateName *string, templateVersion int, template, overrides map[string]string) Effective {
	eff := Effective{TemplateName: templateName, TemplateVersion: templateVersion}
	eff.SeverityFloor, eff.SeveritySource = resolveKey(template, overrides, KeySeverityFloor, DefaultSeverityFloor)
	eff.WatcherGate, eff.WatcherSource = resolveKey(template, overrides, KeyWatcherGate, DefaultWatcherGate)
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

// Keys returns the sorted definition keys, for stable error messages and
// documentation.
func Keys() []string {
	out := []string{KeySeverityFloor, KeyWatcherGate}
	sort.Strings(out)
	return out
}
