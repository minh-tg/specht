package grype

import (
	"bytes"
	"encoding/json"
)

// grypeConfig is the part of descriptor.configuration that decides whether
// Grype could drop a match before writing the report.
type grypeConfig struct {
	OnlyFixed     *bool             `json:"only-fixed"`
	OnlyNotFixed  *bool             `json:"only-notfixed"`
	IgnoreWontFix json.RawMessage   `json:"ignore-wontfix"`
	Ignore        []grypeIgnoreRule `json:"ignore"`
	Exclude       json.RawMessage   `json:"exclude"`
	VexDocuments  json.RawMessage   `json:"vex-documents"`
	VexAdd        json.RawMessage   `json:"vex-add"`
}

type grypeIgnoreRule struct {
	Vulnerability string `json:"vulnerability"`
	Namespace     string `json:"namespace"`
	FixState      string `json:"fix-state"`
	VexStatus     string `json:"vex-status"`
	MatchType     string `json:"match-type"`
	Package       struct {
		Name         string `json:"name"`
		Version      string `json:"version"`
		Language     string `json:"language"`
		Type         string `json:"type"`
		Location     string `json:"location"`
		UpstreamName string `json:"upstream-name"`
	} `json:"package"`
}

// defaultIgnoreRules are the rules Grype ships in its own configuration. Each
// drops only indirect matches against a kernel upstream through its header or
// build packages, which a project does not fix by upgrading them, so they do
// not count as hiding a vulnerability.
var defaultIgnoreRules = []struct{ name, pkgType, upstream string }{
	{"kernel-headers", "rpm", "kernel"},
	{"linux(-.*)?-headers-.*", "deb", "linux.*"},
	{"linux-libc-dev", "deb", "linux"},
	{"linux-kbuild-.*", "deb", "linux.*"},
}

func (r grypeIgnoreRule) isDefault() bool {
	if r.Vulnerability != "" || r.Namespace != "" || r.FixState != "" || r.VexStatus != "" ||
		r.Package.Version != "" || r.Package.Language != "" || r.Package.Location != "" ||
		r.MatchType != "exact-indirect-match" {
		return false
	}
	for _, d := range defaultIgnoreRules {
		if r.Package.Name == d.name && r.Package.Type == d.pkgType && r.Package.UpstreamName == d.upstream {
			return true
		}
	}
	return false
}

// unfiltered reports whether Grype's recorded configuration shows that no
// filter hid a match: not only-fixed, not only-notfixed, no ignore-wontfix, no
// exclude paths, no VEX documents, and no ignore rule beyond Grype's own
// defaults. A report with no configuration, or one that cannot be read,
// proves nothing, so a missing key is not taken as the default.
func unfiltered(raw json.RawMessage) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	var cfg grypeConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false
	}
	if cfg.OnlyFixed == nil || *cfg.OnlyFixed || cfg.OnlyNotFixed == nil || *cfg.OnlyNotFixed {
		return false
	}
	for _, field := range []json.RawMessage{cfg.IgnoreWontFix, cfg.Exclude, cfg.VexDocuments, cfg.VexAdd} {
		if !emptyValue(field) {
			return false
		}
	}
	for _, rule := range cfg.Ignore {
		if !rule.isDefault() {
			return false
		}
	}
	return true
}

// emptyValue is true for an absent key, null, an empty string and an empty
// list or object.
func emptyValue(raw json.RawMessage) bool {
	switch string(bytes.TrimSpace(raw)) {
	case "", "null", `""`, "[]", "{}":
		return true
	}
	return false
}
