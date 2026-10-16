package parseutil

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
)

const (
	// MaxTargetIdentifierLength bounds a target or artifact identifier. The
	// identifier is the target's unique name, so it has to stay inside the btree
	// index row limit.
	MaxTargetIdentifierLength = 1024

	// MaxTargetKindLength bounds a target or artifact kind.
	MaxTargetKindLength = 64

	// MaxDigestLength bounds an artifact digest.
	MaxDigestLength = 256

	// MaxScopeKeyLength and MaxScopeValueLength bound the entries of a scan
	// scope's Ext map.
	MaxScopeKeyLength   = 64
	MaxScopeValueLength = 1024

	// MaxExtensionsBytes caps the serialized size of one finding's Extensions
	// (and of an artifact's Metadata). They are stored as one JSON column per
	// occurrence, so an unbounded value is copied into the database as is.
	MaxExtensionsBytes = 16 << 10

	// extensionKeyLength bounds the name of one Extensions key.
	extensionKeyLength = 256

	// truncatedKey marks an Extensions map that lost keys to the size cap.
	truncatedKey = "_truncated"
)

// HardenReport bounds the report-level fields a scanner fills in from the
// document: the target and artifact names, the artifact metadata and the scan
// scope extension values. Findings and packages are hardened where they are
// built. It returns nr so a parser can end with it.
func HardenReport(nr *domain.NormalizedReport) *domain.NormalizedReport {
	if nr == nil {
		return nil
	}
	if t := nr.Target; t != nil {
		t.Identifier = SanitizeText(t.Identifier, MaxTargetIdentifierLength)
		t.Kind = SanitizeText(t.Kind, MaxTargetKindLength)
	}
	if a := nr.Artifact; a != nil {
		a.Identifier = SanitizeText(a.Identifier, MaxTargetIdentifierLength)
		a.Kind = SanitizeText(a.Kind, MaxTargetKindLength)
		a.Digest = SanitizeText(a.Digest, MaxDigestLength)
		a.Metadata = HardenExtensions(a.Metadata)
	}
	if s := nr.ScanScope; s != nil {
		s.Target = SanitizeText(s.Target, MaxTargetIdentifierLength)
		s.TargetKind = SanitizeText(s.TargetKind, MaxTargetKindLength)
		s.Artifact = SanitizeText(s.Artifact, MaxTargetIdentifierLength)
		s.ArtifactVer = SanitizeText(s.ArtifactVer, 256)
		s.ArtifactTyp = SanitizeText(s.ArtifactTyp, MaxTargetKindLength)
		if len(s.Ext) > 0 {
			ext := make(map[string]string, len(s.Ext))
			for k, v := range s.Ext {
				ext[SanitizeText(k, MaxScopeKeyLength)] = SanitizeText(v, MaxScopeValueLength)
			}
			s.Ext = ext
		}
	}
	return nr
}

// Hardened applies HardenReport to the result of a conversion, passing an
// error through, so a parser can write return parseutil.Hardened(convert(...)).
func Hardened(nr *domain.NormalizedReport, err error) (*domain.NormalizedReport, error) {
	if err != nil {
		return nil, err
	}
	return HardenReport(nr), nil
}

// HardenExtensions removes NUL bytes from the keys and strings of a producer
// payload and keeps its serialized size within MaxExtensionsBytes. Over the cap
// it drops whole keys, largest first, and adds "_truncated": true. A cut JSON
// value would be worse than a missing one. A value that cannot be serialized
// is dropped the same way.
func HardenExtensions(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	type entry struct {
		key   string
		value any
		size  int
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	changed, dropped := false, false
	entries := make([]entry, 0, len(m))
	total := len("{}")
	for _, k := range keys {
		key := SanitizeText(k, extensionKeyLength)
		value, valueChanged := cleanValue(m[k])
		changed = changed || valueChanged || key != k
		encoded, err := json.Marshal(value)
		if err != nil {
			dropped = true
			continue
		}
		size := len(key) + len(encoded) + len(`"":,`)
		entries = append(entries, entry{key, value, size})
		total += size
	}
	if !changed && !dropped && total <= MaxExtensionsBytes {
		return m
	}

	if total > MaxExtensionsBytes {
		dropped = true
		slices.SortStableFunc(entries, func(a, b entry) int { return b.size - a.size })
		marker := len(`"":true,`) + len(truncatedKey)
		for len(entries) > 0 && total+marker > MaxExtensionsBytes {
			total -= entries[0].size
			entries = entries[1:]
		}
	}
	out := make(map[string]any, len(entries)+1)
	for _, e := range entries {
		out[e.key] = e.value
	}
	if dropped {
		out[truncatedKey] = true
	}
	return out
}

// cleanValue strips NUL bytes from every string inside v. It reports whether it
// changed anything, and returns v itself when it did not.
func cleanValue(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if strings.IndexByte(x, 0) < 0 {
			return x, false
		}
		return strings.ReplaceAll(x, "\x00", ""), true
	case []string:
		var out []string
		for i, s := range x {
			if strings.IndexByte(s, 0) < 0 {
				continue
			}
			if out == nil {
				out = slices.Clone(x)
			}
			out[i] = strings.ReplaceAll(s, "\x00", "")
		}
		if out == nil {
			return x, false
		}
		return out, true
	case []any:
		var out []any
		for i, item := range x {
			cleaned, changed := cleanValue(item)
			if !changed {
				continue
			}
			if out == nil {
				out = slices.Clone(x)
			}
			out[i] = cleaned
		}
		if out == nil {
			return x, false
		}
		return out, true
	case map[string]any:
		changed := false
		out := make(map[string]any, len(x))
		for k, item := range x {
			cleaned, itemChanged := cleanValue(item)
			key := strings.ReplaceAll(k, "\x00", "")
			changed = changed || itemChanged || key != k
			out[key] = cleaned
		}
		if !changed {
			return x, false
		}
		return out, true
	}
	return v, false
}
