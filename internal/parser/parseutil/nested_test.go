package parseutil_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
)

func serializedLen(t *testing.T, v any) int {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return len(b)
}

func TestExtensionsUnderTheCapAreUntouched(t *testing.T) {
	in := map[string]any{
		"cwe_ids": []string{"CWE-79", "CWE-89"},
		"target":  "app/main.go",
		"nested":  map[string]any{"a": 1.5, "b": []any{"x", true}},
	}
	got := parseutil.HardenFinding(domain.NormalizedFinding{Extensions: in}).Extensions
	assert.Equal(t, in, got)
	assert.NotContains(t, got, "_truncated")
}

func TestOversizedExtensionsDropTheLargestKeysFirst(t *testing.T) {
	big := strings.Repeat("z", 20<<10)
	medium := strings.Repeat("m", 6<<10)
	in := map[string]any{"small": "keep me", "medium": medium, "big": big, "tiny": 1}

	got := parseutil.HardenFinding(domain.NormalizedFinding{Extensions: in}).Extensions

	assert.LessOrEqual(t, serializedLen(t, got), parseutil.MaxExtensionsBytes)
	assert.Equal(t, true, got["_truncated"])
	assert.NotContains(t, got, "big", "the largest key goes first")
	assert.Equal(t, medium, got["medium"], "a key that fits is kept whole, never cut")
	assert.Equal(t, "keep me", got["small"])
	assert.EqualValues(t, 1, got["tiny"])
}

func TestExtensionsKeepDroppingUntilTheyFit(t *testing.T) {
	in := map[string]any{}
	for _, k := range []string{"a", "b", "c", "d"} {
		in[k] = strings.Repeat(k, 9<<10)
	}
	got := parseutil.HardenFinding(domain.NormalizedFinding{Extensions: in}).Extensions
	assert.LessOrEqual(t, serializedLen(t, got), parseutil.MaxExtensionsBytes)
	assert.Equal(t, true, got["_truncated"])
	assert.Len(t, got, 2, "one 9 KiB key and the marker")
}

func TestExtensionsDropAValueThatCannotBeSerialized(t *testing.T) {
	in := map[string]any{"ok": "yes", "bad": make(chan int)}
	got := parseutil.HardenFinding(domain.NormalizedFinding{Extensions: in}).Extensions
	assert.Equal(t, "yes", got["ok"])
	assert.NotContains(t, got, "bad")
	assert.Equal(t, true, got["_truncated"])
}

func TestExtensionsLoseNULBytesInKeysAndValuesAtAnyDepth(t *testing.T) {
	in := map[string]any{
		"k\x00ey": "v\x00alue",
		"list":    []any{"a\x00b", map[string]any{"in\x00ner": "x\x00"}},
		"strs":    []string{"p\x00q"},
	}
	got := parseutil.HardenFinding(domain.NormalizedFinding{Extensions: in}).Extensions
	b, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(b), `\u0000`, "PostgreSQL jsonb refuses it")
	assert.Equal(t, "value", got["key"])
}

func TestHardenReportBoundsTargetAndArtifact(t *testing.T) {
	long := strings.Repeat("é", 2000) // 4000 bytes
	nr := &domain.NormalizedReport{
		Target:   &domain.TargetInfo{Identifier: long + "\x00", Kind: long},
		Artifact: &domain.ArtifactInfo{Identifier: long, Kind: long, Digest: long, Metadata: map[string]any{"big": strings.Repeat("x", 1<<20)}},
		ScanScope: &domain.ScanScope{Ext: map[string]string{
			"osv_source_path":        long,
			strings.Repeat("k", 500): "v\x00",
		}},
	}
	got := parseutil.HardenReport(nr)

	assert.LessOrEqual(t, len(got.Target.Identifier), parseutil.MaxTargetIdentifierLength)
	assert.LessOrEqual(t, len(got.Target.Kind), parseutil.MaxTargetKindLength)
	assert.True(t, utf8.ValidString(got.Target.Identifier), "truncation never cuts a rune")
	assert.True(t, utf8.ValidString(got.Target.Kind))
	assert.NotContains(t, got.Target.Identifier, "\x00")
	assert.LessOrEqual(t, len(got.Artifact.Identifier), parseutil.MaxTargetIdentifierLength)
	assert.LessOrEqual(t, len(got.Artifact.Kind), parseutil.MaxTargetKindLength)
	assert.LessOrEqual(t, len(got.Artifact.Digest), parseutil.MaxDigestLength)
	assert.LessOrEqual(t, serializedLen(t, got.Artifact.Metadata), parseutil.MaxExtensionsBytes)
	assert.Equal(t, true, got.Artifact.Metadata["_truncated"])
	for k, v := range got.ScanScope.Ext {
		assert.LessOrEqual(t, len(k), parseutil.MaxScopeKeyLength)
		assert.LessOrEqual(t, len(v), parseutil.MaxScopeValueLength)
		assert.NotContains(t, v, "\x00")
	}
}

func TestHardenReportLeavesNormalValuesAndNilPartsAlone(t *testing.T) {
	assert.Nil(t, parseutil.HardenReport(nil))
	nr := &domain.NormalizedReport{
		Target:    &domain.TargetInfo{Identifier: "alpine:3.20", Kind: "container_image"},
		ScanScope: &domain.ScanScope{Ext: map[string]string{"osv_source_path": "go.mod"}},
	}
	got := parseutil.HardenReport(nr)
	assert.Equal(t, "alpine:3.20", got.Target.Identifier)
	assert.Equal(t, "container_image", got.Target.Kind)
	assert.Equal(t, map[string]string{"osv_source_path": "go.mod"}, got.ScanScope.Ext)
	assert.Nil(t, got.Artifact)
}

func TestHardenedForwardsTheError(t *testing.T) {
	nr, err := parseutil.Hardened(nil, assert.AnError)
	assert.Nil(t, nr)
	assert.ErrorIs(t, err, assert.AnError)
}
