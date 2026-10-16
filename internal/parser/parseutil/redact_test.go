package parseutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

func TestRedactKeysMatchesWithoutRegardToCaseAtAnyDepth(t *testing.T) {
	doc := map[string]any{
		"Secret": "a",
		"sEcReT": "b",
		"keep":   "c",
		"inner":  map[string]any{"SECRET": "d", "list": []any{map[string]any{"secret": "e"}, "plain"}},
	}
	parseutil.RedactKeys(doc, "[X]", "secret")
	assert.Equal(t, map[string]any{
		"Secret": "[X]",
		"sEcReT": "[X]",
		"keep":   "c",
		"inner":  map[string]any{"SECRET": "[X]", "list": []any{map[string]any{"secret": "[X]"}, "plain"}},
	}, doc)
}

func TestRedactKeysLeavesEmptyValuesAlone(t *testing.T) {
	doc := map[string]any{"secret": "", "Match": nil, "match": []any{}, "SECRET": map[string]any{}, "secret2": "x"}
	parseutil.RedactKeys(doc, "[X]", "secret", "match")
	assert.Equal(t, map[string]any{"secret": "", "Match": nil, "match": []any{}, "SECRET": map[string]any{}, "secret2": "x"}, doc)
}

func TestRedactKeysRedactsNonStringContent(t *testing.T) {
	doc := map[string]any{"secret": []any{"a"}, "match": 12345.0, "request": map[string]any{"body": "b"}}
	parseutil.RedactKeys(doc, "[X]", "secret", "match", "request")
	assert.Equal(t, map[string]any{"secret": "[X]", "match": "[X]", "request": "[X]"}, doc)
}
