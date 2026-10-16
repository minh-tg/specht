package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

func TestMaxFindingsDefaultsWhenTheContextCarriesNone(t *testing.T) {
	assert.Equal(t, scanner.DefaultMaxFindings, scanner.MaxFindings(context.Background()))
	assert.Equal(t, scanner.DefaultMaxFindings, scanner.MaxFindings(scanner.WithMaxFindings(context.Background(), 0)),
		"a zero or negative limit must never mean unlimited")
	assert.Equal(t, scanner.DefaultMaxFindings, scanner.MaxFindings(scanner.WithMaxFindings(context.Background(), -5)))
	assert.Equal(t, 42, scanner.MaxFindings(scanner.WithMaxFindings(context.Background(), 42)))
}

func TestTooManyFindingsNamesTheLimitAndStaysMatchable(t *testing.T) {
	err := fmt.Errorf("scanner trivy: parse output: %w", scanner.TooManyFindings(1234))
	require.ErrorIs(t, err, scanner.ErrTooManyFindings)
	var tooMany *scanner.TooManyFindingsError
	require.True(t, errors.As(err, &tooMany))
	assert.Equal(t, 1234, tooMany.Limit)
	assert.Contains(t, err.Error(), "1234")
}

func TestCheckDocumentCountsObjectsWithoutDecoding(t *testing.T) {
	// Limit 2 allows 2 * ObjectsPerFinding objects.
	ceiling := 2 * scanner.ObjectsPerFinding
	build := func(n int) []byte { return []byte("[" + strings.TrimSuffix(strings.Repeat("{},", n), ",") + "]") }

	require.NoError(t, scanner.CheckDocument(build(ceiling), 2))
	require.ErrorIs(t, scanner.CheckDocument(build(ceiling+1), 2), scanner.ErrTooManyFindings)
}

func TestCheckDocumentIgnoresBracesInsideStrings(t *testing.T) {
	doc := []byte(`{"a":"` + strings.Repeat(`{`, 1000) + `","b":"\"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{\\","c":{}}`)
	require.NoError(t, scanner.CheckDocument(doc, 1))
}

func TestCheckDocumentCountsJSONLinesAndMapValues(t *testing.T) {
	require.ErrorIs(t, scanner.CheckDocument([]byte(strings.Repeat("{}\n", 100)), 1), scanner.ErrTooManyFindings,
		"one object per line is the nuclei JSONL form")
	require.ErrorIs(t, scanner.CheckDocument([]byte(`{`+strings.TrimSuffix(strings.Repeat(`"k":{},`, 100), ",")+`}`), 1), scanner.ErrTooManyFindings,
		"objects held in a map decode into structs too")
}

func TestCheckDocumentLeavesBrokenInputToTheDecoder(t *testing.T) {
	for _, doc := range []string{"", "not json", `{"unterminated":"`, strings.Repeat("[", 50000), strings.Repeat("}", 100)} {
		assert.NoError(t, scanner.CheckDocument([]byte(doc), 1), "%.20q", doc)
	}
}
