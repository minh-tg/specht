package parseutil_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestBudgetAllowsExactlyTheLimit(t *testing.T) {
	ctx := scanner.WithMaxFindings(context.Background(), 3)
	b, err := parseutil.NewBudget(ctx, []byte(`[{},{},{}]`))
	require.NoError(t, err)
	for range 3 {
		require.NoError(t, b.Add(1))
	}
	err = b.Add(1)
	require.ErrorIs(t, err, scanner.ErrTooManyFindings)
	var tooMany *scanner.TooManyFindingsError
	require.ErrorAs(t, err, &tooMany)
	assert.Equal(t, 3, tooMany.Limit)
}

func TestBudgetCountsBatches(t *testing.T) {
	ctx := scanner.WithMaxFindings(context.Background(), 5)
	b, err := parseutil.NewBudget(ctx, []byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, b.Add(5))
	require.ErrorIs(t, b.Add(1), scanner.ErrTooManyFindings)
}

func TestNewBudgetRefusesAnOversizedDocumentBeforeAnyDecoding(t *testing.T) {
	ctx := scanner.WithMaxFindings(context.Background(), 1)
	doc := make([]byte, 0, 3*scanner.ObjectsPerFinding+2)
	doc = append(doc, '[')
	for range 2 * scanner.ObjectsPerFinding {
		doc = append(doc, "{},"...)
	}
	doc = append(doc, "{}]"...)
	_, err := parseutil.NewBudget(ctx, doc)
	require.ErrorIs(t, err, scanner.ErrTooManyFindings)
}

func TestNewBudgetUsesTheDefaultWithoutALimitInTheContext(t *testing.T) {
	b, err := parseutil.NewBudget(context.Background(), nil)
	require.NoError(t, err)
	require.NoError(t, b.Add(scanner.DefaultMaxFindings))
	require.ErrorIs(t, b.Add(1), scanner.ErrTooManyFindings)
}
