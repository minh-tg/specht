package parseutil

import (
	"context"

	"github.com/minh-tg/specht/internal/scanner"
)

// Budget counts the findings and packages a parser has produced so far and
// stops it once the instance limit is passed. A parser makes one at the top of
// Parse and calls Add each time it appends, so a hostile document aborts at the
// limit instead of being converted in full first.
type Budget struct {
	limit int
	used  int
}

// NewBudget makes a budget from the limit in ctx. It first refuses a document
// with far more objects than the limit allows, before the parser decodes it:
// decoding turns every object into a struct, so that is where the memory goes.
// arrayKeys name the arrays that carry the parser's findings and packages (see
// scanner.CheckDocument), so a document whose finding arrays are too long is
// refused without decoding them.
func NewBudget(ctx context.Context, data []byte, arrayKeys ...string) (*Budget, error) {
	limit := scanner.MaxFindings(ctx)
	if err := scanner.CheckDocument(data, limit, arrayKeys...); err != nil {
		return nil, err
	}
	return &Budget{limit: limit}, nil
}

// Add records n more findings or packages. It returns a
// scanner.TooManyFindingsError once the total passes the limit.
func (b *Budget) Add(n int) error {
	b.used += n
	if b.used > b.limit {
		return scanner.TooManyFindings(b.limit)
	}
	return nil
}
