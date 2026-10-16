package semgrep_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/semgrep"
)

// sarifWithRules builds a SARIF log of n rules and n results. Each result names
// a rule that is last in the list, or one that is missing, which is the worst
// case for a linear scan of the rules.
func sarifWithRules(n int, ruleFor func(i int) string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"r%d","shortDescription":{"text":"rule %d"}}`, i, i)
	}
	b.WriteString(`]}},"results":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ruleId":%q,"message":{"text":"m%d"}}`, ruleFor(i), i)
	}
	b.WriteString(`]}]}`)
	return b.Bytes()
}

// The rule for a result used to be found by scanning the whole rule list, so a
// 2.4 MB report took 3.75 s and each doubling cost four times as much.
func TestSARIFRuleLookupDoesNotScaleWithRulesTimesResults(t *testing.T) {
	const n = 40000
	cases := map[string]func(int) string{
		"rule is last":    func(int) string { return fmt.Sprintf("r%d", n-1) },
		"rule is missing": func(int) string { return "missing" },
	}
	for name, ruleFor := range cases {
		t.Run(name, func(t *testing.T) {
			doc := sarifWithRules(n, ruleFor)
			start := time.Now()
			rep, err := semgrep.NewScanner().Parse(context.Background(), doc)
			elapsed := time.Since(start)
			require.NoError(t, err)
			require.Len(t, rep.Findings, n)
			assert.Less(t, elapsed, 2*time.Second, "%d rules x %d results took %s", n, n, elapsed)
		})
	}
}

// Indexing the rules must keep the first rule when an id repeats, as the
// linear scan did.
func TestSARIFRuleLookupKeepsTheFirstRuleOfARepeatedID(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[
		{"id":"dup","shortDescription":{"text":"first"}},
		{"id":"dup","shortDescription":{"text":"second"}}]}},
		"results":[{"ruleId":"dup","message":{"text":""}}]}]}`
	rep, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.Equal(t, "dup", rep.Findings[0].Title, "the title falls back to the rule id of the first match")
	assert.Equal(t, "first", rep.Findings[0].Description)
}
