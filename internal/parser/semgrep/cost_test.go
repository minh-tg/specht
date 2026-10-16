package semgrep_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/parseutil"
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

// The fingerprint is assigned after the finding is hardened, so it has to be
// bounded where it is built. A 1 MiB check id used to exceed the PostgreSQL
// btree limit and fail the whole report.
func TestFingerprintIsBoundedAndHasNoNUL(t *testing.T) {
	big := strings.Repeat("r", 1<<20)
	docs := map[string]string{
		"native": `{"results":[{"check_id":"` + big + `\u0000x","path":"a.go","start":{"line":1,"col":1},"extra":{"message":"m","severity":"ERROR"}}],"errors":[],"paths":{}}`,
		"sarif":  `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[]}},"results":[{"ruleId":"` + big + `\u0000x","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			rep, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
			require.NoError(t, err)
			require.Len(t, rep.Findings, 1)
			fp := rep.Findings[0].Fingerprint
			assert.LessOrEqual(t, len(fp), parseutil.MaxFingerprintLength)
			assert.NotContains(t, fp, "\x00")
			assert.True(t, strings.HasPrefix(fp, "sast:"), "the identity keeps its readable prefix")
		})
	}
}

func TestOverlongFingerprintsThatShareAPrefixStayDistinct(t *testing.T) {
	prefix := strings.Repeat("r", 4000)
	doc := `{"results":[
		{"check_id":"` + prefix + `A","path":"a.go","start":{"line":1,"col":1},"extra":{"message":"m"}},
		{"check_id":"` + prefix + `B","path":"a.go","start":{"line":2,"col":1},"extra":{"message":"m"}}],"errors":[],"paths":{}}`
	rep, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	require.Len(t, rep.Findings, 2)
	assert.NotEqual(t, rep.Findings[0].Fingerprint, rep.Findings[1].Fingerprint)
}

func TestTheIdentityOfANormalFindingIsUnchanged(t *testing.T) {
	doc := `{"results":[{"check_id":"rules.sql-injection","path":"src/a.go","start":{"line":7,"col":3},"extra":{"message":"tainted query","severity":"ERROR"}}],"errors":[],"paths":{}}`
	rep, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.Regexp(t, `^sast:rules\.sql-injection:src/a\.go:t[0-9a-f]{12}$`, rep.Findings[0].Fingerprint)
}
