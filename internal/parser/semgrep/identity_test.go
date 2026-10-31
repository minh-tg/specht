package semgrep_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/semgrep"
)

// sighting is one Semgrep match, described once and written out in both output formats.
type sighting struct {
	rule, file, message string
	line, col           int
	matchID             string // Semgrep's own match-based id; "" is what a logged-out run writes
}

const loggedOut = "requires login"

func sarifDoc(t *testing.T, ss []sighting) string {
	t.Helper()
	var results, rules []map[string]any
	seen := map[string]bool{}
	for _, s := range ss {
		id := s.matchID
		if id == "" {
			id = loggedOut
		}
		results = append(results, map[string]any{
			"ruleId":  s.rule,
			"message": map[string]any{"text": s.message},
			"level":   "warning",
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": s.file},
				"region":           map[string]any{"startLine": s.line, "startColumn": s.col},
			}}},
			"fingerprints": map[string]any{"matchBasedId/v1": id},
		})
		if !seen[s.rule] {
			seen[s.rule] = true
			rules = append(rules, map[string]any{"id": s.rule, "fullDescription": map[string]any{"text": "rule"}})
		}
	}
	doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "Semgrep OSS", "rules": rules}},
		"results": results,
	}}}
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return string(out)
}

func nativeDoc(t *testing.T, ss []sighting) string {
	t.Helper()
	var results []map[string]any
	for _, s := range ss {
		id := s.matchID
		if id == "" {
			id = loggedOut
		}
		results = append(results, map[string]any{
			"check_id": s.rule, "path": s.file,
			"start": map[string]any{"line": s.line, "col": s.col},
			"end":   map[string]any{"line": s.line, "col": s.col + 5},
			"extra": map[string]any{"message": s.message, "severity": "WARNING", "fingerprint": id, "lines": loggedOut},
		})
	}
	out, err := json.Marshal(map[string]any{"version": "1.0", "results": results, "errors": []any{}, "paths": map[string]any{}})
	require.NoError(t, err)
	return string(out)
}

var formats = map[string]func(*testing.T, []sighting) string{"sarif": sarifDoc, "json": nativeDoc}

func identities(t *testing.T, doc string) []string {
	t.Helper()
	nr, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	out := make([]string, len(nr.Findings))
	for i, f := range nr.Findings {
		out[i] = f.Fingerprint
	}
	return out
}

func eachFormat(t *testing.T, fn func(t *testing.T, doc func([]sighting) string)) {
	for name, build := range formats {
		t.Run(name, func(t *testing.T) { fn(t, func(ss []sighting) string { return build(t, ss) }) })
	}
}

func shell(line int) sighting {
	return sighting{rule: "python.lang.shell-true", file: "app.py", message: "Found subprocess call with shell=True", line: line, col: 5}
}

func TestAFindingKeepsItsIdentityWhenItsLineMoves(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		before := identities(t, doc([]sighting{shell(7)}))
		after := identities(t, doc([]sighting{shell(52)}))
		assert.Equal(t, before, after, "code added above the finding does not make it a new one")
	})
}

func TestTwoIdenticalFindingsInOneFileStayTwo(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		two := identities(t, doc([]sighting{shell(7), shell(19)}))
		require.Len(t, two, 2)
		assert.NotEqual(t, two[0], two[1], "the same mistake twice in a file is two findings")

		shifted := identities(t, doc([]sighting{shell(27), shell(39)}))
		assert.Equal(t, two, shifted, "and both survive an edit above them")
	})
}

func TestFixingTheLaterOfTwoIdenticalFindingsLeavesTheFirstAlone(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		two := identities(t, doc([]sighting{shell(7), shell(19)}))
		one := identities(t, doc([]sighting{shell(7)}))
		require.Len(t, one, 1)
		assert.Equal(t, two[0], one[0], "the first keeps its identity, the second is the one that is gone")
	})
}

func TestFindingsWithDifferentMessagesAreDifferent(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		a := shell(7)
		b := shell(7)
		b.message = "Found subprocess call with shell=True and a tainted argument"
		got := identities(t, doc([]sighting{a, b}))
		assert.NotEqual(t, got[0], got[1], "the message names what was matched, so it tells matches apart")
	})
}

func TestOtherRulesAndFilesAreOtherFindings(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		base := shell(7)
		otherFile := base
		otherFile.file = "lib.py"
		otherRule := base
		otherRule.rule = "python.lang.other"
		got := identities(t, doc([]sighting{base, otherFile, otherRule}))
		assert.Len(t, map[string]bool{got[0]: true, got[1]: true, got[2]: true}, 3)
	})
}

func TestSemgrepsOwnMatchIdIsUsedWhenThereIsOne(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		a, b := shell(7), shell(19)
		a.matchID, b.matchID = "1111aaaa_0", "2222bbbb_0"
		got := identities(t, doc([]sighting{a, b}))
		assert.NotEqual(t, got[0], got[1])

		// A logged-in run: the id follows the code, whatever its line or message wording.
		moved := a
		moved.line = 90
		moved.message = "Same match, reworded rule text"
		assert.Equal(t, got[0], identities(t, doc([]sighting{moved}))[0])
	})
}

func TestTheLoggedOutPlaceholderIsNotAnIdentity(t *testing.T) {
	eachFormat(t, func(t *testing.T, doc func([]sighting) string) {
		a, b := shell(7), shell(19)
		b.message = "A different message"
		got := identities(t, doc([]sighting{a, b}))
		assert.NotEqual(t, got[0], got[1], "two findings must not share the placeholder as an identity")
	})
}

func TestBothFormatsGiveTheSameIdentities(t *testing.T) {
	scan := []sighting{shell(7), shell(19), {rule: "dockerfile.root", file: "Dockerfile", message: "Last user is root", line: 5, col: 1}}
	assert.Equal(t, identities(t, sarifDoc(t, scan)), identities(t, nativeDoc(t, scan)),
		"a project that switches between --sarif and --json keeps its findings")

	withIDs := []sighting{shell(7), shell(19)}
	withIDs[0].matchID, withIDs[1].matchID = "aaaa_0", "bbbb_0"
	assert.Equal(t, identities(t, sarifDoc(t, withIDs)), identities(t, nativeDoc(t, withIDs)))
}

func TestTheIdentityFormulaIsVersioned(t *testing.T) {
	assert.EqualValues(t, 3, semgrep.NewScanner().Descriptor().FingerprintVersion,
		"identities no longer include the line, so the version moves")
	nr, err := semgrep.NewScanner().Parse(context.Background(), []byte(nativeDoc(t, []sighting{shell(7)})))
	require.NoError(t, err)
	assert.EqualValues(t, 3, nr.FingerprintVersion)
}
