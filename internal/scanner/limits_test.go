package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	for _, doc := range []string{"", "not json", `{"unterminated":"`, strings.Repeat("[", 64), strings.Repeat("}", 100)} {
		// 1000 allows 64000 values, and 64 open containers is within the depth cap.
		assert.NoError(t, scanner.CheckDocument([]byte(doc), 1000), "%.20q", doc)
	}
}

// nestedDoc returns a document with depth containers open at its deepest point.
// It alternates objects and arrays, so both kinds count toward the depth.
func nestedDoc(depth int) []byte {
	var b strings.Builder
	for i := range depth {
		if i%2 == 0 {
			b.WriteString(`{"k":`)
		} else {
			b.WriteString(`[`)
		}
	}
	b.WriteString(`null`)
	for i := depth - 1; i >= 0; i-- {
		if i%2 == 0 {
			b.WriteString(`}`)
		} else {
			b.WriteString(`]`)
		}
	}
	return []byte(b.String())
}

func TestCheckDocumentAcceptsNestingAtTheDepthCap(t *testing.T) {
	require.Equal(t, 64, scanner.MaxNestingDepth)
	require.NoError(t, scanner.CheckDocument(nestedDoc(64), scanner.DefaultMaxFindings))
	require.NoError(t, scanner.CheckDocument([]byte(strings.Repeat("[", 64)+strings.Repeat("]", 64)), scanner.DefaultMaxFindings))
}

func TestCheckDocumentRefusesNestingPastTheDepthCapWithTheFindingsError(t *testing.T) {
	err := scanner.CheckDocument(nestedDoc(65), scanner.DefaultMaxFindings)
	require.ErrorIs(t, err, scanner.ErrTooManyFindings)
	var tooMany *scanner.TooManyFindingsError
	require.ErrorAs(t, err, &tooMany)
	assert.Equal(t, 64, tooMany.Limit)

	// The refusal holds for broken input too, since the scan reads it before any decoder.
	require.ErrorIs(t, scanner.CheckDocument([]byte(strings.Repeat("[", 65)), scanner.DefaultMaxFindings), scanner.ErrTooManyFindings)
	// And for a deep document under a limit that its counts would pass.
	require.ErrorIs(t, scanner.CheckDocument(nestedDoc(200), 1000), scanner.ErrTooManyFindings)
}

func TestCheckDocumentDoesNotCountBracketsInsideStrings(t *testing.T) {
	doc := `{"s":"` + strings.Repeat("[", 500) + `"}`
	require.NoError(t, scanner.CheckDocument([]byte(doc), 1))
}

// TestCheckDocumentAcceptsEveryCapturedFixture runs the default check over every
// captured report under the e2e and parser fixtures. A real scanner report must
// stay under the depth cap, so a fixture that goes past it fails here.
func TestCheckDocumentAcceptsEveryCapturedFixture(t *testing.T) {
	var files int
	for _, root := range []string{"../../e2e/testdata", "../../internal/parser/testdata"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			files++
			assert.NoError(t, scanner.CheckDocument(data, scanner.DefaultMaxFindings), path)
			return nil
		})
		require.NoError(t, err)
	}
	require.NotZero(t, files, "the fixture directories are empty or moved")
}

func objects(n int) string {
	return strings.TrimSuffix(strings.Repeat("{},", n), ",")
}

func TestCheckDocumentCountsElementsOfTheNamedArrays(t *testing.T) {
	ceiling := 2 * scanner.ElementsPerFinding
	doc := func(n int) []byte { return []byte(`{"Results":[{"Vulnerabilities":[` + objects(n) + `]}]}`) }

	require.NoError(t, scanner.CheckDocument(doc(ceiling), 2, "Vulnerabilities"))
	require.ErrorIs(t, scanner.CheckDocument(doc(ceiling+1), 2, "Vulnerabilities"), scanner.ErrTooManyFindings)
	require.NoError(t, scanner.CheckDocument(doc(ceiling+1), 2, "Secrets"), "an array under another key is not counted")
	require.NoError(t, scanner.CheckDocument(doc(ceiling+1), 2), "no keys means only the object count applies")
}

func TestCheckDocumentSumsElementsAcrossArraysWithTheSameKey(t *testing.T) {
	doc := `{"Results":[` + strings.TrimSuffix(strings.Repeat(`{"Vulnerabilities":[{},{},{}]},`, 3), ",") + `]}`
	require.NoError(t, scanner.CheckDocument([]byte(doc), 5, "Vulnerabilities"), "9 elements, ceiling 10")
	require.ErrorIs(t, scanner.CheckDocument([]byte(doc), 4, "Vulnerabilities"), scanner.ErrTooManyFindings, "9 elements, ceiling 8")
}

func TestCheckDocumentCountsTheRootArrayAndJSONLinesUnderTheEmptyKey(t *testing.T) {
	require.ErrorIs(t, scanner.CheckDocument([]byte("["+objects(3)+"]"), 1, ""), scanner.ErrTooManyFindings)
	require.ErrorIs(t, scanner.CheckDocument([]byte(strings.Repeat("{}\n", 3)), 1, ""), scanner.ErrTooManyFindings)
	require.NoError(t, scanner.CheckDocument([]byte("["+objects(3)+"]"), 1, "results"), "the root array is not named results")
}

func TestCheckDocumentFollowsNestedArraysOfTheSameKey(t *testing.T) {
	// CycloneDX nests components inside components.
	doc := `{"components":[{"components":[{},{}]},{"components":[{}]}]}`
	require.ErrorIs(t, scanner.CheckDocument([]byte(doc), 1, "components"), scanner.ErrTooManyFindings,
		"2 outer elements and 3 inner ones, ceiling 2")
}

func TestCheckDocumentIgnoresKeysThatLookLikeValuesAndTheReverse(t *testing.T) {
	doc := `{"note":"Vulnerabilities","x":{"Vulnerabilities":"` + strings.Repeat(`{`, 50) + `"},"Results":[` + objects(2) + `]}`
	require.NoError(t, scanner.CheckDocument([]byte(doc), 5, "Vulnerabilities"))
}

func repeatValue(v string, n int) string {
	return strings.TrimSuffix(strings.Repeat(v+",", n), ",")
}

// Padding that is not an object decodes into zero structs or interface values
// just the same, so every element of a counted array costs one whatever it is.
func TestCheckDocumentCountsElementsOfEveryType(t *testing.T) {
	ceiling := 2 * scanner.ElementsPerFinding
	for _, v := range []string{`null`, `""`, `"text"`, `0`, `-1.5e3`, `true`, `false`, `[]`, `[0]`, `{}`} {
		doc := func(n int) []byte { return []byte(`{"Results":[` + repeatValue(v, n) + `]}`) }
		if v != `[0]` { // an array nested in a counted array counts its own elements too
			require.NoError(t, scanner.CheckDocument(doc(ceiling), 2, "Results"), "%s at the ceiling", v)
		}
		require.ErrorIs(t, scanner.CheckDocument(doc(ceiling+1), 2, "Results"), scanner.ErrTooManyFindings, "%s past the ceiling", v)
	}
}

func TestCheckDocumentCountsScalarLinesAndRootElementsUnderTheEmptyKey(t *testing.T) {
	require.ErrorIs(t, scanner.CheckDocument([]byte("["+repeatValue("null", 5)+"]"), 2, ""), scanner.ErrTooManyFindings)
	require.ErrorIs(t, scanner.CheckDocument([]byte(strings.Repeat("null\n", 5)), 2, ""), scanner.ErrTooManyFindings)
	require.NoError(t, scanner.CheckDocument([]byte("["+repeatValue("null", 5)+"]"), 2, "results"), "the root array is not named results")
}

// uni spells r as a JSON unicode escape, for example uni(0x65) is the escape
// for the letter e.
func uni(r rune) string { return fmt.Sprintf("%cu%04x", 92, r) }

// encoding/json matches struct fields case-insensitively and decodes escaped
// keys, so a finding array spelled in another case, or with a JSON escape, is
// still the finding array.
func TestCheckDocumentMatchesArrayKeysLikeEncodingJSON(t *testing.T) {
	ceiling := 2 * scanner.ElementsPerFinding
	keys := []string{
		"Results", "results", "RESULTS", "rEsUlTs",
		"R" + uni('e') + "sults", uni('r') + "esults", uni('R') + "ESULTS", "Result" + uni('s'), "res" + uni('u') + "lts",
		uni('R') + uni('e') + uni('s') + uni('u') + uni('l') + uni('t') + uni('s'),
		"Resu" + strings.Replace(uni('l'), "6c", "6C", 1) + "ts", // upper-case hex digits
	}
	for _, k := range keys {
		doc := func(n int) []byte { return []byte(`{"` + k + `":[` + repeatValue("null", n) + `]}`) }
		require.NoError(t, scanner.CheckDocument(doc(ceiling), 2, "Results"), "%s at the ceiling", k)
		require.ErrorIs(t, scanner.CheckDocument(doc(ceiling+1), 2, "Results"), scanner.ErrTooManyFindings, "key %s", k)
	}
	// An escape that spells a different word, and a long escaped key that
	// cannot match, stay uncounted without trouble.
	bs := string(rune(92))
	for _, k := range []string{
		"R" + uni('e') + "sult", "Results" + uni(0), strings.Repeat(uni('R'), 200), bs + "ud83d" + bs + "ude00", bs + "ud83d", bs + "u00zz", bs + "q", bs + "u12",
	} {
		doc := []byte(`{"` + k + `":[` + repeatValue("null", ceiling+1) + `]}`)
		require.NoError(t, scanner.CheckDocument(doc, 2, "Results"), "key %s", k)
	}
}

func TestCheckDocumentFoldsArrayKeysTheWayEncodingJSONDoes(t *testing.T) {
	// The Kelvin sign folds onto k, as encoding/json folds it.
	doc := []byte(`{"` + string(rune(0x212a)) + `eys":[` + repeatValue("null", 5) + `]}`)
	require.ErrorIs(t, scanner.CheckDocument(doc, 2, "keys"), scanner.ErrTooManyFindings)
}

func TestCheckDocumentCapsTheTotalNumberOfValues(t *testing.T) {
	ceiling := 3 * scanner.ValuesPerFinding
	// One finding whose fields hold arrays and maps of scalars: no counted
	// array, so only the value ceiling applies.
	for _, v := range []string{`0`, `""`, `null`, `true`, `[]`} {
		doc := func(n int) []byte { return []byte(`{"extra":{"x":[` + repeatValue(v, n) + `]}}`) }
		// 3 values are the two objects and the array itself.
		require.NoError(t, scanner.CheckDocument(doc(ceiling-3), 3), "%s at the ceiling", v)
		require.ErrorIs(t, scanner.CheckDocument(doc(ceiling-2), 3), scanner.ErrTooManyFindings, "%s past the ceiling", v)
	}
	mapDoc := `{"m":{` + strings.TrimSuffix(strings.Repeat(`"k":0,`, ceiling), ",") + `}}`
	require.ErrorIs(t, scanner.CheckDocument([]byte(mapDoc), 3), scanner.ErrTooManyFindings, "map members are values")
	// Keys are not values: the root object and ceiling-1 members make exactly
	// the ceiling.
	members := `{` + strings.TrimSuffix(strings.Repeat(`"k":0,`, ceiling-1), ",") + `}`
	require.NoError(t, scanner.CheckDocument([]byte(members), 3))
}

func TestCheckDocumentDoesNotMistakeStringsAndNumbersForSeveralValues(t *testing.T) {
	// 12 values: object, array, 5 strings, 3 numbers, 2 literals... counted once each.
	doc := []byte(`{"a":["x y","{[","1,2",1.5e+3,-0,true,null,"\"q\"",""]}`)
	require.NoError(t, scanner.CheckDocument(doc, 1), "a single finding allows 64 values")
	require.ErrorIs(t, scanner.CheckDocument([]byte(`{"a":[`+repeatValue(`"a,b"`, scanner.ValuesPerFinding)+`]}`), 1), scanner.ErrTooManyFindings)
	require.NoError(t, scanner.CheckDocument([]byte(`{"a":[`+repeatValue(`"a,b"`, scanner.ValuesPerFinding-2)+`]}`), 1))
}

func TestCheckDocumentAllocatesNothingPerElement(t *testing.T) {
	doc := []byte(`{"R` + uni('e') + `sults":[` + repeatValue(`null`, 10000) + `],"x":[` + repeatValue(`"s"`, 10000) + `]}`)
	allocs := testing.AllocsPerRun(5, func() {
		_ = scanner.CheckDocument(doc, 100000, "Results")
	})
	assert.LessOrEqual(t, allocs, 4.0)
}
