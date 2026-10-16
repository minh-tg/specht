package server

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanIngestProject(t *testing.T) {
	big := strings.Repeat("a", 1000)
	tests := []struct {
		name    string
		body    string
		limit   int
		project string
		err     error
		syntax  bool
	}{
		{"project first", `{"project":"my-app","scanner":"trivy","raw_data":{}}`, 4096, "my-app", nil, false},
		{"project after small fields", `{"branch":"main","raw_data":{"a":[1,2]},"project":"my-app"}`, 4096, "my-app", nil, false},
		{"key matches the way the decoder does", `{"PROJECT":"my-app"}`, 4096, "my-app", nil, false},
		{"first of two projects", `{"project":"first","project":"second"}`, 4096, "first", nil, false},
		{"no project in a small body", `{"scanner":"trivy"}`, 4096, "", nil, false},
		{"empty body", ``, 4096, "", nil, false},
		{"null project", `{"project":null}`, 4096, "", nil, false},
		{"project buried behind a big value", `{"raw_data":"` + big + `","project":"my-app"}`, 200, "", errProjectNotInHead, false},
		{"project cut by the limit", `{"project":"my-ap` + big + `"}`, 12, "", errProjectNotInHead, false},
		{"project at the very end of the limit", `{"project":"my-app"}`, len(`{"project":"my-app"`), "my-app", nil, false},
		{"not an object", `[1,2]`, 4096, "", errNotAnObject, true},
		{"project is a number", `{"project":12}`, 4096, "", nil, true},
		{"broken json", `{"project":"my-app" "scanner"`, 4096, "my-app", nil, false},
		{"truncated inside small body", `{"scanner":"tri`, 4096, "", io.ErrUnexpectedEOF, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			project, rest, err := scanIngestProject(strings.NewReader(tc.body), tc.limit)

			switch {
			case tc.syntax:
				require.Error(t, err)
				assert.True(t, isSyntaxError(err), "%v is a syntax error", err)
			case tc.err != nil:
				require.ErrorIs(t, err, tc.err)
			default:
				require.NoError(t, err)
			}
			assert.Equal(t, tc.project, project)
			replayed, readErr := io.ReadAll(rest)
			require.NoError(t, readErr)
			assert.Equal(t, tc.body, string(replayed), "the whole body can be read again")
		})
	}
}

// The scan stops as soon as it has the project, so a caller who is refused
// costs a few bytes of reading, however large the rest of the body is.
func TestScanIngestProject_StopsReadingAtTheProject(t *testing.T) {
	src := &countingReader{r: io.MultiReader(strings.NewReader(`{"project":"x","scanner":"trivy","raw_data":"`), zeroes(25<<20))}

	project, _, err := scanIngestProject(src, ingestHeadBytes)

	require.NoError(t, err)
	assert.Equal(t, "x", project)
	assert.Less(t, src.count(), int64(ingestHeadBytes), "far less than the body was read")
}

func TestScanIngestProject_ReadErrorsSurface(t *testing.T) {
	boom := errors.New("connection reset")
	_, _, err := scanIngestProject(io.MultiReader(strings.NewReader(`{"scanner":"tri`), &errReader{err: boom}), 4096)
	require.ErrorIs(t, err, boom)
}
