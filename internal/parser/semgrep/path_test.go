package semgrep_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/semgrep"
)

// Semgrep writes a file as the target it was given, so `semgrep scan "$PWD"`
// puts the checkout directory in every path, in --json and in --sarif.
func TestAFindingKeepsItsIdentityFromAnotherCheckout(t *testing.T) {
	cases := []struct{ name, file, key, scheme string }{
		{"json path", "semgrep-native.json", `"path": "`, ""},
		{"sarif absolute uri", "semgrep-native-sarif.json", `"uri": "`, ""},
		{"sarif file uri", "semgrep-native-sarif.json", `"uri": "`, "file://"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + c.file)
			require.NoError(t, err)
			parse := func(prefix string) (fingerprints, files []string) {
				doc := strings.ReplaceAll(string(data), c.key, c.key+prefix)
				nr, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
				require.NoError(t, err)
				require.NotEmpty(t, nr.Findings)
				for _, f := range nr.Findings {
					fingerprints = append(fingerprints, f.Fingerprint)
					files = append(files, f.Location)
				}
				return fingerprints, files
			}
			want, wantFiles := parse("")
			for _, root := range []string{"/src/", "/github/workspace/", "/builds/x/1/", "/home/runner/work/api/api/"} {
				got, gotFiles := parse(c.scheme + root)
				assert.Equal(t, want, got, root)
				assert.Equal(t, wantFiles, gotFiles, root)
			}
		})
	}
}
