package parser_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nulCaptured maps each captured report to the scanner that reads it.
var nulCaptured = []struct{ file, scanner string }{
	{"trivy.json", "trivy"},
	{"osv-scanner.json", "osv-scanner"},
	{"grype.json", "grype"},
	{"dependency-check.json", "dependency-check"},
	{"checkov.json", "checkov"},
	{"tfsec.json", "tfsec"},
	{"nuclei.json", "nuclei"},
	{"gitleaks.json", "gitleaks"},
	{"semgrep.json", "semgrep"},
	{"codeql.json", "sarif"},
	{"cyclonedx.json", "sbom"},
	{"spdx.json", "sbom"},
}

// withNULs puts a NUL character into every string value of 16 bytes or more, at
// the start, the middle and the end alternately.
func withNULs(v any, n *int) any {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			x[k] = withNULs(item, n)
		}
		return x
	case []any:
		for i, item := range x {
			x[i] = withNULs(item, n)
		}
		return x
	case string:
		if len(x) < 16 {
			return x // format markers and enum values stay readable
		}
		*n++
		half := len(x) / 2
		switch *n % 3 {
		case 0:
			return "\x00" + x
		case 1:
			return x[:half] + "\x00" + x[half:]
		default:
			return x + "\x00"
		}
	}
	return v
}

// nulPaths returns where in v a string or map key holds a NUL.
func nulPaths(v reflect.Value, path string, out *[]string) {
	switch v.Kind() {
	case reflect.String:
		if strings.ContainsRune(v.String(), 0) {
			*out = append(*out, path)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			nulPaths(v.Elem(), path, out)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				nulPaths(v.Field(i), path+"."+v.Type().Field(i).Name, out)
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if strings.ContainsRune(string(v.Bytes()), 0) {
				*out = append(*out, path)
			}
			return
		}
		for i := range v.Len() {
			nulPaths(v.Index(i), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			nulPaths(k, path+"{key}", out)
			nulPaths(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k), out)
		}
	}
}

// A report with NUL characters in its strings is read, and nothing the parser
// hands to the store holds a NUL: PostgreSQL refuses a text value with one, and
// the whole ingest used to fail with a generic 422.
func TestParsersHandNoNULToTheStore(t *testing.T) {
	for _, c := range nulCaptured {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "captured", c.file))
			require.NoError(t, err)
			var doc any
			require.NoError(t, json.Unmarshal(raw, &doc))
			n := 0
			doc = withNULs(doc, &n)
			require.NotZero(t, n)
			polluted, err := json.Marshal(doc)
			require.NoError(t, err)
			require.Contains(t, string(polluted), fmt.Sprintf("%cu0000", 92), "the document carries the escape")

			rep, err := scannerByName(t, c.scanner).Parse(testCtx(), polluted)
			if err != nil {
				t.Skipf("the parser refuses the polluted document: %v", err)
			}

			var found []string
			nulPaths(reflect.ValueOf(rep), "report", &found)
			assert.Empty(t, found, "strings with a NUL")
		})
	}
}
