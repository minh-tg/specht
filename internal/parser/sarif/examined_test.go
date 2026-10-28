package sarif

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExaminedKeys(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{
			"rules in the driver and in an extension, files listed",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":[{"id":"go/a"}]},"extensions":[{"rules":[{"id":"go/b"}]}]},
			  "artifacts":[{"location":{"uri":"src/x.go"}}],"results":[]}]}`,
			[]string{"run:0:file:src/x.go", "run:0:rule:sast:go/a", "run:0:rule:sast:go/b"},
		},
		{
			"each run proves its rules for its own files",
			`{"version":"2.1.0","runs":[
			  {"tool":{"driver":{"name":"CodeQL","rules":[{"id":"go/a"}]}},"artifacts":[{"location":{"uri":"a.go"}}],"results":[]},
			  {"tool":{"driver":{"name":"CodeQL","rules":[{"id":"js/b"}]}},"artifacts":[{"location":{"uri":"b.js"}}],"results":[]}]}`,
			[]string{"run:0:file:a.go", "run:0:rule:sast:go/a", "run:1:file:b.js", "run:1:rule:sast:js/b"},
		},
		{
			"no file list proves nothing",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"}]}},"results":[]}]}`,
			nil,
		},
		{
			"unsuccessful run proves nothing",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"}]}},"artifacts":[{"location":{"uri":"a.go"}}],"invocations":[{"executionSuccessful":false}],"results":[]}]}`,
			nil,
		},
		{
			"error notification proves nothing",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"}]}},"artifacts":[{"location":{"uri":"a.go"}}],"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error"}]}],"results":[]}]}`,
			nil,
		},
		{
			"a rule with an accepted suppression is not proven",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"},{"id":"r2"}]}},"artifacts":[{"location":{"uri":"a.go"}}],
			  "results":[{"ruleId":"r1","message":{"text":"m"},"suppressions":[{"kind":"inSource","status":"accepted"}]}]}]}`,
			[]string{"run:0:file:a.go", "run:0:rule:sast:r2"},
		},
		{
			"no rule list",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"artifacts":[{"location":{"uri":"a.go"}}],"results":[]}]}`,
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nr, err := NewScanner().Parse(context.Background(), []byte(tc.doc))
			require.NoError(t, err)
			if tc.want == nil {
				assert.Empty(t, nr.ExaminedKeys)
				return
			}
			assert.Equal(t, tc.want, nr.ExaminedKeys)
		})
	}
}
