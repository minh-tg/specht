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
			[]string{"file:src/x.go", "rule:sast:go/a", "rule:sast:go/b", "scope:files"},
		},
		{
			"no file list",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"}]}},"results":[]}]}`,
			[]string{"rule:sast:r1"},
		},
		{
			"unsuccessful run proves nothing",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"}]}},"invocations":[{"executionSuccessful":false}],"results":[]}]}`,
			nil,
		},
		{
			"error notification proves nothing",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"}]}},"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[{"level":"error"}]}],"results":[]}]}`,
			nil,
		},
		{
			"a rule with an accepted suppression is not proven",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r1"},{"id":"r2"}]}},
			  "results":[{"ruleId":"r1","message":{"text":"m"},"suppressions":[{"kind":"inSource","status":"accepted"}]}]}]}`,
			[]string{"rule:sast:r2"},
		},
		{
			"no rule list",
			`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T"}},"results":[]}]}`,
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
