package grype

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
)

const kernelIgnore = `{"vulnerability":"","include-aliases":false,"reason":"","namespace":"","fix-state":"","package":{"name":"kernel-headers","version":"","language":"","type":"rpm","location":"","upstream-name":"kernel"},"vex-status":"","vex-justification":"","match-type":"exact-indirect-match"}`

func grypeWith(configuration string) []byte {
	return []byte(fmt.Sprintf(`{"matches":[],"descriptor":{"name":"grype","version":"0.120.1"%s}}`, configuration))
}

func TestUnfilteredReportCoversVulnerabilities(t *testing.T) {
	cases := []struct {
		name string
		doc  []byte
		want bool
	}{
		{
			"default configuration",
			grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":false,"ignore-wontfix":"","ignore":[` + kernelIgnore + `],"exclude":[],"vex-documents":[],"vex-add":[]}`), true,
		},
		{"no configuration", grypeWith(``), false},
		{"only-fixed", grypeWith(`,"configuration":{"only-fixed":true,"only-notfixed":false}`), false},
		{"only-notfixed", grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":true}`), false},
		{"filter keys missing", grypeWith(`,"configuration":{"output":["json"]}`), false},
		{"ignore-wontfix set", grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":false,"ignore-wontfix":"wont-fix"}`), false},
		{"exclude set", grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":false,"exclude":["./vendor/**"]}`), false},
		{"vex document set", grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":false,"vex-documents":["a.json"]}`), false},
		{"user ignore rule", grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":false,"ignore":[{"vulnerability":"CVE-2020-1","package":{"name":""},"match-type":""}]}`), false},
		{"ignore rule on a package", grypeWith(`,"configuration":{"only-fixed":false,"only-notfixed":false,"ignore":[{"package":{"name":"lodash","type":"npm"}}]}`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nr, err := NewScanner().Parse(context.Background(), tc.doc)
			require.NoError(t, err)
			if tc.want {
				assert.Equal(t, domain.CompletenessComplete, nr.Completeness)
				assert.Equal(t, []string{"sca"}, nr.CoveredFindingKinds)
				return
			}
			assert.Equal(t, domain.CompletenessUnknown, nr.Completeness)
			assert.Empty(t, nr.CoveredFindingKinds)
		})
	}
}
