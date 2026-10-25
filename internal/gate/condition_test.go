package gate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCondition(t *testing.T) {
	valid := []WaiverCondition{
		{Field: "severity_rank", Operator: "lte", Value: "2"},
		{Field: "severity_rank", Operator: "neq", Value: "4"},
		{Field: "finding_kind", Operator: "eq", Value: "sca"},
		{Field: "fingerprint", Operator: "neq", Value: "abc"},
		{Field: "title_pattern", Operator: "contains", Value: "openssl"},
		{Field: "title_pattern", Operator: "matches", Value: "Exact title"},
		{Field: "cve_id", Operator: "eq", Value: "CVE-2024-1234"},
		{Field: "cve_id", Operator: "contains", Value: "CVE-2024"},
	}
	for _, c := range valid {
		assert.NoError(t, ValidateCondition(c), "%+v", c)
	}

	invalid := []struct {
		c    WaiverCondition
		want string
	}{
		{WaiverCondition{Field: "severity", Operator: "eq", Value: "high"}, `field "severity"`},
		{WaiverCondition{Field: "cve", Operator: "eq", Value: "CVE-1"}, `field "cve"`},
		{WaiverCondition{Field: "severity_rank", Operator: "=", Value: "3"}, `operator "="`},
		{WaiverCondition{Field: "finding_kind", Operator: "contains", Value: "sca"}, `operator "contains"`},
		{WaiverCondition{Field: "cve_id", Operator: "neq", Value: "CVE-1"}, `operator "neq"`},
		{WaiverCondition{Field: "severity_rank", Operator: "gte", Value: "high"}, "whole number"},
		{WaiverCondition{Field: "cve_id", Operator: "eq", Value: "  "}, "must not be empty"},
	}
	for _, tc := range invalid {
		err := ValidateCondition(tc.c)
		if assert.Error(t, err, "%+v", tc.c) {
			assert.Contains(t, err.Error(), tc.want)
		}
	}
}

// Every condition ValidateCondition accepts must be one matchCondition can
// match, or a stored waiver would still cover nothing.
func TestValidatedConditionsCanMatch(t *testing.T) {
	f := Finding{
		FindingKind: "sca", Fingerprint: "sca:CVE-2024-1234:lodash", CurrentTitle: "CVE-2024-1234 in lodash",
		CurrentSeverityRank: 3,
	}
	values := map[string]map[string]string{
		"severity_rank": {"eq": "3", "neq": "1", "lt": "4", "lte": "3", "gt": "2", "gte": "3"},
		"finding_kind":  {"eq": "sca", "neq": "sast"},
		"fingerprint":   {"eq": f.Fingerprint, "neq": "other"},
		"title_pattern": {"contains": "lodash", "matches": f.CurrentTitle},
		"cve_id":        {"eq": "CVE-2024-1234", "contains": "2024-1234"},
	}
	for field, ops := range conditionOperators {
		for _, op := range ops {
			c := WaiverCondition{Field: field, Operator: op, Value: values[field][op]}
			assert.NoError(t, ValidateCondition(c))
			assert.True(t, matchCondition(f, c), "%+v", c)
		}
	}
}
