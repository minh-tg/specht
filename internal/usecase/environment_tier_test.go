package usecase

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultEnvironmentTier(t *testing.T) {
	for name, want := range map[string]string{
		"production":   "production",
		"prod":         "production",
		"Prod-EU":      "production",
		"eu_prd":       "production",
		"live":         "production",
		"staging":      "staging",
		"stage-2":      "staging",
		"stg":          "staging",
		"preprod":      "staging",
		"uat":          "staging",
		"test":         "test",
		"qa":           "test",
		"ci":           "test",
		"integration":  "development",
		"dev":          "development",
		"feature-x":    "development",
		"prod-test":    "production",
		"productivity": "development",
		"contest":      "development",
		"":             "development",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, want, defaultEnvironmentTier(name))
		})
	}
}
