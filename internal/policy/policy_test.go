package policy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDefinition_Valid(t *testing.T) {
	def, err := ParseDefinition(json.RawMessage(`{"severity_floor":"Critical","watcher_gate":"off"}`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"severity_floor": "critical", "watcher_gate": "off"}, def)
}

func TestParseDefinition_RejectsUnknown(t *testing.T) {
	_, err := ParseDefinition(json.RawMessage(`{"nuclear_option":"yes"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown policy key")

	_, err = ParseDefinition(json.RawMessage(`{"severity_floor":"extreme"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid value")

	_, err = ParseDefinition(json.RawMessage(`{"severity_floor":42}`))
	require.Error(t, err)

	_, err = ParseDefinition(json.RawMessage(`{oops`))
	require.Error(t, err)
}

func TestResolve_Precedence(t *testing.T) {
	name := "baseline"
	eff := Resolve(&name, 3,
		map[string]string{"severity_floor": "medium", "watcher_gate": "off"},
		map[string]string{"severity_floor": "critical"},
	)
	assert.Equal(t, "critical", eff.SeverityFloor)
	assert.Equal(t, SourceOverride, eff.SeveritySource)
	assert.Equal(t, "off", eff.WatcherGate)
	assert.Equal(t, SourceTemplate, eff.WatcherSource)
	assert.Equal(t, &name, eff.TemplateName)
	assert.Equal(t, 3, eff.TemplateVersion)
}

func TestResolve_Defaults(t *testing.T) {
	eff := Resolve(nil, 0, nil, nil)
	assert.Equal(t, "high", eff.SeverityFloor)
	assert.Equal(t, SourceDefault, eff.SeveritySource)
	assert.Equal(t, "immediate", eff.WatcherGate)
	assert.Equal(t, SourceDefault, eff.WatcherSource)
	assert.Nil(t, eff.TemplateName)
}

func TestSeverityRank(t *testing.T) {
	assert.Equal(t, int16(4), SeverityRank("critical"))
	assert.Equal(t, int16(3), SeverityRank("high"))
	assert.Equal(t, int16(2), SeverityRank("medium"))
	assert.Equal(t, int16(1), SeverityRank("low"))
	assert.Equal(t, int16(3), SeverityRank("bogus"), "unknown floors fail closed toward blocking")
}
