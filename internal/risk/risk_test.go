package risk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func f64(v float64) *float64 { return &v }

func TestScore_MaximumInputs(t *testing.T) {
	exp := Score(Signals{
		SeverityRank: 4, CVSS: f64(10),
		Reachability: "reachable", EnvTier: "production", InternetFacing: true,
		AgeDays: 90, RecurrenceCount: 5, HasKnownExploit: &[]bool{true}[0],
	})
	assert.Equal(t, ModelVersion, exp.Version)
	assert.InDelta(t, 100.0, exp.Score, 1e-9)
	assert.Equal(t, "critical", exp.Band)
	assert.Empty(t, exp.Missing)
}

func TestScore_AllUnknown(t *testing.T) {
	exp := Score(Signals{})
	assert.InDelta(t, 0.0, exp.Score, 1e-9)
	assert.Equal(t, "low", exp.Band)
	// Severity/age/recurrence have zero defaults, not "unknown" signals;
	// every genuinely unknown feed must be listed.
	assert.ElementsMatch(t, []string{"cvss", "reachability", "exposure", "exploit"}, exp.Missing)
	for _, c := range exp.Components {
		if c.Signal == "severity" || c.Signal == "age" || c.Signal == "recurrence" {
			assert.False(t, c.Missing)
		}
	}
}

func TestScore_GoldenVector(t *testing.T) {
	exp := Score(Signals{
		SeverityRank: 3, CVSS: f64(7.5),
		Reachability: "unknown", EnvTier: "production",
		AgeDays: 30, RecurrenceCount: 1, HasKnownExploit: nil,
	})
	// 22.5 + 11.25 + 7.5 + 10 + 1.667 + 1 + 0 = 53.917
	assert.InDelta(t, 53.9166667, exp.Score, 1e-6)
	assert.Equal(t, "high", exp.Band)
	assert.ElementsMatch(t, []string{"exploit"}, exp.Missing)
}

func TestScore_Deterministic(t *testing.T) {
	in := Signals{
		SeverityRank: 2, CVSS: f64(5.0), Reachability: "reachable",
		EnvTier: "staging", AgeDays: 10, RecurrenceCount: 2,
	}
	assert.Equal(t, Score(in), Score(in))
}

func TestScore_ClampsOutOfRange(t *testing.T) {
	exp := Score(Signals{SeverityRank: 99, CVSS: f64(99), AgeDays: -5, RecurrenceCount: 99})
	require.LessOrEqual(t, exp.Score, float64(MaxScore))
	// rank 4 -> 30, cvss 10 -> 15, age 0, recurrence 5 -> 5 = 50 before
	// reachability/exposure/exploit missings.
	assert.InDelta(t, 50.0, exp.Score, 1e-9)
}

func TestBand_Boundaries(t *testing.T) {
	assert.Equal(t, "low", Band(0))
	assert.Equal(t, "low", Band(24.99))
	assert.Equal(t, "medium", Band(25))
	assert.Equal(t, "high", Band(50))
	assert.Equal(t, "critical", Band(75))
	assert.Equal(t, "critical", Band(100))
}
