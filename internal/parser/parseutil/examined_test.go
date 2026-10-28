package parseutil

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/domain"
)

// proves answers what report_examined_finding answers for run keys: some run
// lists both the finding's rule (of its kind) and one of its files. It reads
// the run number up to the second colon, as the SQL split_part does.
func proves(keys []string, kind string, ruleIDs, files []string) bool {
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	for _, k := range keys {
		parts := strings.SplitN(k, ":", 3)
		if len(parts) < 3 || parts[0] != "run" {
			continue
		}
		run := parts[1]
		for _, r := range ruleIDs {
			if k != "run:"+run+":rule:"+kind+":"+r {
				continue
			}
			for _, f := range files {
				if set["run:"+run+":file:"+f] {
					return true
				}
			}
		}
	}
	return false
}

func TestExaminedFromRunsSingleRun(t *testing.T) {
	keys := ExaminedFromRuns([]RuleRun{{Kind: "sast", RuleIDs: []string{"r1", "r2"}, Files: []string{"a.go", "b.go"}}})
	assert.Equal(t, []string{
		domain.ExaminedRunFile(0, "a.go"), domain.ExaminedRunFile(0, "b.go"),
		domain.ExaminedRunRule(0, "sast", "r1"), domain.ExaminedRunRule(0, "sast", "r2"),
	}, keys)
	assert.True(t, proves(keys, "sast", []string{"r1"}, []string{"b.go"}))
	assert.False(t, proves(keys, "sast", []string{"r1"}, []string{"c.go"}), "a file the run never listed")
	assert.False(t, proves(keys, "iac", []string{"r1"}, []string{"a.go"}), "a rule of another kind")
	assert.False(t, proves(keys, "sast", []string{"r1"}, nil), "a finding with no file")
}

// Run A ran rule R1 over file a and run B ran R2 over file b. Nothing ran R1
// over b, so a finding for R1 in b is not proven absent.
func TestExaminedFromRunsKeepsEachRuleToItsOwnRunsFiles(t *testing.T) {
	keys := ExaminedFromRuns([]RuleRun{
		{Kind: "sast", RuleIDs: []string{"R1"}, Files: []string{"a"}},
		{Kind: "sast", RuleIDs: []string{"R2"}, Files: []string{"b"}},
	})
	assert.Equal(t, []string{
		domain.ExaminedRunFile(0, "a"), domain.ExaminedRunRule(0, "sast", "R1"),
		domain.ExaminedRunFile(1, "b"), domain.ExaminedRunRule(1, "sast", "R2"),
	}, keys)
	assert.True(t, proves(keys, "sast", []string{"R1"}, []string{"a"}))
	assert.True(t, proves(keys, "sast", []string{"R2"}, []string{"b"}))
	assert.False(t, proves(keys, "sast", []string{"R1"}, []string{"b"}), "R1 never ran over b")
	assert.False(t, proves(keys, "sast", []string{"R2"}, []string{"a"}), "R2 never ran over a")
}

func TestExaminedFromRunsWithoutFilesProvesNothing(t *testing.T) {
	assert.Empty(t, ExaminedFromRuns([]RuleRun{{Kind: "sast", RuleIDs: []string{"r1"}}}))

	// A run without files next to one with files lends its rules nothing.
	keys := ExaminedFromRuns([]RuleRun{
		{Kind: "sast", RuleIDs: []string{"R1"}},
		{Kind: "sast", RuleIDs: []string{"R2"}, Files: []string{"b"}},
	})
	assert.Equal(t, []string{domain.ExaminedRunFile(1, "b"), domain.ExaminedRunRule(1, "sast", "R2")}, keys)
	assert.False(t, proves(keys, "sast", []string{"R1"}, []string{"b"}))
}

func TestExaminedFromRunsSkipsAFailedRun(t *testing.T) {
	keys := ExaminedFromRuns([]RuleRun{
		{Kind: "sast", RuleIDs: []string{"R1"}, Files: []string{"a"}, Failed: true},
		{Kind: "sast", RuleIDs: []string{"R2"}, Files: []string{"a"}},
	})
	assert.Equal(t, []string{domain.ExaminedRunFile(1, "a"), domain.ExaminedRunRule(1, "sast", "R2")}, keys)
	assert.False(t, proves(keys, "sast", []string{"R1"}, []string{"a"}))
}

func TestExaminedFromRunsLeavesAnUnprovenRuleOut(t *testing.T) {
	keys := ExaminedFromRuns([]RuleRun{{
		Kind: "sast", RuleIDs: []string{"r1", "r2"}, Files: []string{"a"},
		Unproven: map[string]bool{"r1": true},
	}})
	assert.Equal(t, []string{domain.ExaminedRunFile(0, "a"), domain.ExaminedRunRule(0, "sast", "r2")}, keys)
	assert.False(t, proves(keys, "sast", []string{"r1"}, []string{"a"}))

	// A run whose only rule is unproven proves nothing, files included.
	assert.Empty(t, ExaminedFromRuns([]RuleRun{{
		Kind: "sast", RuleIDs: []string{"r1"}, Files: []string{"a"},
		Unproven: map[string]bool{"r1": true},
	}}))
}

// A colon in a rule id or a path must not let one run's key pass for another
// run's or move the run number.
func TestExaminedFromRunsWithColonsInRuleAndPath(t *testing.T) {
	keys := ExaminedFromRuns([]RuleRun{
		{Kind: "sast", RuleIDs: []string{"a:b"}, Files: []string{"c:/src/x.go"}},
		{Kind: "sast", RuleIDs: []string{"1:rule:sast:a:b"}, Files: []string{"y.go"}},
	})
	assert.True(t, proves(keys, "sast", []string{"a:b"}, []string{"c:/src/x.go"}))
	assert.False(t, proves(keys, "sast", []string{"a:b"}, []string{"y.go"}))
	assert.False(t, proves(keys, "sast", []string{"1:rule:sast:a:b"}, []string{"c:/src/x.go"}))
	assert.True(t, proves(keys, "sast", []string{"1:rule:sast:a:b"}, []string{"y.go"}))
}

func TestExaminedFromRunsOverTheCapProvesNothing(t *testing.T) {
	files := make([]string, domain.MaxExaminedKeys)
	for i := range files {
		files[i] = "f/" + strconv.Itoa(i)
	}
	assert.Nil(t, ExaminedFromRuns([]RuleRun{{Kind: "sast", RuleIDs: []string{"r1"}, Files: files}}))
}
