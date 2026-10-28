package tfsec

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOneResourceAddressInTwoModulesIsTwoFindings(t *testing.T) {
	// tfsec 1.28.14 on a/main.tf and b/main.tf, each with aws_s3_bucket.this.
	data, err := os.ReadFile("testdata/tfsec-two-modules.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 18)

	seen := map[string]bool{}
	for _, f := range rep.Findings {
		seen[f.Fingerprint] = true
	}
	assert.Len(t, seen, 18, "a check failing in two modules is two findings")
	assert.True(t, seen["iac:AVD-AWS-0086:aws_s3_bucket.this:infra/a/main.tf"])
	assert.True(t, seen["iac:AVD-AWS-0086:aws_s3_bucket.this:infra/b/main.tf"])
}

func TestAFindingKeepsItsIdentityFromAnotherCheckout(t *testing.T) {
	// tfsec writes absolute paths, so the checkout directory is in every
	// filename. The same files from a container mount, a GitHub Docker action
	// and a GitLab runner are the same findings.
	data, err := os.ReadFile("testdata/tfsec-two-modules.json")
	require.NoError(t, err)
	fingerprints := func(root string) []string {
		doc := strings.ReplaceAll(string(data), `"/src/infra/`, `"`+root+`infra/`)
		rep, err := NewScanner().Parse(context.Background(), []byte(doc))
		require.NoError(t, err)
		var out []string
		for _, f := range rep.Findings {
			out = append(out, f.Fingerprint)
			assert.NotContains(t, f.CodeLocation.File, root, "the checkout directory is not part of the file")
		}
		return out
	}
	want := fingerprints("/src/")
	assert.Equal(t, want, fingerprints("/github/workspace/"))
	assert.Equal(t, want, fingerprints("/builds/x/1/"))
}

func TestAFindingKeepsItsIdentityWhenItsResourceMoves(t *testing.T) {
	doc := func(line string) []byte {
		return []byte(`{"results":[{"rule_id":"AVD-AWS-0086","long_id":"aws-s3-block-public-acls","status":0,"severity":"HIGH",
			"resource":"aws_s3_bucket.this","location":{"filename":"main.tf","start_line":` + line + `}}]}`)
	}
	before, err := NewScanner().Parse(context.Background(), doc("1"))
	require.NoError(t, err)
	after, err := NewScanner().Parse(context.Background(), doc("40"))
	require.NoError(t, err)
	assert.Equal(t, before.Findings[0].Fingerprint, after.Findings[0].Fingerprint)
}

func TestResultsWithoutAResourceFallBackToTheLine(t *testing.T) {
	rep, err := NewScanner().Parse(context.Background(), []byte(`{"results":[
		{"rule_id":"r","long_id":"x-r","status":0,"severity":"HIGH","location":{"filename":"main.tf","start_line":3}},
		{"rule_id":"r","long_id":"x-r","status":0,"severity":"HIGH","location":{"filename":"main.tf","start_line":9}}]}`))
	require.NoError(t, err)
	require.Len(t, rep.Findings, 2)
	assert.NotEqual(t, rep.Findings[0].Fingerprint, rep.Findings[1].Fingerprint)
}

func TestTheScannerSaysItsIdentitiesChanged(t *testing.T) {
	assert.EqualValues(t, 2, NewScanner().Descriptor().FingerprintVersion)
	rep, err := NewScanner().Parse(context.Background(), []byte(`{"results":[]}`))
	require.NoError(t, err)
	assert.EqualValues(t, 2, rep.FingerprintVersion)
}
