package checkov

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPassedChecksBecomeExaminedFingerprints(t *testing.T) {
	doc := `{"check_type":"terraform","results":{
	  "passed_checks":[{"check_id":"CKV_AWS_18","resource":"aws_s3_bucket.a","file_path":"/main.tf"},{"check_id":"","resource":"x","file_path":"/x.tf"}],
	  "failed_checks":[{"check_id":"CKV_AWS_19","resource":"aws_s3_bucket.a","file_path":"/main.tf","check_name":"n"}],
	  "skipped_checks":[{"check_id":"CKV_AWS_20","resource":"aws_s3_bucket.a","file_path":"/main.tf"}]},
	  "summary":{"passed":1,"failed":1}}`
	nr, err := NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	require.Len(t, nr.Findings, 1)
	assert.Equal(t, []string{"fp:iac:CKV_AWS_18:aws_s3_bucket.a:/main.tf"}, nr.ExaminedKeys,
		"only the passed check with an id counts, a skipped one proves nothing")
}

func TestPassedCheckFingerprintMatchesAFailedOne(t *testing.T) {
	failed := `{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_X","resource":"r.a","file_path":"/m.tf","check_name":"n"}]}}`
	passed := `{"check_type":"terraform","results":{"passed_checks":[{"check_id":"CKV_X","resource":"r.a","file_path":"/m.tf"}]}}`
	f, err := NewScanner().Parse(context.Background(), []byte(failed))
	require.NoError(t, err)
	p, err := NewScanner().Parse(context.Background(), []byte(passed))
	require.NoError(t, err)
	assert.Equal(t, []string{"fp:" + f.Findings[0].Fingerprint}, p.ExaminedKeys)
}

func TestQuietReportExaminesNothing(t *testing.T) {
	doc := `{"check_type":"terraform","results":{"failed_checks":[{"check_id":"CKV_X","resource":"r.a","file_path":"/m.tf"}]}}`
	nr, err := NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	assert.Empty(t, nr.ExaminedKeys)
}

func TestMultiFrameworkReportMergesPassedChecks(t *testing.T) {
	doc := `[{"check_type":"terraform","results":{"passed_checks":[{"check_id":"A","resource":"r","file_path":"/a.tf"}]}},
	  {"check_type":"kubernetes","results":{"passed_checks":[{"check_id":"B","resource":"d","file_path":"/b.yaml"}]}}]`
	nr, err := NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	assert.Equal(t, []string{"fp:iac:A:r:/a.tf", "fp:iac:B:d:/b.yaml"}, nr.ExaminedKeys)
}
