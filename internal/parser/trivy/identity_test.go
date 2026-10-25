package trivy_test

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/trivy"
)

func parseFile(t *testing.T, path string) *domain.NormalizedReport {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	nr, err := trivy.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	return nr
}

func parseDoc(t *testing.T, doc string) *domain.NormalizedReport {
	t.Helper()
	nr, err := trivy.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	return nr
}

func distinctFingerprints(nr *domain.NormalizedReport) map[string]bool {
	out := map[string]bool{}
	for _, f := range nr.Findings {
		out[f.Fingerprint] = true
	}
	return out
}

func TestEveryFailedResourceIsItsOwnMisconfiguration(t *testing.T) {
	// trivy config on a main.tf with two buckets and two security group rules.
	nr := parseFile(t, "testdata/two-resources-misconfig.json")
	require.Len(t, nr.Findings, 19)
	assert.Len(t, distinctFingerprints(nr), 19, "a check failing on two buckets is two findings")

	var bucketA *domain.NormalizedFinding
	for i := range nr.Findings {
		if nr.Findings[i].Fingerprint == "iac:AWS-0086:aws_s3_bucket.a:main.tf" {
			bucketA = &nr.Findings[i]
		}
	}
	require.NotNil(t, bucketA)
	assert.Equal(t, "aws_s3_bucket.a", bucketA.Resource)
	assert.Equal(t, "main.tf:1", bucketA.Location)
	assert.Contains(t, bucketA.Dimensions, domain.Dimension{Key: domain.DimResource, Value: "aws_s3_bucket.a"})
	require.NotNil(t, bucketA.CodeLocation)
	assert.Equal(t, 3, bucketA.CodeLocation.EndLine)
}

func misconfigDoc(target, resource string, line int) string {
	return `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[{"Target":"` + target +
		`","Class":"config","Type":"terraform","Misconfigurations":[{"ID":"AWS-0086","Severity":"HIGH","CauseMetadata":{"Resource":"` +
		resource + `","StartLine":` + strconv.Itoa(line) + `}}]}]}`
}

func TestAMisconfigurationKeepsItsIdentityWhenItsResourceMoves(t *testing.T) {
	before := parseDoc(t, misconfigDoc("main.tf", "aws_s3_bucket.a", 1))
	after := parseDoc(t, misconfigDoc("main.tf", "aws_s3_bucket.a", 40))
	assert.Equal(t, before.Findings[0].Fingerprint, after.Findings[0].Fingerprint)
}

func TestAMisconfigurationIsBoundToItsFile(t *testing.T) {
	a := parseDoc(t, misconfigDoc("a/main.tf", "aws_s3_bucket.this", 1))
	b := parseDoc(t, misconfigDoc("b/main.tf", "aws_s3_bucket.this", 1))
	assert.NotEqual(t, a.Findings[0].Fingerprint, b.Findings[0].Fingerprint)
}

func TestAMisconfigurationWithoutAResourceFallsBackToTheLine(t *testing.T) {
	nr := parseDoc(t, `{"SchemaVersion":2,"ArtifactName":".","Results":[{"Target":"Dockerfile","Class":"config","Type":"dockerfile","Misconfigurations":[
		{"ID":"DS005","Severity":"LOW","CauseMetadata":{"StartLine":3}},
		{"ID":"DS005","Severity":"LOW","CauseMetadata":{"StartLine":7}}]}]}`)
	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
}

func TestEverySecretOfOneRuleInOneFileIsItsOwnFinding(t *testing.T) {
	// trivy fs on a cred.env with two GitHub tokens on lines 1 and 2.
	nr := parseFile(t, "testdata/two-secrets.json")
	require.Len(t, nr.Findings, 2)
	assert.Equal(t, "secret:github-pat:cred.env:1", nr.Findings[0].Fingerprint)
	assert.Equal(t, "secret:github-pat:cred.env:2", nr.Findings[1].Fingerprint)
	assert.Equal(t, "cred.env:2", nr.Findings[1].Location)
	assert.Contains(t, nr.Findings[1].Dimensions, domain.Dimension{Key: domain.DimLine, Value: "2"})
	require.NotNil(t, nr.Findings[1].CodeLocation)
	assert.Equal(t, 2, nr.Findings[1].CodeLocation.StartLine)
}

func TestTheScannerSaysItsIdentitiesChanged(t *testing.T) {
	assert.EqualValues(t, 2, trivy.NewScanner().Descriptor().FingerprintVersion)
	assert.EqualValues(t, 2, parseFile(t, "testdata/two-secrets.json").FingerprintVersion)
}
