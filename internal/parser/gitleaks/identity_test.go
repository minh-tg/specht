package gitleaks_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/gitleaks"
	"github.com/minh-tg/specht/internal/scanner"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func withKey(key []byte) context.Context {
	return scanner.WithFingerprintKey(context.Background(), key)
}

func parseDoc(t *testing.T, ctx context.Context, doc string) *domain.NormalizedReport {
	t.Helper()
	nr, err := gitleaks.NewScanner().Parse(ctx, []byte(doc))
	require.NoError(t, err)
	return nr
}

// leak builds one Gitleaks entry.
func leak(rule, file, secret string, line int, commit string) string {
	b, _ := json.Marshal(map[string]any{
		"RuleID": rule, "File": file, "Secret": secret, "Match": "KEY=" + secret, "StartLine": line, "EndLine": line,
		"Commit": commit, "Fingerprint": commit + ":" + file + ":" + rule + ":" + string(rune('0'+line%10)),
	})
	return string(b)
}

func list(entries ...string) string { return "[" + strings.Join(entries, ",") + "]" }

func TestTwoSecretsOfOneRuleInOneFileAreTwoFindings(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks-two-secrets.json")
	require.NoError(t, err)
	nr, err := gitleaks.NewScanner().Parse(withKey(testKey), data)
	require.NoError(t, err)

	require.Len(t, nr.Findings, 2, "a .env with two keys is two findings, not one")
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
	for _, f := range nr.Findings {
		assert.True(t, strings.HasPrefix(f.Fingerprint, "secret:generic-api-key:config.env:"), f.Fingerprint)
		assert.Equal(t, "secret", f.Extensions["identity_basis"])
	}
}

func TestAFindingKeepsItsIdentityWhenItsLineMoves(t *testing.T) {
	before := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "a.env", "value-one", 2, "c1")))
	after := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "a.env", "value-one", 40, "c2")))
	assert.Equal(t, before.Findings[0].Fingerprint, after.Findings[0].Fingerprint,
		"the same secret in the same file is the same finding after an edit above it or in a later commit")
}

func TestTheSameSecretInManyCommitsIsOneFinding(t *testing.T) {
	nr := parseDoc(t, withKey(testKey), list(
		leak("generic-api-key", "a.env", "value-one", 2, "c1"),
		leak("generic-api-key", "a.env", "value-one", 2, "c2"),
		leak("generic-api-key", "a.env", "value-one", 5, "c3"),
	))
	fingerprints := map[string]bool{}
	for _, f := range nr.Findings {
		fingerprints[f.Fingerprint] = true
	}
	assert.Len(t, fingerprints, 1, "a history scan that sees one secret three times reports one secret")
}

func TestARotatedSecretIsANewFinding(t *testing.T) {
	old := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "a.env", "value-one", 2, "c1")))
	rotated := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "a.env", "value-two", 2, "c2")))
	assert.NotEqual(t, old.Findings[0].Fingerprint, rotated.Findings[0].Fingerprint)
}

func TestIdentityIsBoundToTheRuleAndTheFile(t *testing.T) {
	a := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "a.env", "same", 2, "c1")))
	otherFile := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "b.env", "same", 2, "c1")))
	otherRule := parseDoc(t, withKey(testKey), list(leak("aws-access-token", "a.env", "same", 2, "c1")))
	assert.NotEqual(t, a.Findings[0].Fingerprint, otherFile.Findings[0].Fingerprint)
	assert.NotEqual(t, a.Findings[0].Fingerprint, otherRule.Findings[0].Fingerprint)
}

func TestTheKeyDecidesTheIdentity(t *testing.T) {
	doc := list(leak("generic-api-key", "a.env", "value-one", 2, "c1"))
	one := parseDoc(t, withKey(testKey), doc)
	same := parseDoc(t, withKey(testKey), doc)
	other := parseDoc(t, withKey([]byte("fedcba9876543210fedcba9876543210")), doc)
	assert.Equal(t, one.Findings[0].Fingerprint, same.Findings[0].Fingerprint, "the same key gives the same identity")
	assert.NotEqual(t, one.Findings[0].Fingerprint, other.Findings[0].Fingerprint,
		"without the key the identity cannot be recomputed from a guess")
}

func TestTheSecretNeverLeavesTheParser(t *testing.T) {
	secret := "value-one-that-must-not-leak"
	nr := parseDoc(t, withKey(testKey), list(leak("generic-api-key", "a.env", secret, 2, "c1")))
	out, err := json.Marshal(nr)
	require.NoError(t, err)
	assert.NotContains(t, string(out), secret)
	assert.NotContains(t, string(out), "KEY=")
}

func TestASecretWithoutAKeyIsRefusedNotWeakened(t *testing.T) {
	_, err := gitleaks.NewScanner().Parse(context.Background(), []byte(list(leak("generic-api-key", "a.env", "value-one", 2, "c1"))))
	require.ErrorIs(t, err, scanner.ErrFingerprintKeyRequired)
}

func TestACleanReportNeedsNoKey(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(context.Background(), []byte(`[]`))
	require.NoError(t, err)
	assert.Empty(t, nr.Findings)
}

func TestARedactedReportFallsBackToGitleaksOwnFingerprint(t *testing.T) {
	// gitleaks --redact replaces the secret, so two keys look alike. Its own fingerprint (commit,
	// file, rule, line) still tells them apart, with no key needed.
	nr, err := gitleaks.NewScanner().Parse(context.Background(), []byte(`[
		{"RuleID":"generic-api-key","File":"a.env","Secret":"REDACTED","Match":"REDACTED","StartLine":2,"Fingerprint":"c1:a.env:generic-api-key:2"},
		{"RuleID":"generic-api-key","File":"a.env","Secret":"REDACTED","Match":"REDACTED","StartLine":3,"Fingerprint":"c1:a.env:generic-api-key:3"}]`))
	require.NoError(t, err)
	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
	assert.Equal(t, "fingerprint", nr.Findings[0].Extensions["identity_basis"])
}

func TestSpechtsOwnRedactionMarkerIsNotHashedEither(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(context.Background(), []byte(`[
		{"RuleID":"generic-api-key","File":"a.env","Secret":"[REDACTED]","StartLine":2,"Fingerprint":"c1:a.env:generic-api-key:2"},
		{"RuleID":"generic-api-key","File":"a.env","Secret":"[REDACTED]","StartLine":3,"Fingerprint":"c1:a.env:generic-api-key:3"}]`))
	require.NoError(t, err)
	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint,
		"stored evidence that is parsed again must not collapse every secret into one")
}

func TestWithNothingElseToGoOnTheLineTellsFindingsApart(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(context.Background(), []byte(`[
		{"RuleID":"generic-api-key","File":"a.env","StartLine":2},{"RuleID":"generic-api-key","File":"a.env","StartLine":3}]`))
	require.NoError(t, err)
	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
	assert.Equal(t, "line", nr.Findings[0].Extensions["identity_basis"])
}

func TestTheScannerAsksForTheKeyAndSaysItsIdentitiesChanged(t *testing.T) {
	s := gitleaks.NewScanner()
	assert.True(t, s.UsesFingerprintKey())
	assert.EqualValues(t, 3, s.Descriptor().FingerprintVersion)
	assert.EqualValues(t, 3, parseDoc(t, withKey(testKey), `[]`).FingerprintVersion)
}
