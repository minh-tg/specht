package usecase

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

func reportWith(fingerprints ...string) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{}
	for _, fp := range fingerprints {
		nr.Findings = append(nr.Findings, domain.NormalizedFinding{Fingerprint: fp})
	}
	return nr
}

func TestReportHash_UnkeyedScannersKeepTheirPlainHash(t *testing.T) {
	raw := []byte(`{"matches":[]}`)
	sum := sha256.Sum256(raw)
	plain := &mockScanner{name: "plain"}

	assert.Equal(t, hex.EncodeToString(sum[:]), reportHash(plain, raw, reportWith("a", "b"), false),
		"a scanner without a fingerprint key hashes the body alone")
}

func TestReportHash_ReportsThatDifferOnlyInASecretStayDistinct(t *testing.T) {
	// A keyed scanner folds the identities in, so the same body under a rotated key is not a replay.
	redacted := []byte(`[{"RuleID":"generic-api-key","Secret":"[REDACTED]"}]`)
	keyed := &keyedMockScanner{mockScanner{name: "keyed"}}

	first := reportHash(keyed, redacted, reportWith("secret:r:f:digest-one"), false)
	second := reportHash(keyed, redacted, reportWith("secret:r:f:digest-two"), false)
	same := reportHash(keyed, redacted, reportWith("secret:r:f:digest-one"), false)

	assert.NotEqual(t, first, second, "a rotated secret is not a replay")
	assert.Equal(t, first, same, "the same secret is")
}

func TestReportHash_TheOrderOfFindingsDoesNotMatter(t *testing.T) {
	raw := []byte(`[]`)
	keyed := &keyedMockScanner{mockScanner{name: "keyed"}}
	assert.Equal(t, reportHash(keyed, raw, reportWith("a", "b", "c"), false), reportHash(keyed, raw, reportWith("c", "a", "b"), false))
}

func TestReportHash_FindingBoundariesAreNotAmbiguous(t *testing.T) {
	raw := []byte(`[]`)
	keyed := &keyedMockScanner{mockScanner{name: "keyed"}}
	assert.NotEqual(t, reportHash(keyed, raw, reportWith("ab", "c"), false), reportHash(keyed, raw, reportWith("a", "bc"), false))
}

// Every report whose redaction failed is stored as the same placeholder, so the
// bytes cannot tell two of them apart. The finding identities do.
func TestReportHash_RedactionFailedReportsStayDistinct(t *testing.T) {
	placeholder := []byte(scanner.RedactionFailedEvidence)
	plain := &mockScanner{name: "plain"}

	first := reportHash(plain, placeholder, reportWith("dast:t:https://a"), true)
	second := reportHash(plain, placeholder, reportWith("dast:t:https://b"), true)
	same := reportHash(plain, placeholder, reportWith("dast:t:https://a"), true)

	assert.NotEqual(t, first, second, "different findings are not a replay of each other")
	assert.Equal(t, first, same)
	assert.NotEqual(t, first, reportHash(plain, placeholder, reportWith("dast:t:https://a"), false),
		"the failure is part of what was stored")
}
