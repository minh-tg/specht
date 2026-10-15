package usecase

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/domain"
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

	assert.Equal(t, hex.EncodeToString(sum[:]), reportHash(plain, raw, reportWith("a", "b")),
		"existing reports keep the hash they were stored with")
}

func TestReportHash_ReportsThatDifferOnlyInASecretStayDistinct(t *testing.T) {
	// Redaction removes the secrets, so the stored bytes are the same. The identities are not.
	redacted := []byte(`[{"RuleID":"generic-api-key","Secret":"[REDACTED]"}]`)
	keyed := &keyedMockScanner{mockScanner{name: "keyed"}}

	first := reportHash(keyed, redacted, reportWith("secret:r:f:digest-one"))
	second := reportHash(keyed, redacted, reportWith("secret:r:f:digest-two"))
	same := reportHash(keyed, redacted, reportWith("secret:r:f:digest-one"))

	assert.NotEqual(t, first, second, "a rotated secret is not a replay")
	assert.Equal(t, first, same, "the same secret is")
}

func TestReportHash_TheOrderOfFindingsDoesNotMatter(t *testing.T) {
	raw := []byte(`[]`)
	keyed := &keyedMockScanner{mockScanner{name: "keyed"}}
	assert.Equal(t, reportHash(keyed, raw, reportWith("a", "b", "c")), reportHash(keyed, raw, reportWith("c", "a", "b")))
}

func TestReportHash_FindingBoundariesAreNotAmbiguous(t *testing.T) {
	raw := []byte(`[]`)
	keyed := &keyedMockScanner{mockScanner{name: "keyed"}}
	assert.NotEqual(t, reportHash(keyed, raw, reportWith("ab", "c")), reportHash(keyed, raw, reportWith("a", "bc")))
}
