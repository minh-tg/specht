package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/domain"
)

func TestCanonicalDimensionKeys(t *testing.T) {
	keys := []string{
		domain.DimVulnerabilityID,
		domain.DimAlias,
		domain.DimPURL,
		domain.DimPackageName,
		domain.DimEcosystem,
		domain.DimInstalledVer,
		domain.DimFixedVersion,
		domain.DimRuleID,
		domain.DimFile,
		domain.DimLine,
		domain.DimResource,
		domain.DimSource,
	}
	want := []string{
		"vulnerability_id", "alias", "purl", "package_name", "ecosystem",
		"installed_version", "fixed_version", "rule_id", "file", "line",
		"resource", "source",
	}
	assert.Equal(t, want, keys, "canonical dimension keys must use the persisted snake_case vocabulary")
}

func TestDimensionCanBeConstructed(t *testing.T) {
	d := domain.Dimension{Key: domain.DimVulnerabilityID, Value: "CVE-2026-1234"}
	assert.Equal(t, "vulnerability_id", d.Key)
	assert.Equal(t, "CVE-2026-1234", d.Value)
}

func TestReachabilityStateValues(t *testing.T) {
	assert.Equal(t, "reachable", string(domain.ReachabilityReachable))
	assert.Equal(t, "not_reachable", string(domain.ReachabilityNotReachable))
	assert.Equal(t, "unknown", string(domain.ReachabilityUnknown))
	assert.Equal(t, "not_applicable", string(domain.ReachabilityNotApplicable))
}

func TestValidReachabilityState(t *testing.T) {
	assert.True(t, domain.ValidReachabilityState(domain.ReachabilityReachable))
	assert.True(t, domain.ValidReachabilityState(domain.ReachabilityNotReachable))
	assert.True(t, domain.ValidReachabilityState(domain.ReachabilityUnknown))
	assert.True(t, domain.ValidReachabilityState(domain.ReachabilityNotApplicable))
	assert.False(t, domain.ValidReachabilityState(""))
	assert.False(t, domain.ValidReachabilityState("exploitable"))
	assert.False(t, domain.ValidReachabilityState("true"))
	assert.False(t, domain.ValidReachabilityState("reachable-ish"))
}

func TestNormalizeReachabilityState(t *testing.T) {
	assert.Equal(t, domain.ReachabilityReachable, domain.NormalizeReachabilityState(domain.ReachabilityReachable))
	assert.Equal(t, domain.ReachabilityUnknown, domain.NormalizeReachabilityState(""))
	assert.Equal(t, domain.ReachabilityUnknown, domain.NormalizeReachabilityState("garbage"))
}

func TestReachabilityHintIsObservationOnly(t *testing.T) {
	// A hint carries state/evidence/source; it is never treated as an
	// authoritative assessment by the core.
	h := domain.ReachabilityHint{
		State:    domain.ReachabilityNotReachable,
		Evidence: "no call path to the sink",
		Source:   "osv",
	}
	assert.Equal(t, domain.ReachabilityNotReachable, h.State)
	assert.NotEmpty(t, h.Evidence)
	assert.Equal(t, "osv", h.Source)
}

func TestFingerprintVersionsAreNumeric(t *testing.T) {
	assert.Equal(t, uint16(1), uint16(domain.FingerprintVersion(1)))
	assert.Equal(t, uint16(1), uint16(domain.ContractVersion(1)))
}

func TestSCAFingerprintVersion1(t *testing.T) {
	// Version-1 fingerprint formula: vulnID + ":" + normalized purl. It must
	// not change so existing finding rows and waivers do not fork.
	assert.Equal(t, "CVE-2024-1234:pkg:npm/foo@1.0.0", string(domain.SCAFingerprint("CVE-2024-1234", "pkg:npm/foo@1.0.0")))
}

func TestCanonicalVulnID(t *testing.T) {
	assert.Equal(t, "CVE-2024-1234", domain.CanonicalVulnID("cve-2024-1234", nil))
	assert.Equal(t, "CVE-2024-1234", domain.CanonicalVulnID("GHSA-xxxx-yyyy", []string{"cve-2024-1234", "PYSEC-2024-1"}))
	assert.Equal(t, "GHSA-xxxx-yyyy", domain.CanonicalVulnID("GHSA-xxxx-yyyy", []string{"OSV-123"}))
}
