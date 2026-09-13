package patch

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPropose_DependencyBump(t *testing.T) {
	out := Propose(Input{
		FindingID: "f1", FindingKind: "sca", Title: "CVE-2024-1",
		Dims: map[string]string{
			"package_name": "lodash", "installed_version": "4.17.20",
			"fixed_version": "4.17.21", "file": "package.json",
		},
		Tool: "trivy", ReportID: "r1", CommitSha: "abc123",
	})
	require.True(t, out.Supported)
	require.NotNil(t, out.Proposal)
	p := out.Proposal
	assert.Equal(t, ClassDependencyBump, p.Class)
	assert.Equal(t, ApplyModeManual, p.ApplyMode, "proposals never self-apply")
	require.Len(t, p.Edits, 1)
	assert.Equal(t, "package.json", p.Edits[0].File)
	assert.Equal(t, "set-dependency-version", p.Edits[0].Operation)
	assert.Equal(t, "4.17.20", p.Edits[0].FromVersion)
	assert.Equal(t, "4.17.21", p.Edits[0].ToVersion)
	assert.Equal(t, "r1", p.Evidence.ReportID)
	assert.Equal(t, "trivy", p.Evidence.Scanner)
	assert.Contains(t, p.VerifyBy, "rescan")

	again := Propose(Input{
		FindingID: "f1", FindingKind: "sca", Title: "CVE-2024-1",
		Dims: map[string]string{
			"package_name": "lodash", "installed_version": "4.17.20",
			"fixed_version": "4.17.21", "file": "package.json",
		},
		Tool: "trivy", ReportID: "r1", CommitSha: "abc123",
	})
	assert.Equal(t, p.ID, again.Proposal.ID, "identical evidence reproduces the identical proposal")
}

func TestPropose_SecretRefused(t *testing.T) {
	out := Propose(Input{
		FindingID: "f1", FindingKind: "secret", Title: "AWS key",
		Dims: map[string]string{"file": "config.env"}, Tool: "gitleaks",
	})
	assert.False(t, out.Supported)
	assert.Nil(t, out.Proposal, "refusals produce no partial patch")
	assert.Contains(t, out.Reason, "never auto-patched")
}

func TestPropose_SastWithoutExactChangeRefused(t *testing.T) {
	out := Propose(Input{
		FindingID: "f1", FindingKind: "sast", Title: "XSS",
		Dims: map[string]string{"file": "app.go"}, Tool: "semgrep",
	})
	assert.False(t, out.Supported)
	assert.Nil(t, out.Proposal)
}

func TestPropose_MissingFixedVersionRefused(t *testing.T) {
	out := Propose(Input{
		FindingID: "f1", FindingKind: "sca", Title: "CVE-2024-1",
		Dims: map[string]string{"package_name": "lodash"}, Tool: "trivy",
	})
	assert.False(t, out.Supported)
	assert.Nil(t, out.Proposal)
}
