package usecase

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateIngestInputPreservesBranchCase(t *testing.T) {
	in, err := validateIngestInput(IngestReportInput{
		ProjectSlug:  "p",
		Scanner:      "trivy",
		RawData:      json.RawMessage(`{}`),
		ScanMode:     ScanModeIncremental,
		BaseRevision: "Feature/Foo",
		CommitSha:    "ABC123",
	})
	require.NoError(t, err)
	require.Equal(t, "Feature/Foo", in.BaseRevision)
	require.Equal(t, "abc123", in.CommitSha)
}

func TestValidateIngestInputRejectsTheSameCommitInDifferentCase(t *testing.T) {
	_, err := validateIngestInput(IngestReportInput{
		ProjectSlug:  "p",
		Scanner:      "trivy",
		RawData:      json.RawMessage(`{}`),
		ScanMode:     ScanModeIncremental,
		BaseRevision: "A1B2C3D4E5",
		CommitSha:    "a1b2c3d4e5",
	})
	require.Error(t, err)
}
