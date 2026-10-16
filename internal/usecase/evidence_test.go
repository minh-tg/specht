package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const deleteEvidenceID = "00000000-0000-0000-0000-000000000031"

// deleteEvidenceFixture wires the two stores DeleteEvidence consults: the
// finding store (the id in the path) and the evidence store.
type deleteEvidenceFixture struct {
	uc       *Usecases
	findings *mockFindingRepo
	evidence *mockEvidenceRepo
	projects *mockProjectRepo
	deleted  []string
}

func newDeleteEvidenceFixture() *deleteEvidenceFixture {
	f := &deleteEvidenceFixture{
		findings: &mockFindingRepo{},
		evidence: &mockEvidenceRepo{},
		projects: &mockProjectRepo{},
	}
	f.evidence.deleteFn = func(_ context.Context, id string) error {
		f.deleted = append(f.deleted, id)
		return nil
	}
	f.uc = New(Deps{Stores: &port.Stores{
		Projects: f.projects, Findings: f.findings, Evidence: f.evidence,
	}})
	return f
}

func deleteEvidenceMemberCtx() context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040",
		Role:   auth.RoleManager,
	})
}

// TestDeleteEvidence_MatchingPairDeletes keeps the happy path: evidence
// addressed through its own finding is deleted.
func TestDeleteEvidence_MatchingPairDeletes(t *testing.T) {
	f := newDeleteEvidenceFixture()
	finding := makeFindingRow(1)
	f.findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return finding, nil
	}
	f.evidence.getByIDFn = func(_ context.Context, id string) (port.Evidence, error) {
		return port.Evidence{ID: id, FindingID: finding.ID}, nil
	}

	err := f.uc.DeleteEvidence(adminCtx(), finding.ID, deleteEvidenceID)
	require.NoError(t, err)
	assert.Equal(t, []string{deleteEvidenceID}, f.deleted)
}

// TestDeleteEvidence_MismatchedFindingIsNotFound covers evidence that belongs
// to another finding: the pair does not exist, so the answer is 404 and
// nothing is deleted.
func TestDeleteEvidence_MismatchedFindingIsNotFound(t *testing.T) {
	f := newDeleteEvidenceFixture()
	pathFinding := makeFindingRow(1)
	otherFinding := makeFindingRow(2)
	f.findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return pathFinding, nil
	}
	f.evidence.getByIDFn = func(_ context.Context, id string) (port.Evidence, error) {
		return port.Evidence{ID: id, FindingID: otherFinding.ID}, nil
	}

	err := f.uc.DeleteEvidence(adminCtx(), pathFinding.ID, deleteEvidenceID)
	require.ErrorIs(t, err, ErrEvidenceNotFound)
	assert.Empty(t, f.deleted, "a mismatched pair must not delete")
}

// TestDeleteEvidence_ForeignEvidenceIsNotFound covers the cross-tenant pair:
// X's finding in the path with Y's evidence id is a pair that does not exist.
func TestDeleteEvidence_ForeignEvidenceIsNotFound(t *testing.T) {
	f := newDeleteEvidenceFixture()
	pathFinding := makeFindingRow(1)
	foreignFinding := makeFindingRow(8)
	foreignFinding.ProjectID = gateForeignProject
	f.findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return pathFinding, nil
	}
	f.evidence.getByIDFn = func(_ context.Context, id string) (port.Evidence, error) {
		return port.Evidence{ID: id, FindingID: foreignFinding.ID}, nil
	}

	err := f.uc.DeleteEvidence(adminCtx(), pathFinding.ID, deleteEvidenceID)
	require.ErrorIs(t, err, ErrEvidenceNotFound)
	assert.Empty(t, f.deleted, "a foreign evidence row must not delete")
}

// TestDeleteEvidence_MissingFindingIsNotFound pins that a finding that does
// not exist answers 404 even for the instance admin, never 204.
func TestDeleteEvidence_MissingFindingIsNotFound(t *testing.T) {
	f := newDeleteEvidenceFixture()
	f.findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	f.evidence.getByIDFn = func(context.Context, string) (port.Evidence, error) {
		t.Fatal("evidence must not be read when the finding in the path is missing")
		return port.Evidence{}, nil
	}

	err := f.uc.DeleteEvidence(adminCtx(), makeFindingRow(1).ID, deleteEvidenceID)
	require.ErrorIs(t, err, ErrFindingNotFound)
	assert.Empty(t, f.deleted)
}

// TestDeleteEvidence_MissingEvidenceIsNotFound covers an evidence id that does
// not exist.
func TestDeleteEvidence_MissingEvidenceIsNotFound(t *testing.T) {
	f := newDeleteEvidenceFixture()
	finding := makeFindingRow(1)
	f.findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return finding, nil
	}
	f.evidence.getByIDFn = func(context.Context, string) (port.Evidence, error) {
		return port.Evidence{}, port.ErrNotFound
	}

	err := f.uc.DeleteEvidence(adminCtx(), finding.ID, deleteEvidenceID)
	require.ErrorIs(t, err, ErrEvidenceNotFound)
	assert.Empty(t, f.deleted)
}

// TestDeleteEvidence_MemberDeniedBeforeEvidenceRead pins the order: the
// finding in the path is authorized first, so a caller without write access
// gets 403 without the evidence row being touched.
func TestDeleteEvidence_MemberDeniedBeforeEvidenceRead(t *testing.T) {
	f := newDeleteEvidenceFixture()
	finding := makeFindingRow(1)
	f.findings.getByIDFn = func(context.Context, string) (port.Finding, error) {
		return finding, nil
	}
	f.projects.effectiveRoleFn = func(context.Context, string, string) (string, error) {
		return auth.RoleMember, nil
	}
	f.evidence.getByIDFn = func(context.Context, string) (port.Evidence, error) {
		t.Fatal("evidence must not be read for a caller without write access")
		return port.Evidence{}, nil
	}

	err := f.uc.DeleteEvidence(deleteEvidenceMemberCtx(), finding.ID, deleteEvidenceID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Empty(t, f.deleted)
}
