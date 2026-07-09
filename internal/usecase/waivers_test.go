package usecase

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/repo"
)

func uuidFromString(s string) pgtype.UUID {
	var id pgtype.UUID
	id.Scan(s)
	return id
}

func makeFindingWithID(id int) sqlc.Finding {
	return sqlc.Finding{
		ID: uuidFromString(fmt.Sprintf("00000000-0000-0000-0000-0000000000%02d", id)),
	}
}

func TestMatchContexts(t *testing.T) {
	envA := uuidFromString("00000000-0000-0000-0000-0000000000a1")
	envB := uuidFromString("00000000-0000-0000-0000-0000000000b1")
	tgtA := uuidFromString("00000000-0000-0000-0000-0000000000c1")
	artA := uuidFromString("00000000-0000-0000-0000-0000000000d1")

	tests := []struct {
		name     string
		ctx      findingContext
		contexts []sqlc.WaiverContext
		want     bool
	}{
		{
			name:     "empty contexts",
			ctx:      findingContext{},
			contexts: nil,
			want:     true,
		},
		{
			name: "single context environment match",
			ctx:  findingContext{environmentID: envA},
			contexts: []sqlc.WaiverContext{
				{EnvironmentID: pgtype.UUID{Bytes: envA.Bytes, Valid: true}},
			},
			want: true,
		},
		{
			name: "single context environment mismatch",
			ctx:  findingContext{environmentID: envA},
			contexts: []sqlc.WaiverContext{
				{EnvironmentID: pgtype.UUID{Bytes: envB.Bytes, Valid: true}},
			},
			want: false,
		},
		{
			name: "single context target match",
			ctx:  findingContext{targetID: tgtA},
			contexts: []sqlc.WaiverContext{
				{TargetID: pgtype.UUID{Bytes: tgtA.Bytes, Valid: true}},
			},
			want: true,
		},
		{
			name: "single context artifact match",
			ctx:  findingContext{artifactID: artA},
			contexts: []sqlc.WaiverContext{
				{ArtifactID: pgtype.UUID{Bytes: artA.Bytes, Valid: true}},
			},
			want: true,
		},
		{
			name: "multiple contexts all match",
			ctx:  findingContext{environmentID: envA, targetID: tgtA},
			contexts: []sqlc.WaiverContext{
				{EnvironmentID: pgtype.UUID{Bytes: envA.Bytes, Valid: true}},
				{TargetID: pgtype.UUID{Bytes: tgtA.Bytes, Valid: true}},
			},
			want: true,
		},
		{
			name: "multiple contexts one mismatches",
			ctx:  findingContext{environmentID: envA, targetID: tgtA},
			contexts: []sqlc.WaiverContext{
				{EnvironmentID: pgtype.UUID{Bytes: envA.Bytes, Valid: true}},
				{TargetID: pgtype.UUID{Bytes: envB.Bytes, Valid: true}},
			},
			want: false,
		},
		{
			name: "context with unset field skips check",
			ctx:  findingContext{environmentID: envA},
			contexts: []sqlc.WaiverContext{
				{EnvironmentID: pgtype.UUID{Bytes: envA.Bytes, Valid: true}, TargetID: pgtype.UUID{Valid: false}},
			},
			want: true,
		},
		{
			name: "finding has no context but waiver requires it",
			ctx:  findingContext{},
			contexts: []sqlc.WaiverContext{
				{EnvironmentID: pgtype.UUID{Bytes: envA.Bytes, Valid: true}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchContexts(tt.ctx, tt.contexts)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchTargets(t *testing.T) {
	finding := makeFindingWithID(1)
	otherID := uuidFromString("00000000-0000-0000-0000-000000000022")

	tests := []struct {
		name    string
		targets []sqlc.WaiverFindingTarget
		want    bool
	}{
		{
			name:    "empty targets returns false",
			targets: nil,
			want:    false,
		},
		{
			name: "matching target returns true",
			targets: []sqlc.WaiverFindingTarget{
				{FindingID: pgtype.UUID{Bytes: finding.ID.Bytes, Valid: true}},
			},
			want: true,
		},
		{
			name: "non-matching target returns false",
			targets: []sqlc.WaiverFindingTarget{
				{FindingID: pgtype.UUID{Bytes: otherID.Bytes, Valid: true}},
			},
			want: false,
		},
		{
			name: "multiple targets one matches",
			targets: []sqlc.WaiverFindingTarget{
				{FindingID: pgtype.UUID{Bytes: otherID.Bytes, Valid: true}},
				{FindingID: pgtype.UUID{Bytes: finding.ID.Bytes, Valid: true}},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchTargets(finding, tt.targets)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchContexts_NoEnvironment(t *testing.T) {
	fctx := findingContext{}

	envA := uuidFromString("00000000-0000-0000-0000-0000000000a1")
	contexts := []sqlc.WaiverContext{
		{EnvironmentID: pgtype.UUID{Bytes: envA.Bytes, Valid: true}},
	}

	assert.False(t, matchContexts(fctx, contexts), "finding with no context should not match waiver context")
	assert.True(t, matchContexts(fctx, nil), "empty contexts should match even without finding context")
}

func TestMatchContexts_ReuseLastInstance(t *testing.T) {
	envID := pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Valid: true}
	tgtID := pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Valid: true}
	artID := pgtype.UUID{Bytes: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}, Valid: true}

	fc := repo.FindingContext{
		EnvironmentID: envID,
		TargetID:      tgtID,
		ArtifactID:    artID,
	}

	fctx := findContextFromRepo(fc)
	assert.Equal(t, envID.Bytes, fctx.environmentID.Bytes)
	assert.Equal(t, tgtID.Bytes, fctx.targetID.Bytes)
	assert.Equal(t, artID.Bytes, fctx.artifactID.Bytes)
}
