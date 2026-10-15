package usecase

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/minh-tg/specht/internal/port"
)

// ErrInvalidEnvironment is returned when an environment edit names a tier or
// a data sensitivity outside the stored vocabulary. Handlers map it to a 400.
var ErrInvalidEnvironment = errors.New("invalid environment settings")

// ErrEnvironmentNotFound is returned when the environment does not exist in
// the project, including an id that is not a UUID. Handlers map it to a 404.
var ErrEnvironmentNotFound = errors.New("environment not found")

var (
	environmentTiers       = []string{"production", "staging", "development", "test"}
	environmentSensitivity = []string{"public", "internal", "confidential", "restricted"}
)

// UpdateEnvironmentInput carries the three settings of one environment. All
// three are required: the request replaces them.
type UpdateEnvironmentInput struct {
	ProjectSlug     string
	EnvironmentID   string
	Tier            string
	InternetFacing  bool
	DataSensitivity string
}

// UpdateEnvironment changes how a project's environment is classified. It is
// gated like the other project settings: a project admin or a global admin.
func (u *Usecases) UpdateEnvironment(ctx context.Context, in UpdateEnvironmentInput) (*EnvironmentResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, in.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, in.ProjectSlug, err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	if !slices.Contains(environmentTiers, in.Tier) || !slices.Contains(environmentSensitivity, in.DataSensitivity) {
		return nil, ErrInvalidEnvironment
	}
	id, err := uuid.Parse(in.EnvironmentID)
	if err != nil {
		return nil, ErrEnvironmentNotFound
	}
	updated, err := u.deps.Stores.Environments.Update(ctx, id.String(), project.ID, in.Tier, in.InternetFacing, in.DataSensitivity)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrEnvironmentNotFound
		}
		return nil, fmt.Errorf("update environment: %w", err)
	}
	resp := toEnvironment(updated)
	return &resp, nil
}
