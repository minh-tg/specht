package repo

import (
	"context"
	"encoding/json"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgPolicyPort persists policy templates and project assignments directly
// over sqlc.
type pgPolicyPort struct{ q *sqlc.Queries }

func policyRowToPort(t sqlc.PolicyTemplate) port.PolicyTemplate {
	return port.PolicyTemplate{
		ID:          toUUID(t.ID),
		Name:        t.Name,
		Description: t.Description,
		Definition:  rawOrNil(t.Definition),
		Version:     t.Version,
		CreatedAt:   t.CreatedAt.Time,
		UpdatedAt:   t.UpdatedAt.Time,
	}
}

func (r *pgPolicyPort) CreateTemplate(ctx context.Context, input port.PolicyTemplateInput) (port.PolicyTemplate, error) {
	row, err := r.q.CreatePolicyTemplate(ctx, sqlc.CreatePolicyTemplateParams{
		Name:        input.Name,
		Description: input.Description,
		Definition:  definitionOrEmpty(input.Definition),
	})
	if err != nil {
		return port.PolicyTemplate{}, mappingErr(err)
	}
	return policyRowToPort(row), nil
}

func (r *pgPolicyPort) GetTemplateByID(ctx context.Context, id string) (port.PolicyTemplate, error) {
	pid, err := parseID(id)
	if err != nil {
		return port.PolicyTemplate{}, err
	}
	row, err := r.q.GetPolicyTemplateByID(ctx, pid)
	if err != nil {
		return port.PolicyTemplate{}, mappingErr(err)
	}
	return policyRowToPort(row), nil
}

func (r *pgPolicyPort) GetTemplateByName(ctx context.Context, name string) (port.PolicyTemplate, error) {
	row, err := r.q.GetPolicyTemplateByName(ctx, name)
	if err != nil {
		return port.PolicyTemplate{}, mappingErr(err)
	}
	return policyRowToPort(row), nil
}

func (r *pgPolicyPort) ListTemplates(ctx context.Context) ([]port.PolicyTemplate, error) {
	rows, err := r.q.ListPolicyTemplates(ctx)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.PolicyTemplate, len(rows))
	for i, row := range rows {
		out[i] = policyRowToPort(row)
	}
	return out, nil
}

func (r *pgPolicyPort) UpdateTemplate(ctx context.Context, id string, input port.PolicyTemplateInput) (port.PolicyTemplate, error) {
	pid, err := parseID(id)
	if err != nil {
		return port.PolicyTemplate{}, err
	}
	row, err := r.q.UpdatePolicyTemplate(ctx, sqlc.UpdatePolicyTemplateParams{
		ID:          pid,
		Name:        input.Name,
		Description: input.Description,
		Definition:  definitionOrEmpty(input.Definition),
	})
	if err != nil {
		return port.PolicyTemplate{}, mappingErr(err)
	}
	return policyRowToPort(row), nil
}

func (r *pgPolicyPort) DeleteTemplate(ctx context.Context, id string) error {
	pid, err := parseID(id)
	if err != nil {
		return err
	}
	return mappingErr(r.q.DeletePolicyTemplate(ctx, pid))
}

func (r *pgPolicyPort) SetProjectTemplate(ctx context.Context, projectID string, templateID *string) (port.Project, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Project{}, err
	}
	row, err := r.q.SetProjectPolicyTemplate(ctx, sqlc.SetProjectPolicyTemplateParams{
		ID:               pid,
		PolicyTemplateID: uuidPtrFromString(templateID),
	})
	if err != nil {
		return port.Project{}, mappingErr(err)
	}
	return projectToPort(row), nil
}

// definitionOrEmpty encodes a template definition, defaulting to {} so
// the NOT NULL column never sees NULL.
func definitionOrEmpty(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return []byte(raw)
}
