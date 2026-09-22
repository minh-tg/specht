package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/policy"
	"github.com/xMinhx/specht/internal/port"
)

// ErrPolicyConflict is returned when a template name is already taken.
// Callers map it to a client error (409).
var ErrPolicyConflict = errors.New("policy template conflict")

// ErrPolicyNotFound is returned when a template does not exist.
var ErrPolicyNotFound = errors.New("policy template not found")

// PolicyTemplateResponse is the API representation of a template.
type PolicyTemplateResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Definition  map[string]string `json:"definition"`
	Version     int32             `json:"version"`
}

// PolicyEffectiveResponse is one project's resolved policy with provenance.
type PolicyEffectiveResponse struct {
	TemplateName    *string `json:"template_name"`
	TemplateVersion int     `json:"template_version"`
	SeverityFloor   string  `json:"severity_floor"`
	SeveritySource  string  `json:"severity_source"`
	WatcherGate     string  `json:"watcher_gate"`
	WatcherSource   string  `json:"watcher_source"`
}

// CreatePolicyTemplate validates and stores a reusable baseline. Names are
// unique: a duplicate fails with ErrPolicyConflict instead of a raw
// constraint violation.
func (u *Usecases) CreatePolicyTemplate(ctx context.Context, name, description string, definition json.RawMessage) (*PolicyTemplateResponse, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("template name is required")
	}
	def, err := policy.ParseDefinition(definition)
	if err != nil {
		return nil, err
	}
	if _, err := u.deps.Stores.Policy.GetTemplateByName(ctx, name); err == nil {
		return nil, fmt.Errorf("%w: %q", ErrPolicyConflict, name)
	} else if !errors.Is(err, port.ErrNotFound) {
		return nil, fmt.Errorf("lookup template: %w", err)
	}
	t, err := u.deps.Stores.Policy.CreateTemplate(ctx, port.PolicyTemplateInput{
		Name: name, Description: description, Definition: mustMarshal(def),
	})
	if err != nil {
		return nil, fmt.Errorf("create template: %w", err)
	}
	return toPolicyTemplate(t, def), nil
}

// ListPolicyTemplates returns every baseline in name order.
func (u *Usecases) ListPolicyTemplates(ctx context.Context) ([]PolicyTemplateResponse, error) {
	templates, err := u.deps.Stores.Policy.ListTemplates(ctx)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	out := make([]PolicyTemplateResponse, len(templates))
	for i, t := range templates {
		def, err := policy.ParseDefinition(t.Definition)
		if err != nil {
			return nil, fmt.Errorf("stored template %q is invalid: %w", t.Name, err)
		}
		out[i] = *toPolicyTemplate(t, def)
	}
	return out, nil
}

// UpdatePolicyTemplate replaces a baseline's definition (version bumps in
// storage so consumers can tell the baseline moved). Renames conflict with
// other templates.
func (u *Usecases) UpdatePolicyTemplate(ctx context.Context, id, name, description string, definition json.RawMessage) (*PolicyTemplateResponse, error) {
	if _, err := validID(id); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("template name is required")
	}
	def, err := policy.ParseDefinition(definition)
	if err != nil {
		return nil, err
	}
	existing, err := u.deps.Stores.Policy.GetTemplateByID(ctx, id)
	if err != nil {
		return nil, notFoundAsPolicy(err)
	}
	if existing.Name != name {
		if other, err := u.deps.Stores.Policy.GetTemplateByName(ctx, name); err == nil && other.ID != id {
			return nil, fmt.Errorf("%w: %q", ErrPolicyConflict, name)
		} else if err != nil && !errors.Is(err, port.ErrNotFound) {
			return nil, fmt.Errorf("lookup template: %w", err)
		}
	}
	updated, err := u.deps.Stores.Policy.UpdateTemplate(ctx, id, port.PolicyTemplateInput{
		Name: name, Description: description, Definition: mustMarshal(def),
	})
	if err != nil {
		return nil, fmt.Errorf("update template: %w", err)
	}
	return toPolicyTemplate(updated, def), nil
}

// DeletePolicyTemplate removes a baseline; linked projects keep their
// overrides and fall back to defaults (FK SET NULL).
func (u *Usecases) DeletePolicyTemplate(ctx context.Context, id string) error {
	if _, err := validID(id); err != nil {
		return err
	}
	if _, err := u.deps.Stores.Policy.GetTemplateByID(ctx, id); err != nil {
		return notFoundAsPolicy(err)
	}
	if err := u.deps.Stores.Policy.DeleteTemplate(ctx, id); err != nil {
		return fmt.Errorf("delete template: %w", err)
	}
	return nil
}

// SetProjectPolicy links a project to a baseline by name, or unlinks with
// an empty name. Project admins own the assignment (same gate as member
// management).
func (u *Usecases) SetProjectPolicy(ctx context.Context, projectSlug, templateName string) (*PolicyEffectiveResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	var templateID *string
	if strings.TrimSpace(templateName) != "" {
		t, err := u.deps.Stores.Policy.GetTemplateByName(ctx, strings.TrimSpace(templateName))
		if err != nil {
			return nil, notFoundAsPolicy(err)
		}
		templateID = &t.ID
	}
	updated, err := u.deps.Stores.Policy.SetProjectTemplate(ctx, project.ID, templateID)
	if err != nil {
		return nil, fmt.Errorf("assign template: %w", err)
	}
	return u.effectivePolicy(ctx, updated)
}

// SetProjectPolicyOverrides replaces a project's per-key overrides. An
// empty map clears overrides. Keys and values validate like templates.
func (u *Usecases) SetProjectPolicyOverrides(ctx context.Context, projectSlug string, overrides map[string]string) (*PolicyEffectiveResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	normalized := make(map[string]string, len(overrides))
	for k, v := range overrides {
		normalized[k] = v
	}
	if _, err := policy.ParseDefinition(mustMarshal(normalized)); err != nil {
		return nil, err
	}
	merged, err := projectSettingsWithPolicy(project.Settings, normalized)
	if err != nil {
		return nil, err
	}
	updated, err := u.deps.Stores.Projects.UpdateSettings(ctx, project.ID, merged)
	if err != nil {
		return nil, fmt.Errorf("store overrides: %w", err)
	}
	return u.effectivePolicy(ctx, updated)
}

// EffectivePolicy resolves one project's policy with provenance.
func (u *Usecases) EffectivePolicy(ctx context.Context, projectSlug string) (*PolicyEffectiveResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	return u.effectivePolicy(ctx, project)
}

func (u *Usecases) effectivePolicy(ctx context.Context, project port.Project) (*PolicyEffectiveResponse, error) {
	overrides, err := projectPolicyOverrides(project.Settings)
	if err != nil {
		return nil, err
	}
	// A nil policy store (unit-test doubles that predate templates) skips
	// the template lookup; overrides still apply. Production always wires
	// the store.
	if u.deps.Stores.Policy == nil {
		eff := policy.Resolve(nil, 0, nil, overrides)
		return &PolicyEffectiveResponse{
			SeverityFloor: eff.SeverityFloor, SeveritySource: eff.SeveritySource,
			WatcherGate: eff.WatcherGate, WatcherSource: eff.WatcherSource,
		}, nil
	}
	var name *string
	version := 0
	templateDef := map[string]string{}
	if project.PolicyTemplateID != nil {
		t, err := u.deps.Stores.Policy.GetTemplateByID(ctx, *project.PolicyTemplateID)
		if err != nil {
			return nil, fmt.Errorf("lookup project template: %w", err)
		}
		def, err := policy.ParseDefinition(t.Definition)
		if err != nil {
			return nil, fmt.Errorf("stored template %q is invalid: %w", t.Name, err)
		}
		name = &t.Name
		version = int(t.Version)
		templateDef = def
	}
	eff := policy.Resolve(name, version, templateDef, overrides)
	return &PolicyEffectiveResponse{
		TemplateName: eff.TemplateName, TemplateVersion: eff.TemplateVersion,
		SeverityFloor: eff.SeverityFloor, SeveritySource: eff.SeveritySource,
		WatcherGate: eff.WatcherGate, WatcherSource: eff.WatcherSource,
	}, nil
}

// projectPolicyOverrides extracts the namespaced overrides from project
// settings. Absent or malformed policy sections yield no overrides —
// except malformed JSON outright, which fails loudly rather than silently
// dropping enforcement-relevant configuration.
func projectPolicyOverrides(settings json.RawMessage) (map[string]string, error) {
	if len(settings) == 0 {
		return map[string]string{}, nil
	}
	var doc struct {
		Policy map[string]string `json:"policy"`
	}
	if err := json.Unmarshal(settings, &doc); err != nil {
		return nil, fmt.Errorf("invalid project settings: %w", err)
	}
	if doc.Policy == nil {
		return map[string]string{}, nil
	}
	if _, err := policy.ParseDefinition(mustMarshal(doc.Policy)); err != nil {
		return nil, fmt.Errorf("invalid project policy overrides: %w", err)
	}
	return doc.Policy, nil
}

// projectSettingsWithPolicy merges overrides into the settings document,
// preserving every other namespace. A settings document that fails to
// decode errors out: silently replacing it would drop
// enforcement-relevant configuration. (PostgreSQL JSONB always holds valid
// JSON, so this path triggers only on driver-level corruption.)
func projectSettingsWithPolicy(settings json.RawMessage, overrides map[string]string) (json.RawMessage, error) {
	var doc map[string]any
	if len(settings) > 0 {
		if err := json.Unmarshal(settings, &doc); err != nil {
			return nil, fmt.Errorf("invalid project settings: %w", err)
		}
	}
	if doc == nil {
		doc = map[string]any{}
	}
	if len(overrides) == 0 {
		delete(doc, "policy")
	} else {
		doc["policy"] = overrides
	}
	return mustMarshal(doc), nil
}

func toPolicyTemplate(t port.PolicyTemplate, def map[string]string) *PolicyTemplateResponse {
	return &PolicyTemplateResponse{
		ID: t.ID, Name: t.Name, Description: t.Description,
		Definition: def, Version: t.Version,
	}
}

func notFoundAsPolicy(err error) error {
	if errors.Is(err, port.ErrNotFound) {
		return ErrPolicyNotFound
	}
	return err
}

// effectiveSeverityFloor resolves the gate floor: an explicit caller
// severity wins, otherwise the project's effective policy applies.
func (u *Usecases) effectiveSeverityFloor(ctx context.Context, project port.Project, explicit []string) int16 {
	if len(explicit) > 0 {
		return gateSeverityRank(explicit, nil)
	}
	eff, err := u.effectivePolicy(ctx, project)
	if err != nil {
		return gateSeverityRank(nil, nil)
	}
	return policy.SeverityRank(eff.SeverityFloor)
}
