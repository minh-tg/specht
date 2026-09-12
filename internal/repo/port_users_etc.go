package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// pgUserPort adapts UserStore.
type pgUserPort struct{ q *sqlc.Queries }

func (r *pgUserPort) Create(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
	row, err := r.q.CreateUser(ctx, sqlc.CreateUserParams{
		Email:        email,
		DisplayName:  textPtrFromString(displayName),
		PasswordHash: textPtrFromString(passwordHash),
	})
	if err != nil {
		return port.User{}, err
	}
	return userToPort(row), nil
}

func (r *pgUserPort) GetByEmail(ctx context.Context, email string) (port.User, error) {
	row, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return port.User{}, mappingErr(err)
	}
	return userToPort(row), nil
}

func (r *pgUserPort) GetByID(ctx context.Context, id string) (port.User, error) {
	uid, err := parseID(id)
	if err != nil {
		return port.User{}, err
	}
	row, err := r.q.GetUserByID(ctx, uid)
	if err != nil {
		return port.User{}, mappingErr(err)
	}
	return userToPort(row), nil
}

func (r *pgUserPort) SetRole(ctx context.Context, userID, role string) (port.User, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.User{}, err
	}
	row, err := r.q.SetUserRole(ctx, sqlc.SetUserRoleParams{ID: uid, Role: role})
	if err != nil {
		return port.User{}, mappingErr(err)
	}
	return userToPort(row), nil
}

func (r *pgUserPort) UpdateDisplayName(ctx context.Context, userID string, displayName *string) (port.User, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.User{}, err
	}
	row, err := r.q.UpdateUserDisplayName(ctx, sqlc.UpdateUserDisplayNameParams{
		ID:          uid,
		DisplayName: textPtrFromString(displayName),
	})
	if err != nil {
		return port.User{}, mappingErr(err)
	}
	return userToPort(row), nil
}

func userToPort(u sqlc.User) port.User {
	return port.User{
		ID:           toUUID(u.ID),
		Email:        u.Email,
		DisplayName:  stringFromTextPtr(u.DisplayName),
		PasswordHash: strVal(u.PasswordHash),
		Role:         u.Role,
		CreatedAt:    u.CreatedAt.Time,
	}
}

// pgRefreshTokenPort adapts RefreshTokenStore.
type pgRefreshTokenPort struct{ q *sqlc.Queries }

func (r *pgRefreshTokenPort) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.RefreshToken{}, err
	}
	row, err := r.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		UserID:    uid,
		TokenHash: tokenHash,
		ExpiresAt: uuidFromTime(expiresAt),
	})
	if err != nil {
		return port.RefreshToken{}, err
	}
	return refreshTokenToPort(row), nil
}

func (r *pgRefreshTokenPort) GetByHash(ctx context.Context, tokenHash string) (port.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return port.RefreshToken{}, mappingErr(err)
	}
	return refreshTokenToPort(row), nil
}

func (r *pgRefreshTokenPort) Revoke(ctx context.Context, id string) (port.RefreshToken, error) {
	tid, err := parseID(id)
	if err != nil {
		return port.RefreshToken{}, err
	}
	row, err := r.q.RevokeRefreshToken(ctx, tid)
	if err != nil {
		return port.RefreshToken{}, mappingErr(err)
	}
	return refreshTokenToPort(row), nil
}

func (r *pgRefreshTokenPort) RevokeAllForUser(ctx context.Context, userID string) error {
	uid, err := parseID(userID)
	if err != nil {
		return err
	}
	return r.q.RevokeUserRefreshTokens(ctx, uid)
}

func refreshTokenToPort(t sqlc.RefreshToken) port.RefreshToken {
	return port.RefreshToken{
		ID:        toUUID(t.ID),
		UserID:    toUUID(t.UserID),
		TokenHash: t.TokenHash,
		ExpiresAt: t.ExpiresAt.Time,
		RevokedAt: timePtrFromTimestamptz(t.RevokedAt),
	}
}

// pgAPIKeyPort adapts APIKeyStore.
type pgAPIKeyPort struct{ q *sqlc.Queries }

func (r *pgAPIKeyPort) Create(ctx context.Context, input port.CreateAPIKeyInput) (port.APIKey, error) {
	pid, err := parseID(input.ProjectID)
	if err != nil {
		return port.APIKey{}, err
	}
	row, err := r.q.CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
		ProjectID: pid,
		Name:      input.Name,
		KeyPrefix: input.KeyPrefix,
		KeyHash:   input.KeyHash,
		LastFour:  textPtrFromString(&input.LastFour),
		Scopes:    input.Scopes,
		CreatedBy: uuidPtrFromString(&input.CreatedBy),
		ExpiresAt: timestamptzPtrFromTime(input.ExpiresAt),
	})
	if err != nil {
		return port.APIKey{}, err
	}
	return apiKeyToPort(row), nil
}

func (r *pgAPIKeyPort) TouchLastUsed(ctx context.Context, id string) error {
	kid, err := parseID(id)
	if err != nil {
		return err
	}
	return r.q.TouchAPIKeyLastUsed(ctx, kid)
}

func (r *pgAPIKeyPort) ListByProject(ctx context.Context, projectID string) ([]port.APIKey, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListAPIKeysByProject(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.APIKey, len(rows))
	for i, row := range rows {
		out[i] = port.APIKey{
			ID:        toUUID(row.ID),
			Name:      row.Name,
			KeyPrefix: row.KeyPrefix,
			LastFour:  stringFromTextPtr(row.LastFour),
			CreatedAt: row.CreatedAt.Time,
			RevokedAt: timePtrFromTimestamptz(row.RevokedAt),
		}
	}
	return out, nil
}

func (r *pgAPIKeyPort) GetByHash(ctx context.Context, keyHash string) (port.APIKey, error) {
	row, err := r.q.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return port.APIKey{}, mappingErr(err)
	}
	return apiKeyToPort(row), nil
}

func (r *pgAPIKeyPort) Revoke(ctx context.Context, id, projectID string) (port.APIKey, error) {
	kid, err := parseID(id)
	if err != nil {
		return port.APIKey{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.APIKey{}, err
	}
	row, err := r.q.RevokeAPIKey(ctx, sqlc.RevokeAPIKeyParams{ID: kid, ProjectID: pid})
	if err != nil {
		return port.APIKey{}, mappingErr(err)
	}
	return apiKeyToPort(row), nil
}

func apiKeyToPort(k sqlc.ApiKey) port.APIKey {
	return port.APIKey{
		ID:         toUUID(k.ID),
		ProjectID:  toUUID(k.ProjectID),
		Name:       k.Name,
		KeyPrefix:  k.KeyPrefix,
		LastFour:   stringFromTextPtr(k.LastFour),
		CreatedBy:  stringPtrFromUUID(k.CreatedBy),
		CreatedAt:  k.CreatedAt.Time,
		ExpiresAt:  timePtrFromTimestamptz(k.ExpiresAt),
		LastUsedAt: timePtrFromTimestamptz(k.LastUsedAt),
		RevokedAt:  timePtrFromTimestamptz(k.RevokedAt),
	}
}

// pgEnvironmentPort adapts EnvironmentStore.
type pgEnvironmentPort struct{ q *sqlc.Queries }

func (r *pgEnvironmentPort) Upsert(ctx context.Context, projectID, name, tier string, internetFacing bool, dataSensitivity string) (port.Environment, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Environment{}, err
	}
	row, err := r.q.UpsertEnvironment(ctx, sqlc.UpsertEnvironmentParams{
		ProjectID:       pid,
		Name:            name,
		Tier:            tier,
		InternetFacing:  internetFacing,
		DataSensitivity: dataSensitivity,
	})
	if err != nil {
		return port.Environment{}, err
	}
	return environmentToPort(row), nil
}

func (r *pgEnvironmentPort) List(ctx context.Context, projectID string) ([]port.Environment, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListEnvironments(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Environment, len(rows))
	for i, row := range rows {
		out[i] = environmentToPort(row)
	}
	return out, nil
}

func (r *pgEnvironmentPort) GetByID(ctx context.Context, id, projectID string) (port.Environment, error) {
	eid, err := parseID(id)
	if err != nil {
		return port.Environment{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Environment{}, err
	}
	row, err := r.q.GetEnvironment(ctx, sqlc.GetEnvironmentParams{ID: eid, ProjectID: pid})
	if err != nil {
		return port.Environment{}, mappingErr(err)
	}
	return environmentToPort(row), nil
}

func (r *pgEnvironmentPort) Delete(ctx context.Context, id, projectID string) (port.Environment, error) {
	eid, err := parseID(id)
	if err != nil {
		return port.Environment{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Environment{}, err
	}
	row, err := r.q.DeleteEnvironment(ctx, sqlc.DeleteEnvironmentParams{ID: eid, ProjectID: pid})
	if err != nil {
		return port.Environment{}, mappingErr(err)
	}
	return environmentToPort(row), nil
}

func environmentToPort(e sqlc.Environment) port.Environment {
	return port.Environment{
		ID:              toUUID(e.ID),
		ProjectID:       toUUID(e.ProjectID),
		Name:            e.Name,
		Tier:            e.Tier,
		InternetFacing:  e.InternetFacing,
		DataSensitivity: e.DataSensitivity,
		CreatedAt:       e.CreatedAt.Time,
	}
}

// pgTargetPort adapts TargetStore.
type pgTargetPort struct{ q *sqlc.Queries }

func (r *pgTargetPort) Upsert(ctx context.Context, projectID, name, kind, locator, owner string) (port.Target, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Target{}, err
	}
	row, err := r.q.UpsertTarget(ctx, sqlc.UpsertTargetParams{
		ProjectID: pid,
		Name:      name,
		Kind:      kind,
		Locator:   textPtrFromString(&locator),
		Column5:   owner,
	})
	if err != nil {
		return port.Target{}, err
	}
	return targetToPort(row), nil
}

func (r *pgTargetPort) List(ctx context.Context, projectID string) ([]port.Target, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListTargets(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Target, len(rows))
	for i, row := range rows {
		out[i] = targetToPort(row)
	}
	return out, nil
}

func (r *pgTargetPort) GetByID(ctx context.Context, id, projectID string) (port.Target, error) {
	tid, err := parseID(id)
	if err != nil {
		return port.Target{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Target{}, err
	}
	row, err := r.q.GetTarget(ctx, sqlc.GetTargetParams{ID: tid, ProjectID: pid})
	if err != nil {
		return port.Target{}, mappingErr(err)
	}
	return targetToPort(row), nil
}

func (r *pgTargetPort) Delete(ctx context.Context, id, projectID string) (port.Target, error) {
	tid, err := parseID(id)
	if err != nil {
		return port.Target{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Target{}, err
	}
	row, err := r.q.DeleteTarget(ctx, sqlc.DeleteTargetParams{ID: tid, ProjectID: pid})
	if err != nil {
		return port.Target{}, mappingErr(err)
	}
	return targetToPort(row), nil
}

func targetToPort(t sqlc.Target) port.Target {
	return port.Target{
		ID:        toUUID(t.ID),
		ProjectID: toUUID(t.ProjectID),
		Name:      t.Name,
		Kind:      t.Kind,
		Locator:   stringFromTextPtr(t.Locator),
		Owner:     stringFromTextPtr(t.Owner),
		CreatedAt: t.CreatedAt.Time,
	}
}

// pgArtifactPort adapts ArtifactStore.
type pgArtifactPort struct{ q *sqlc.Queries }

func (r *pgArtifactPort) Upsert(ctx context.Context, input port.ArtifactInput) (port.Artifact, error) {
	pid, err := parseID(input.ProjectID)
	if err != nil {
		return port.Artifact{}, err
	}
	row, err := r.q.UpsertArtifact(ctx, sqlc.UpsertArtifactParams{
		ProjectID:    pid,
		TargetID:     uuidPtrFromString(&input.TargetID),
		ArtifactType: input.ArtifactType,
		Name:         input.Name,
		Version:      textPtrFromString(input.Version),
		Digest:       textPtrFromString(input.Digest),
		Locator:      textPtrFromString(input.Locator),
		Metadata:     input.Metadata,
	})
	if err != nil {
		return port.Artifact{}, err
	}
	return artifactToPort(row), nil
}

func (r *pgArtifactPort) List(ctx context.Context, projectID string) ([]port.Artifact, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListArtifacts(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Artifact, len(rows))
	for i, row := range rows {
		out[i] = artifactToPort(row)
	}
	return out, nil
}

func (r *pgArtifactPort) ListByTarget(ctx context.Context, targetID string) ([]port.Artifact, error) {
	tid, err := parseID(targetID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListArtifactsByTarget(ctx, tid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Artifact, len(rows))
	for i, row := range rows {
		out[i] = artifactToPort(row)
	}
	return out, nil
}

func (r *pgArtifactPort) GetByID(ctx context.Context, id, projectID string) (port.Artifact, error) {
	aid, err := parseID(id)
	if err != nil {
		return port.Artifact{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Artifact{}, err
	}
	row, err := r.q.GetArtifact(ctx, sqlc.GetArtifactParams{ID: aid, ProjectID: pid})
	if err != nil {
		return port.Artifact{}, mappingErr(err)
	}
	return artifactToPort(row), nil
}

func (r *pgArtifactPort) Delete(ctx context.Context, id, projectID string) (port.Artifact, error) {
	aid, err := parseID(id)
	if err != nil {
		return port.Artifact{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Artifact{}, err
	}
	row, err := r.q.DeleteArtifact(ctx, sqlc.DeleteArtifactParams{ID: aid, ProjectID: pid})
	if err != nil {
		return port.Artifact{}, mappingErr(err)
	}
	return artifactToPort(row), nil
}

func artifactToPort(a sqlc.Artifact) port.Artifact {
	return port.Artifact{
		ID:           toUUID(a.ID),
		ProjectID:    toUUID(a.ProjectID),
		TargetID:     toUUID(a.TargetID),
		ArtifactType: a.ArtifactType,
		Name:         a.Name,
		Version:      stringFromTextPtr(a.Version),
		Digest:       stringFromTextPtr(a.Digest),
		Locator:      stringFromTextPtr(a.Locator),
		Metadata:     a.Metadata,
		CreatedAt:    a.CreatedAt.Time,
	}
}

// pgEvidencePort adapts EvidenceStore.
type pgEvidencePort struct{ q *sqlc.Queries }

func (r *pgEvidencePort) Create(ctx context.Context, input port.EvidenceInput) (port.Evidence, error) {
	fid, err := parseID(input.FindingID)
	if err != nil {
		return port.Evidence{}, err
	}
	row, err := r.q.CreateEvidence(ctx, sqlc.CreateEvidenceParams{
		FindingID:   fid,
		Type:        input.Type,
		Url:         input.URL,
		Description: input.Description,
		UploadedBy:  uuidPtrFromString(input.UploadedBy),
	})
	if err != nil {
		return port.Evidence{}, err
	}
	return evidenceToPort(row), nil
}

func (r *pgEvidencePort) ListByFinding(ctx context.Context, findingID string) ([]port.Evidence, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListEvidenceByFinding(ctx, fid)
	if err != nil {
		return nil, err
	}
	out := make([]port.Evidence, len(rows))
	for i, row := range rows {
		out[i] = evidenceToPort(row)
	}
	return out, nil
}

func (r *pgEvidencePort) GetByID(ctx context.Context, id string) (port.Evidence, error) {
	eid, err := parseID(id)
	if err != nil {
		return port.Evidence{}, err
	}
	row, err := r.q.GetEvidenceByID(ctx, eid)
	if err != nil {
		return port.Evidence{}, mappingErr(err)
	}
	return evidenceToPort(row), nil
}

func (r *pgEvidencePort) Delete(ctx context.Context, id string) error {
	eid, err := parseID(id)
	if err != nil {
		return err
	}
	return r.q.DeleteEvidence(ctx, eid)
}

func evidenceToPort(e sqlc.EvidenceArtifact) port.Evidence {
	return port.Evidence{
		ID:          toUUID(e.ID),
		FindingID:   toUUID(e.FindingID),
		Type:        e.Type,
		URL:         e.Url,
		Description: e.Description,
		UploadedBy:  stringPtrFromUUID(e.UploadedBy),
		CreatedAt:   e.CreatedAt.Time,
	}
}

// pgReachabilityPort adapts ReachabilityStore.
type pgReachabilityPort struct{ q *sqlc.Queries }

func (r *pgReachabilityPort) Upsert(ctx context.Context, findingID, state, evidence, assessedBy string) (port.ReachabilityAssessment, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.ReachabilityAssessment{}, err
	}
	uid, err := parseID(assessedBy)
	if err != nil {
		return port.ReachabilityAssessment{}, err
	}
	row, err := r.q.UpsertReachability(ctx, sqlc.UpsertReachabilityParams{
		FindingID:  fid,
		State:      sqlc.ReachabilityState(state),
		Evidence:   evidence,
		AssessedBy: uid,
	})
	if err != nil {
		return port.ReachabilityAssessment{}, err
	}
	return reachabilityToPort(row), nil
}

func (r *pgReachabilityPort) ListByFinding(ctx context.Context, findingID string) ([]port.ReachabilityAssessment, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListReachabilityByFinding(ctx, fid)
	if err != nil {
		return nil, err
	}
	out := make([]port.ReachabilityAssessment, len(rows))
	for i, row := range rows {
		out[i] = reachabilityToPort(row)
	}
	return out, nil
}

func (r *pgReachabilityPort) GetByID(ctx context.Context, id string) (port.ReachabilityAssessment, error) {
	rid, err := parseID(id)
	if err != nil {
		return port.ReachabilityAssessment{}, err
	}
	row, err := r.q.GetReachability(ctx, rid)
	if err != nil {
		return port.ReachabilityAssessment{}, mappingErr(err)
	}
	return reachabilityToPort(row), nil
}

func (r *pgReachabilityPort) LatestByFinding(ctx context.Context, findingID string) (port.ReachabilityAssessment, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.ReachabilityAssessment{}, err
	}
	row, err := r.q.LatestReachabilityByFinding(ctx, fid)
	if err != nil {
		return port.ReachabilityAssessment{}, mappingErr(err)
	}
	return reachabilityToPort(row), nil
}

func (r *pgReachabilityPort) LatestByFindings(ctx context.Context, findingIDs []string) ([]port.ReachabilityAssessment, error) {
	ids := make([]pgtype.UUID, len(findingIDs))
	for i, id := range findingIDs {
		uid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		ids[i] = uid
	}
	rows, err := r.q.LatestReachabilityByFindings(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]port.ReachabilityAssessment, len(rows))
	for i, row := range rows {
		out[i] = reachabilityToPort(row)
	}
	return out, nil
}

func reachabilityToPort(a sqlc.ReachabilityAssessment) port.ReachabilityAssessment {
	return port.ReachabilityAssessment{
		ID:         toUUID(a.ID),
		FindingID:  toUUID(a.FindingID),
		State:      string(a.State),
		Evidence:   a.Evidence,
		AssessedBy: toUUID(a.AssessedBy),
		CreatedAt:  a.CreatedAt.Time,
		UpdatedAt:  a.UpdatedAt.Time,
	}
}

// pgSignoffPort adapts SignoffStore.
type pgSignoffPort struct{ q *sqlc.Queries }

func (r *pgSignoffPort) Upsert(ctx context.Context, findingID, status, reviewedBy, comment string) (port.Signoff, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.Signoff{}, err
	}
	rid, err := parseID(reviewedBy)
	if err != nil {
		return port.Signoff{}, err
	}
	row, err := r.q.UpsertSignoff(ctx, sqlc.UpsertSignoffParams{
		FindingID:  fid,
		Status:     sqlc.SignoffStatus(status),
		ReviewedBy: rid,
		Comment:    comment,
	})
	if err != nil {
		return port.Signoff{}, err
	}
	return signoffToPort(row), nil
}

func (r *pgSignoffPort) GetByFinding(ctx context.Context, findingID string) (port.Signoff, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.Signoff{}, err
	}
	row, err := r.q.GetSignoffByFinding(ctx, fid)
	if err != nil {
		return port.Signoff{}, mappingErr(err)
	}
	return signoffToPort(row), nil
}

func signoffToPort(s sqlc.Signoff) port.Signoff {
	return port.Signoff{
		ID:         toUUID(s.ID),
		FindingID:  toUUID(s.FindingID),
		Status:     string(s.Status),
		ReviewedBy: toUUID(s.ReviewedBy),
		Comment:    s.Comment,
		CreatedAt:  s.CreatedAt.Time,
		UpdatedAt:  s.UpdatedAt.Time,
	}
}
