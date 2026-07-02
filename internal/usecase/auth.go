package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

type APIKeyResponse struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	KeyPrefix string  `json:"key_prefix"`
	RawKey    string  `json:"raw_key,omitempty"`
	LastFour  *string `json:"last_four"`
	CreatedAt string  `json:"created_at"`
}

func (u *Usecases) Register(ctx context.Context, email, password string) (*AuthResponse, error) {
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password are required")
	}

	existing, err := u.deps.Repos.Users.GetByEmail(ctx, email)
	if err == nil && existing.Email != "" {
		return nil, fmt.Errorf("email already registered")
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := u.deps.Repos.Users.Create(ctx, email, pgtype.Text{Valid: false}, pgtype.Text{String: hash, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	userID := uuid.UUID(user.ID.Bytes).String()
	token, err := u.deps.JWTAuth.CreateToken(userID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	refreshToken, err := u.deps.JWTAuth.CreateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	return &AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       userID,
		Email:        user.Email,
	}, nil
}

func (u *Usecases) Login(ctx context.Context, email, password string) (*AuthResponse, error) {
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password are required")
	}

	user, err := u.deps.Repos.Users.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid email or password")
	}

	if !user.PasswordHash.Valid {
		return nil, fmt.Errorf("invalid email or password")
	}

	if !auth.VerifyPassword(password, user.PasswordHash.String) {
		return nil, fmt.Errorf("invalid email or password")
	}

	userID := uuid.UUID(user.ID.Bytes).String()
	token, err := u.deps.JWTAuth.CreateToken(userID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	refreshToken, err := u.deps.JWTAuth.CreateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	return &AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		UserID:       userID,
		Email:        user.Email,
	}, nil
}

func (u *Usecases) CreateAPIKey(ctx context.Context, projectSlug, name string) (*APIKeyResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}

	rawKey, prefix, hash, lastFour, err := auth.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	key, err := u.deps.Repos.APIKeys.Create(ctx, sqlc.CreateAPIKeyParams{
		ProjectID: pgtype.UUID{Bytes: project.ID.Bytes, Valid: true},
		Name:      name,
		KeyPrefix: prefix,
		KeyHash:   hash,
		LastFour:  pgtype.Text{String: lastFour, Valid: true},
		Scopes:    []byte(`["ingest"]`),
	})
	if err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}

	return &APIKeyResponse{
		ID:        uuid.UUID(key.ID.Bytes).String(),
		Name:      key.Name,
		KeyPrefix: key.KeyPrefix,
		RawKey:    rawKey,
		LastFour:  strPtr(lastFour),
		CreatedAt: key.CreatedAt.Time.Format(time.RFC3339),
	}, nil
}

func (u *Usecases) ListAPIKeys(ctx context.Context, projectSlug string) ([]APIKeyResponse, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}

	keys, err := u.deps.Repos.APIKeys.ListByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	resp := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		lf := ""
		if k.LastFour.Valid {
			lf = k.LastFour.String
		}
		resp[i] = APIKeyResponse{
			ID:        uuid.UUID(k.ID.Bytes).String(),
			Name:      k.Name,
			KeyPrefix: k.KeyPrefix,
			LastFour:  strPtr(lf),
			CreatedAt: k.CreatedAt.Time.Format(time.RFC3339),
		}
	}
	return resp, nil
}

func (u *Usecases) RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	var id pgtype.UUID
	if err := id.Scan(keyID); err != nil {
		return fmt.Errorf("invalid key id: %w", err)
	}

	_, err = u.deps.Repos.APIKeys.Revoke(ctx, id, project.ID)
	if err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	return nil
}

func strPtr(s string) *string { return &s }
