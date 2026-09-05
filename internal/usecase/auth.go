package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

// UserProfile is the authenticated user's public profile.
type UserProfile struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	CreatedAt   string `json:"created_at"`
}

// AuthResponse carries the tokens and identity returned by login/register.
type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

// APIKeyResponse is a project API key. RawKey is present only in the create response.
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
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	existing, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	if err == nil && existing.Email != "" {
		return nil, fmt.Errorf("email already registered")
	}

	hash, err := u.deps.Passwords.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user, err := u.deps.Stores.Users.Create(ctx, email, nil, &hash)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	userID := user.ID
	token, err := u.deps.Tokens.CreateToken(userID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	resp, err := u.createSession(ctx, userID, user.Email)
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return resp, nil
}

func (u *Usecases) Login(ctx context.Context, email, password string) (*AuthResponse, error) {
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password are required")
	}

	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid email or password")
	}

	if user.PasswordHash == "" {
		return nil, fmt.Errorf("invalid email or password")
	}

	if !u.deps.Passwords.Verify(password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid email or password")
	}

	userID := user.ID
	token, err := u.deps.Tokens.CreateToken(userID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	resp, err := u.createSession(ctx, userID, user.Email)
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return resp, nil
}

func (u *Usecases) CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string) (*APIKeyResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	creatorID, err := uuid.Parse(createdBy)
	if err != nil {
		return nil, fmt.Errorf("invalid creator user id: %w", err)
	}

	rawKey, prefix, hash, lastFour, err := auth.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	key, err := u.deps.Stores.APIKeys.Create(ctx, port.CreateAPIKeyInput{
		ProjectID: project.ID,
		Name:      name,
		KeyPrefix: prefix,
		KeyHash:   hash,
		LastFour:  lastFour,
		Scopes:    json.RawMessage(`["ingest"]`),
		CreatedBy: creatorID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}

	return &APIKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		KeyPrefix: key.KeyPrefix,
		RawKey:    rawKey,
		LastFour:  strPtr(lastFour),
		CreatedAt: key.CreatedAt.Format(time.RFC3339),
	}, nil
}

func (u *Usecases) ListAPIKeys(ctx context.Context, projectSlug string) ([]APIKeyResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}

	keys, err := u.deps.Stores.APIKeys.ListByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	resp := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		lf := ""
		if k.LastFour != nil {
			lf = *k.LastFour
		}
		resp[i] = APIKeyResponse{
			ID:        k.ID,
			Name:      k.Name,
			KeyPrefix: k.KeyPrefix,
			LastFour:  strPtr(lf),
			CreatedAt: k.CreatedAt.Format(time.RFC3339),
		}
	}
	return resp, nil
}

func (u *Usecases) RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	id, err := uuid.Parse(keyID)
	if err != nil {
		return fmt.Errorf("invalid key id: %w", err)
	}

	_, err = u.deps.Stores.APIKeys.Revoke(ctx, id.String(), project.ID)
	if err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	return nil
}

func (u *Usecases) createSession(ctx context.Context, userID, email string) (*AuthResponse, error) {
	rawRefresh, err := u.deps.Tokens.CreateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	hash := sha256.Sum256([]byte(rawRefresh))
	hashStr := hex.EncodeToString(hash[:])

	if _, err := u.deps.Stores.RefreshTokens.Create(ctx, userID, hashStr, time.Now().Add(7*24*time.Hour)); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &AuthResponse{
		RefreshToken: rawRefresh,
		UserID:       userID,
		Email:        email,
	}, nil
}

func (u *Usecases) Refresh(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}

	hash := sha256.Sum256([]byte(refreshToken))
	hashStr := hex.EncodeToString(hash[:])

	stored, err := u.deps.Stores.RefreshTokens.GetByHash(ctx, hashStr)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if stored.RevokedAt != nil {
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	if stored.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token has expired")
	}

	if _, err := u.deps.Stores.RefreshTokens.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("revoke old token: %w", err)
	}

	userID := stored.UserID
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	token, err := u.deps.Tokens.CreateToken(userID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	resp, err := u.createSession(ctx, userID, user.Email)
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return resp, nil
}

func (u *Usecases) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return nil
	}

	hash := sha256.Sum256([]byte(refreshToken))
	hashStr := hex.EncodeToString(hash[:])

	stored, err := u.deps.Stores.RefreshTokens.GetByHash(ctx, hashStr)
	if err != nil {
		return nil
	}

	_, err = u.deps.Stores.RefreshTokens.Revoke(ctx, stored.ID)
	return err
}

func (u *Usecases) GetProfile(ctx context.Context, userID string) (*UserProfile, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	user, err := u.deps.Stores.Users.GetByID(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	name := ""
	if user.DisplayName != nil {
		name = *user.DisplayName
	}

	return &UserProfile{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: name,
		Role:        user.Role,
		CreatedAt:   user.CreatedAt.Format(time.RFC3339),
	}, nil
}

func strPtr(s string) *string { return &s }
