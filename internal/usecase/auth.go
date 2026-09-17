package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

// ErrRegistrationFailed is returned when a self-service registration cannot
// be completed. It is deliberately generic: revealing whether the failure is
// a duplicate email, a storage error, or anything else would let callers
// enumerate registered accounts. Detail is written to the server log instead.
var ErrRegistrationFailed = errors.New("registration failed")

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
	ExpiresAt *string `json:"expires_at,omitempty"`
}

func (u *Usecases) Register(ctx context.Context, email, password string) (*AuthResponse, error) {
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password are required")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || !strings.Contains(addr.Address, "@") {
		return nil, fmt.Errorf("invalid email address")
	}
	email = strings.ToLower(strings.TrimSpace(addr.Address))
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	_, err = u.deps.Stores.Users.GetByEmail(ctx, email)
	if err == nil {
		// M8: the duplicate is a legitimate operational detail for operators,
		// but must never reach the caller. Log it, return the generic error.
		slog.Warn("register: email already registered", "email", email)
		return nil, ErrRegistrationFailed
	}
	if !errors.Is(err, port.ErrNotFound) {
		slog.Error("register: lookup user failed", "email", email, "error", err)
		return nil, ErrRegistrationFailed
	}

	hash, err := u.deps.Passwords.Hash(password)
	if err != nil {
		slog.Error("register: hash password failed", "email", email, "error", err)
		return nil, ErrRegistrationFailed
	}

	user, err := u.deps.Stores.Users.Create(ctx, email, nil, &hash)
	if err != nil {
		slog.Error("register: create user failed", "email", email, "error", err)
		return nil, ErrRegistrationFailed
	}

	userID := user.ID
	token, err := u.deps.Tokens.CreateToken(userID, user.Email, auth.RoleViewer)
	if err != nil {
		slog.Error("register: create token failed", "email", email, "error", err)
		return nil, ErrRegistrationFailed
	}

	resp, err := u.createSession(ctx, userID, user.Email)
	if err != nil {
		slog.Error("register: create session failed", "email", email, "error", err)
		return nil, ErrRegistrationFailed
	}
	resp.Token = token
	return resp, nil
}

// FindOrProvisionSSOUser resolves an SSO-authenticated principal (sub is the
// stable IdP subject, email the asserted address) to a local account for
// token issuance. Existing accounts keep their local role — IdP groups never
// change an established role. Unknown accounts are provisioned only when the
// email domain is allowlisted, otherwise auth.ErrSSONotProvisioned is
// returned (the caller maps it to a generic 403). Provisioned accounts are
// created without a password hash, so they can never use password login
// (Login rejects empty hashes); they receive the default member role unless
// IdP group membership matches adminGroups, in which case they are elevated
// to admin via SetRole. A SetRole failure fails the login closed: the
// account exists as a member and an operator can elevate it explicitly.
func (u *Usecases) FindOrProvisionSSOUser(ctx context.Context, sub, email string, groups []string, allowedDomains []string, adminGroups []string) (userID, role string, provisioned bool, err error) {
	if email == "" {
		return "", "", false, auth.ErrSSONotProvisioned
	}
	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	if err == nil {
		if sub != "" {
			slog.Info("sso login: existing account", "email", email, "sub", sub)
		}
		return user.ID, auth.TokenRole(user.Role), false, nil
	}
	if !errors.Is(err, port.ErrNotFound) {
		return "", "", false, fmt.Errorf("lookup sso user: %w", err)
	}
	domain := ssoEmailDomain(email)
	allowed := false
	for _, d := range allowedDomains {
		if d != "" && domain == d {
			allowed = true
			break
		}
	}
	if !allowed {
		slog.Warn("sso login: account not provisioned", "email", email, "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	}
	created, err := u.deps.Stores.Users.Create(ctx, email, nil, nil)
	if err != nil {
		return "", "", false, fmt.Errorf("provision sso user: %w", err)
	}
	slog.Info("sso login: provisioned account", "email", email, "sub", sub)
	if auth.IsSSOAdmin(groups, adminGroups) {
		elevated, err := u.deps.Stores.Users.SetRole(ctx, created.ID, auth.RoleAdmin)
		if err != nil {
			return "", "", false, fmt.Errorf("elevate sso admin: %w", err)
		}
		slog.Info("sso login: elevated to admin by IdP group", "email", email, "sub", sub)
		return elevated.ID, auth.TokenRole(elevated.Role), true, nil
	}
	return created.ID, auth.TokenRole(created.Role), true, nil
}

// ssoEmailDomain returns the lowercased domain part of an email address,
// or "" when the address has no domain part.
func ssoEmailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at+1 >= len(email) {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

func (u *Usecases) Login(ctx context.Context, email, password string) (*AuthResponse, error) {
	if email == "" || password == "" {
		return nil, fmt.Errorf("email and password are required")
	}
	email = strings.ToLower(strings.TrimSpace(email))

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
	token, err := u.deps.Tokens.CreateToken(userID, user.Email, auth.TokenRole(user.Role))
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

func (u *Usecases) CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string, expiresAt *time.Time) (*APIKeyResponse, error) {
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
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}

	resp := &APIKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		KeyPrefix: key.KeyPrefix,
		RawKey:    rawKey,
		LastFour:  strPtr(lastFour),
		CreatedAt: key.CreatedAt.Format(time.RFC3339),
	}
	if key.ExpiresAt != nil {
		exp := key.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &exp
	}
	return resp, nil
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
		// M3: presenting an already-revoked token is reuse of a rotated
		// token. The family of tokens issued to this user may have been
		// stolen, so revoke the whole family before failing.
		if err := u.deps.Stores.RefreshTokens.RevokeAllForUser(ctx, stored.UserID); err != nil {
			slog.Error("refresh: revoke family after reuse", "user_id", stored.UserID, "error", err)
		}
		return nil, fmt.Errorf("refresh token has been revoked")
	}

	if stored.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token has expired")
	}

	// M3: rotation must be atomic. RevokeRefreshToken is a compare-and-swap
	// (UPDATE ... WHERE id = $1 AND revoked_at IS NULL RETURNING); a second,
	// concurrent rotation of the same token revokes zero rows and surfaces
	// as ErrNotFound. Only the single winner proceeds to mint a new session.
	if _, err := u.deps.Stores.RefreshTokens.Revoke(ctx, stored.ID); err != nil {
		if errors.Is(err, port.ErrNotFound) {
			// M3: another request rotated this token between our read and
			// our revoke. Reuse of a rotated token means the family may be
			// compromised: revoke every token issued to this user.
			if err := u.deps.Stores.RefreshTokens.RevokeAllForUser(ctx, stored.UserID); err != nil {
				slog.Error("refresh: revoke family after concurrent reuse", "user_id", stored.UserID, "error", err)
			}
			return nil, fmt.Errorf("refresh token has been revoked")
		}
		return nil, fmt.Errorf("revoke old token: %w", err)
	}

	userID := stored.UserID
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	token, err := u.deps.Tokens.CreateToken(userID, user.Email, auth.TokenRole(user.Role))
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

	// Revoke is a guarded compare-and-swap: revoking an already-revoked
	// token matches zero rows and reports ErrNotFound, which is the desired
	// outcome for logout (the token is already unusable).
	_, err = u.deps.Stores.RefreshTokens.Revoke(ctx, stored.ID)
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}
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

// UpdateProfile changes the caller's display name. A nil or blank
// displayName clears it.
func (u *Usecases) UpdateProfile(ctx context.Context, userID string, displayName *string) (*UserProfile, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
	if displayName != nil {
		trimmed := strings.TrimSpace(*displayName)
		if trimmed == "" {
			displayName = nil
		} else {
			displayName = &trimmed
		}
	}

	user, err := u.deps.Stores.Users.UpdateDisplayName(ctx, id.String(), displayName)
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
