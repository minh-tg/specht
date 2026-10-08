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
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	authMsgInvalidCredentials = "invalid email or password"
	authMsgProjectNotFound    = "project not found: %w"
	authMsgUserNotFound       = "user not found"
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
	email = auth.NormalizeEmail(addr.Address)
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return nil, fmt.Errorf("password must be at most 72 characters")
	}

	_, err = u.deps.Stores.Users.GetByEmail(ctx, email)
	if err == nil {
		// M8: the duplicate is a legitimate operational detail for operators,
		// but must never reach the caller. Log it, return the generic error.
		// Hash anyway: skipping the work would make duplicates answer
		// measurably faster than new accounts and reveal who is registered.
		u.burnHash(password)
		slog.Warn("register: email already registered", "email", auth.MaskEmail(email))
		return nil, ErrRegistrationFailed
	}
	if !errors.Is(err, port.ErrNotFound) {
		slog.Error("register: lookup user failed", "email", auth.MaskEmail(email), "error", err)
		return nil, ErrRegistrationFailed
	}

	hash, err := u.deps.Passwords.Hash(password)
	if err != nil {
		slog.Error("register: hash password failed", "email", auth.MaskEmail(email), "error", err)
		return nil, ErrRegistrationFailed
	}

	user, err := u.deps.Stores.Users.Create(ctx, email, nil, &hash)
	if err != nil {
		slog.Error("register: create user failed", "email", auth.MaskEmail(email), "error", err)
		return nil, ErrRegistrationFailed
	}

	userID := user.ID
	token, err := u.deps.Tokens.CreateToken(userID, user.Email, auth.RoleViewer)
	if err != nil {
		slog.Error("register: create token failed", "email", auth.MaskEmail(email), "error", err)
		return nil, ErrRegistrationFailed
	}

	resp, err := u.createSession(ctx, userID, user.Email)
	if err != nil {
		slog.Error("register: create session failed", "email", auth.MaskEmail(email), "error", err)
		return nil, ErrRegistrationFailed
	}
	resp.Token = token
	return resp, nil
}

// burnVerify spends the cost of one password check against a dummy hash. The
// early-exit branches of Login (unknown email, account with no password) call
// it so they take as long as a real check; otherwise response time reveals
// which emails are registered and which use password login.
func (u *Usecases) burnVerify(password string) {
	if u.deps.Passwords == nil {
		return
	}
	u.dummyOnce.Do(func() {
		u.dummyHash, _ = u.deps.Passwords.Hash("timing-equalisation-placeholder")
	})
	if u.dummyHash != "" {
		u.deps.Passwords.Verify(password, u.dummyHash)
	}
}

// burnHash spends the cost of hashing one password and discards the result.
func (u *Usecases) burnHash(password string) {
	if u.deps.Passwords == nil {
		return
	}
	_, _ = u.deps.Passwords.Hash(password)
}

// FindOrProvisionSSOUser resolves an SSO-authenticated principal to a local
// account for token issuance.
//
// The pair (issuer, subject) identifies the person at the provider and decides
// first: a subject that was linked before is resolved by that link alone, so a
// changed or unverified email claim cannot redirect it to another account.
// Only a first-time subject falls back to the email, and only when the
// provider vouches for it (or the operator opted in with
// SSOAllowUnverifiedEmail). A verified email that matches an existing account
// links that account, unless it is already bound to a different subject at the
// same provider. Otherwise the account is provisioned when the email domain is
// allowlisted; anything else yields auth.ErrSSONotProvisioned (the caller maps
// it to a generic 403). Existing accounts keep their local role. Provisioned
// accounts have no password, so password login stays impossible for them, and
// become admin only when IdP group membership matches adminGroups; a SetRole
// failure fails the login closed.
func (u *Usecases) FindOrProvisionSSOUser(ctx context.Context, claims auth.SSOClaims, allowedDomains []string, adminGroups []string) (userID, role string, provisioned bool, err error) {
	issuer, sub := claims.Issuer, claims.Subject
	if issuer == "" || sub == "" {
		slog.Warn("sso login: provider returned no stable identity", "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	}

	linked, err := u.deps.Stores.Identities.GetBySubject(ctx, issuer, sub)
	switch {
	case err == nil:
		user, err := u.deps.Stores.Users.GetByID(ctx, linked.UserID)
		if err != nil {
			return "", "", false, fmt.Errorf("lookup linked sso user: %w", err)
		}
		slog.Info("sso login: linked account", "user_id", user.ID, "sub", sub)
		return user.ID, auth.TokenRole(user.Role), false, nil
	case !errors.Is(err, port.ErrNotFound):
		return "", "", false, fmt.Errorf("lookup sso identity: %w", err)
	}

	email := auth.NormalizeEmail(claims.Email)
	if email == "" || (!claims.EmailVerified && !u.deps.SSOAllowUnverifiedEmail) {
		slog.Warn("sso login: first login without a verified email", "email", auth.MaskEmail(email), "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	}

	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	switch {
	case err == nil:
		return u.linkExistingSSOUser(ctx, user, issuer, sub)
	case errors.Is(err, port.ErrNotFound):
		return u.provisionSSOUser(ctx, claims, email, allowedDomains, adminGroups)
	default:
		return "", "", false, fmt.Errorf("lookup sso user: %w", err)
	}
}

// linkExistingSSOUser binds a provider identity to the account its verified
// email matched. An account that already has an identity at this provider is
// refused: a second subject presenting the same email is exactly how a
// reassigned or spoofed address would take the account over.
func (u *Usecases) linkExistingSSOUser(ctx context.Context, user port.User, issuer, sub string) (string, string, bool, error) {
	_, err := u.deps.Stores.Identities.GetForUser(ctx, user.ID, issuer)
	switch {
	case err == nil:
		slog.Warn("sso login: account already linked to a different subject", "user_id", user.ID, "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	case !errors.Is(err, port.ErrNotFound):
		return "", "", false, fmt.Errorf("lookup user identity: %w", err)
	}
	// Whoever registered this address first may not be its owner. Drop the
	// password so it cannot be used again, and end every session minted
	// with it, before the provider identity takes the account over. The
	// steps are idempotent, so a failure part-way is retried on the next
	// login instead of leaving a linked account with a live backdoor.
	if user.PasswordHash != "" {
		if err := u.deps.Stores.Users.ClearPassword(ctx, user.ID); err != nil {
			return "", "", false, fmt.Errorf("disable password for sso link: %w", err)
		}
	}
	if err := u.deps.Stores.RefreshTokens.RevokeAllForUser(ctx, user.ID); err != nil {
		return "", "", false, fmt.Errorf("revoke sessions for sso link: %w", err)
	}
	if err := u.linkSSOIdentity(ctx, user.ID, issuer, sub); err != nil {
		return "", "", false, err
	}
	slog.Info("sso login: linked existing account", "user_id", user.ID, "sub", sub, "password_disabled", user.PasswordHash != "")
	return user.ID, auth.TokenRole(user.Role), false, nil
}

// provisionSSOUser creates and links an account for a first-time subject whose
// email domain is allowlisted.
func (u *Usecases) provisionSSOUser(ctx context.Context, claims auth.SSOClaims, email string, allowedDomains, adminGroups []string) (string, string, bool, error) {
	domain := ssoEmailDomain(email)
	allowed := false
	for _, d := range allowedDomains {
		if d != "" && domain == d {
			allowed = true
			break
		}
	}
	if !allowed {
		slog.Warn("sso login: account not provisioned", "email", auth.MaskEmail(email), "sub", claims.Subject)
		return "", "", false, auth.ErrSSONotProvisioned
	}
	created, err := u.deps.Stores.Users.Create(ctx, email, nil, nil)
	if err != nil {
		return "", "", false, fmt.Errorf("provision sso user: %w", err)
	}
	if err := u.linkSSOIdentity(ctx, created.ID, claims.Issuer, claims.Subject); err != nil {
		return "", "", false, err
	}
	slog.Info("sso login: provisioned account", "user_id", created.ID, "sub", claims.Subject)
	if auth.IsSSOAdmin(claims.Groups, adminGroups) {
		elevated, err := u.deps.Stores.Users.SetRole(ctx, created.ID, auth.RoleAdmin)
		if err != nil {
			return "", "", false, fmt.Errorf("elevate sso admin: %w", err)
		}
		slog.Info("sso login: elevated to admin by IdP group", "user_id", created.ID, "sub", claims.Subject)
		return elevated.ID, auth.TokenRole(elevated.Role), true, nil
	}
	return created.ID, auth.TokenRole(created.Role), true, nil
}

// linkSSOIdentity records the binding, mapping a lost race (the subject or the
// account got linked in between) to the same refusal as any other conflict.
func (u *Usecases) linkSSOIdentity(ctx context.Context, userID, issuer, sub string) error {
	if _, err := u.deps.Stores.Identities.Link(ctx, userID, issuer, sub); err != nil {
		if errors.Is(err, port.ErrIdentityLinked) {
			slog.Warn("sso login: identity linked concurrently", "user_id", userID, "sub", sub)
			return auth.ErrSSONotProvisioned
		}
		return fmt.Errorf("link sso identity: %w", err)
	}
	return nil
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
	email = auth.NormalizeEmail(email)

	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	if err != nil {
		u.burnVerify(password)
		return nil, errors.New(authMsgInvalidCredentials)
	}

	if user.PasswordHash == "" {
		u.burnVerify(password)
		return nil, errors.New(authMsgInvalidCredentials)
	}

	if !u.deps.Passwords.Verify(password, user.PasswordHash) {
		return nil, errors.New(authMsgInvalidCredentials)
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
		return nil, fmt.Errorf(authMsgProjectNotFound, err)
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
		// ingest+read is the documented CI contract: the adapter and CLI
		// ingest a report and then read the gate/findings back with the
		// same key (see cmd/adapter and the dogfood pipeline).
		Scopes:    json.RawMessage(`["ingest","read"]`),
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
		return nil, fmt.Errorf(authMsgProjectNotFound, err)
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
		return fmt.Errorf(authMsgProjectNotFound, err)
	}

	id, err := uuid.Parse(keyID)
	if err != nil {
		return ErrInvalidID
	}

	_, err = u.deps.Stores.APIKeys.Revoke(ctx, id.String(), project.ID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ErrAPIKeyNotFound
		}
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
		return nil, errors.New(authMsgUserNotFound)
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
		return nil, errors.New(authMsgUserNotFound)
	}

	profile := toUserProfile(user)
	return &profile, nil
}

// ListUsers returns the account directory ordered by email, for the admin
// surfaces that pick a user to grant access to. filter matches a
// case-insensitive substring of the email; empty lists every account. The
// password hash never leaves this layer.
func (u *Usecases) ListUsers(ctx context.Context, filter string, limit, offset int32) ([]UserProfile, error) {
	users, err := u.deps.Stores.Users.List(ctx, strings.TrimSpace(filter), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	out := make([]UserProfile, len(users))
	for i, user := range users {
		out[i] = toUserProfile(user)
	}
	return out, nil
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
		return nil, errors.New(authMsgUserNotFound)
	}

	profile := toUserProfile(user)
	return &profile, nil
}

// toUserProfile maps a stored account to its API shape. The password hash is
// deliberately absent: it never crosses this boundary.
func toUserProfile(user port.User) UserProfile {
	name := ""
	if user.DisplayName != nil {
		name = *user.DisplayName
	}
	return UserProfile{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: name,
		Role:        user.Role,
		CreatedAt:   user.CreatedAt.Format(time.RFC3339),
	}
}

func strPtr(s string) *string { return &s }
