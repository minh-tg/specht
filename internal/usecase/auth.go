package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	// Disabled is true for a deactivated account, which keeps its history and
	// memberships but cannot sign in. DisabledAt says since when.
	Disabled   bool    `json:"disabled"`
	DisabledAt *string `json:"disabled_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
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
	// CreatorIsMember is set on list responses only. It is false when the
	// person who created the key is no longer a direct or team member of the
	// project; the key still works.
	CreatorIsMember *bool `json:"creator_is_member,omitempty"`
}

// ErrInvalidCredentialInput wraps the reasons a new account's email or password
// is refused. The message says what to fix.
var ErrInvalidCredentialInput = errors.New("invalid email or password")

type credentialInputError struct{ message string }

// NewCredentialInputError builds a credential rule violation whose message
// tells the person what to fix. Callers outside the package use it to report
// the same class of error the password rules produce.
func NewCredentialInputError(message string) error { return badCredentials(message) }

func (e *credentialInputError) Error() string        { return e.message }
func (e *credentialInputError) Is(target error) bool { return target == ErrInvalidCredentialInput }

func badCredentials(message string) error { return &credentialInputError{message: message} }

// The password policy errors below are credential input errors too, so
// errors.Is(err, ErrInvalidCredentialInput) holds for them. Handlers match
// them first to give each its own code.
var (
	// ErrPasswordTooCommon means the password is on the embedded list of
	// commonly used passwords.
	ErrPasswordTooCommon = badCredentials("This password is on a list of commonly used passwords. Choose another.")
	// ErrPasswordMatchesAccount means the password equals the account's email
	// address, the part of it before the at sign, or its display name.
	ErrPasswordMatchesAccount = badCredentials("The password must not be your email address or name.")
	// ErrPasswordNotVisible means the password holds only white space,
	// invisible code points or combining marks. It is a plain credential input
	// error, so each endpoint answers it with its generic password code.
	ErrPasswordNotVisible = badCredentials("The password must contain visible characters.")
)

// validateCredentials checks the email address and password of a new account
// and returns the address in its normal form. displayName is the name the
// account will carry, or empty.
func validateCredentials(email, password, displayName string) (string, error) {
	if email == "" || password == "" {
		return "", badCredentials("email and password are required")
	}
	if err := checkEmailLength(email); err != nil {
		return "", badCredentials(err.Error())
	}
	if err := checkDisplayNameLength(displayName); err != nil {
		return "", badCredentials(err.Error())
	}
	normalized, err := normalizeAddress(email)
	if err != nil {
		return "", err
	}
	if err := checkPassword(password, normalized, displayName); err != nil {
		return "", err
	}
	return normalized, nil
}

// validateEmail checks one email address the way every way of creating an
// account does and returns it in its normal form: within the length limit, a
// bare address with no display name, no control character, and spelled in runes
// that fold the same way in Go and in the database. Callers trim first when the
// source may pad the value.
func validateEmail(email string) (string, error) {
	if err := checkEmailLength(email); err != nil {
		return "", badCredentials(err.Error())
	}
	return normalizeAddress(email)
}

// normalizeAddress is validateEmail after the length check, for callers that
// order their other input checks around it.
func normalizeAddress(email string) (string, error) {
	if strings.ContainsFunc(email, unicode.IsControl) {
		return "", badCredentials("invalid email address")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || !strings.Contains(addr.Address, "@") {
		return "", badCredentials("invalid email address")
	}
	normalized := auth.NormalizeEmail(addr.Address)
	if normalized == "" {
		// A rune that lower-cases differently in Go and in the database.
		return "", badCredentials("invalid email address")
	}
	return normalized, nil
}

// checkPassword holds the password rules every way of choosing a password
// shares: registration, setup, invites, a password change and both resets.
// The minimum counts characters, as the forms do; the maximum counts bytes,
// because 72 bytes is the longest input bcrypt reads. A listed password is
// refused, a password with no visible character is refused, and so is one equal to the account's email, its local part or its
// display name; pass empty strings where the account is not known yet.
func checkPassword(password, email, displayName string) error {
	if utf8.RuneCountInString(password) < 8 {
		return badCredentials("password must be at least 8 characters")
	}
	if len(password) > 72 {
		return badCredentials("password must be at most 72 bytes; some characters, such as emoji, take more than one")
	}
	if !auth.HasVisibleCharacter(password) {
		return ErrPasswordNotVisible
	}
	if auth.IsCommonPassword(password) {
		return ErrPasswordTooCommon
	}
	if auth.PasswordMatchesAccount(password, email, displayName) {
		return ErrPasswordMatchesAccount
	}
	return nil
}

func (u *Usecases) Register(ctx context.Context, email, password string) (*AuthResponse, error) {
	// The password rules run before the duplicate lookup below. Their errors
	// are specific, which is safe only because they come the same way for an
	// address that is registered and one that is not.
	email, err := validateCredentials(email, password, "")
	if err != nil {
		return nil, err
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
	token, err := u.issueAccessToken(ctx, userID, user.Email, auth.RoleViewer)
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
// same provider. A link made while the provider vouched for the email also
// marks the account's address as proven, which ADMIN_EMAILS requires. Otherwise the account is provisioned when the email domain is
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
		if user.DisabledAt != nil {
			slog.Warn("sso login: deactivated account", "user_id", user.ID, "sub", sub)
			return "", "", false, auth.ErrSSONotProvisioned
		}
		slog.Info("sso login: linked account", "user_id", user.ID, "sub", sub)
		return user.ID, auth.TokenRole(user.Role), false, nil
	case !errors.Is(err, port.ErrNotFound):
		return "", "", false, fmt.Errorf("lookup sso identity: %w", err)
	}

	// A first login is matched, linked or provisioned by the provider's email
	// claim, so it has to be an address this server would accept from a person.
	// An empty claim is "no email", handled below; anything else that fails
	// the checks is refused before it reaches a lookup or a stored row.
	var email string
	if raw := strings.TrimSpace(claims.Email); raw != "" || strings.ContainsFunc(claims.Email, unicode.IsControl) {
		// Control characters are checked before the trim, which would hide a
		// trailing newline. An address with no canonical form keeps the answer
		// it always had: it matches no account and is not offered a new one.
		if raw != "" && auth.NormalizeEmail(raw) == "" {
			slog.Warn("sso login: first login with an address that has no canonical form", "sub", sub)
			return "", "", false, auth.ErrSSONotProvisioned
		}
		valid, err := validateEmail(raw)
		if err != nil || strings.ContainsFunc(claims.Email, unicode.IsControl) {
			slog.Warn("sso login: provider sent an invalid email", "sub", sub, "email_bytes", len(claims.Email))
			return "", "", false, auth.ErrSSOInvalidEmail
		}
		email = valid
	}
	if email == "" || (!claims.EmailVerified && !u.deps.SSOAllowUnverifiedEmail) {
		slog.Warn("sso login: first login without a verified email", "email", auth.MaskEmail(email), "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	}

	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	switch {
	case err == nil && user.DisabledAt != nil:
		slog.Warn("sso login: deactivated account", "user_id", user.ID, "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	case err == nil:
		return u.linkExistingSSOUser(ctx, user, issuer, sub, claims.EmailVerified)
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
func (u *Usecases) linkExistingSSOUser(ctx context.Context, user port.User, issuer, sub string, emailVerified bool) (string, string, bool, error) {
	_, err := u.deps.Stores.Identities.GetForUser(ctx, user.ID, issuer)
	switch {
	case err == nil:
		slog.Warn("sso login: account already linked to a different subject", "user_id", user.ID, "sub", sub)
		return "", "", false, auth.ErrSSONotProvisioned
	case !errors.Is(err, port.ErrNotFound):
		return "", "", false, fmt.Errorf("lookup user identity: %w", err)
	}
	// Whoever registered this address first may not be its owner. The store
	// binds the identity and, in the same transaction, drops the password,
	// starts a new token generation, ends the refresh tokens and reset links
	// and revokes the API keys that holder created. A failure rolls all of it
	// back, so the next login retries from the start instead of finding a
	// linked account that still has the old holder's credentials.
	revoked, err := u.linkSSOIdentityRevokingKeys(ctx, user.ID, issuer, sub, emailVerified)
	if err != nil {
		return "", "", false, err
	}
	for _, key := range revoked {
		slog.Warn("sso login: revoked api key created before the link", "user_id", user.ID, "key_id", key.ID, "project", key.ProjectSlug)
	}
	slog.Info("sso login: linked existing account", "user_id", user.ID, "sub", sub, "password_disabled", user.PasswordHash != "", "api_keys_revoked", len(revoked))
	return user.ID, auth.TokenRole(user.Role), false, nil
}

// issueAccessToken mints an access token bound to the account's current token
// generation, so bumping that generation later invalidates the token.
func (u *Usecases) issueAccessToken(ctx context.Context, userID, email, role string) (string, error) {
	version, err := u.deps.Stores.Users.TokenVersion(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("load token version: %w", err)
	}
	return u.deps.Tokens.CreateToken(userID, email, role, version)
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
	if err := u.linkSSOIdentity(ctx, created.ID, claims.Issuer, claims.Subject, claims.EmailVerified); err != nil {
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
// emailVerified says whether the provider vouched for the account's email; the
// store marks the address as proven in the same write, and a login that got
// through only on SSO_ALLOW_UNVERIFIED_EMAIL leaves it unproven.
func (u *Usecases) linkSSOIdentity(ctx context.Context, userID, issuer, sub string, emailVerified bool) error {
	if _, err := u.deps.Stores.Identities.Link(ctx, userID, issuer, sub, emailVerified); err != nil {
		if errors.Is(err, port.ErrIdentityLinked) {
			slog.Warn("sso login: identity linked concurrently", "user_id", userID, "sub", sub)
			return auth.ErrSSONotProvisioned
		}
		return fmt.Errorf("link sso identity: %w", err)
	}
	return nil
}

// linkSSOIdentityRevokingKeys links like linkSSOIdentity and also ends every
// credential the account held before the link: password, sessions, reset links
// and the API keys it created. emailVerified is passed on to the store, which
// marks the address as proven in the same write.
func (u *Usecases) linkSSOIdentityRevokingKeys(ctx context.Context, userID, issuer, sub string, emailVerified bool) ([]port.RevokedAPIKey, error) {
	_, revoked, err := u.deps.Stores.Identities.LinkRevokingKeys(ctx, userID, issuer, sub, emailVerified)
	if err != nil {
		if errors.Is(err, port.ErrIdentityLinked) {
			slog.Warn("sso login: identity linked concurrently", "user_id", userID, "sub", sub)
			return nil, auth.ErrSSONotProvisioned
		}
		if errors.Is(err, port.ErrAccountDeactivated) {
			// Deactivated after the read that said otherwise.
			slog.Warn("sso login: account deactivated before the link", "user_id", userID, "sub", sub)
			return nil, auth.ErrSSONotProvisioned
		}
		return nil, fmt.Errorf("link sso identity: %w", err)
	}
	return revoked, nil
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
	if user.DisabledAt != nil {
		// Same answer as a wrong password, so the response does not tell
		// whoever holds the password that the account exists but is off.
		slog.Warn("login: deactivated account", "user_id", user.ID)
		return nil, errors.New(authMsgInvalidCredentials)
	}

	// The checks above ran on a read taken before the password verify, which
	// takes tens of milliseconds. An SSO link, a password change or a
	// deactivation can commit inside that window, so the store confirms the
	// account is unchanged under a row lock when it stores the session.
	resp, version, err := u.createLoginSession(ctx, user)
	if errors.Is(err, port.ErrLoginStale) {
		slog.Warn("login: account changed during the password check", "user_id", user.ID)
		return nil, errors.New(authMsgInvalidCredentials)
	}
	if err != nil {
		return nil, err
	}
	token, err := u.deps.Tokens.CreateToken(user.ID, user.Email, auth.TokenRole(user.Role), version)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	resp.Token = token
	return resp, nil
}

// requireProjectKeyManager lets a project manager or admin manage the
// project's API keys. A key never manages keys.
func (u *Usecases) requireProjectKeyManager(ctx context.Context, projectID string) error {
	return u.requireProjectManager(ctx, projectID)
}

func (u *Usecases) CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string, expiresAt *time.Time) (*APIKeyResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(authMsgProjectNotFound, err)
	}
	if err := u.requireProjectKeyManager(ctx, project.ID); err != nil {
		return nil, err
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
		// The session's token generation, so a key request that
		// authenticated before an SSO link or a deactivation committed
		// is refused after it.
		CreatorTokenVersion: sessionTokenVersion(ctx, creatorID.String()),
	})
	if err != nil {
		if errors.Is(err, port.ErrCreatorInactive) {
			// The creator was deactivated, or started a new token generation
			// (an SSO link does), after authentication. The store refuses
			// under a row lock that both also take, so no key outlives the
			// credentials it was requested with.
			return nil, ErrProjectAccessDenied
		}
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

// sessionTokenVersion returns the token generation the request's session
// authenticated with, or nil when the request is not a versioned session of
// userID.
func sessionTokenVersion(ctx context.Context, userID string) *int32 {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey || ident.UserID != userID {
		return nil
	}
	return ident.TokenVersion
}

func (u *Usecases) ListAPIKeys(ctx context.Context, projectSlug string) ([]APIKeyResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(authMsgProjectNotFound, err)
	}
	if err := u.requireProjectKeyManager(ctx, project.ID); err != nil {
		return nil, err
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
		creatorIsMember := k.CreatorIsMember
		resp[i] = APIKeyResponse{
			ID:              k.ID,
			Name:            k.Name,
			KeyPrefix:       k.KeyPrefix,
			LastFour:        strPtr(lf),
			CreatedAt:       k.CreatedAt.Format(time.RFC3339),
			CreatorIsMember: &creatorIsMember,
		}
	}
	return resp, nil
}

func (u *Usecases) RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf(authMsgProjectNotFound, err)
	}
	if err := u.requireProjectKeyManager(ctx, project.ID); err != nil {
		return err
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

// ErrRefreshReused is returned when a refresh token that was already spent is
// presented again. Either a client refreshed twice with one token or someone
// else holds a copy, and the two cannot be told apart, so the sign-in chain the
// token belongs to is revoked. Handlers map it to a 401 with its own code so
// the client can tell the user the session ended.
var ErrRefreshReused = errors.New("refresh token was already used")

const (
	// refreshReuseGrace is how long after rotation a replay of the old token
	// is still answered as a benign race and leaves the session alone. It is
	// zero: a thief who refreshes inside any window gets the successor, and
	// the owner's own refresh then looks like the retry. The web client keeps
	// one refresh in flight at a time, so a valid client never replays.
	refreshReuseGrace time.Duration = 0
	// refreshTokenTTL is how long one refresh token stays valid. Rotation
	// renews it, up to the session's absolute lifetime.
	refreshTokenTTL = 7 * 24 * time.Hour
	// DefaultSessionMaxAge is the absolute session lifetime when none is
	// configured.
	DefaultSessionMaxAge = 30 * 24 * time.Hour
)

// clock returns the current time, from the injected clock when there is one.
func (u *Usecases) clock() time.Time {
	if u.deps.Now != nil {
		return u.deps.Now()
	}
	return time.Now()
}

func (u *Usecases) sessionMaxAge() time.Duration {
	if u.deps.SessionMaxAge > 0 {
		return u.deps.SessionMaxAge
	}
	return DefaultSessionMaxAge
}

// createSession starts a new sign-in: a refresh token that heads a new family
// whose start time is now.
func (u *Usecases) createSession(ctx context.Context, userID, email string) (*AuthResponse, error) {
	return u.storeSession(ctx, userID, email, uuid.NewString(), u.clock())
}

// createLoginSession starts the sign-in of a password login. The store checks
// the account against the row the login read before its password check and
// refuses with port.ErrLoginStale when it changed. It returns the token
// generation read under the lock, which the access token must carry.
func (u *Usecases) createLoginSession(ctx context.Context, user port.User) (*AuthResponse, int32, error) {
	var version int32
	resp, err := u.newSession(user.ID, user.Email, uuid.NewString(), u.clock(), func(in port.NewRefreshToken) error {
		var err error
		version, err = u.deps.Stores.RefreshTokens.CreateForLogin(ctx, in, port.LoginGuard{
			PasswordHash: user.PasswordHash,
			TokenVersion: user.TokenVersion,
		})
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return resp, version, nil
}

// storeSession issues a refresh token in the given family. The token lasts
// one refresh period but never past the end of the session, so a family that
// is close to its absolute lifetime cannot hold a token beyond it.
func (u *Usecases) storeSession(ctx context.Context, userID, email, familyID string, familyStartedAt time.Time) (*AuthResponse, error) {
	return u.newSession(userID, email, familyID, familyStartedAt, func(in port.NewRefreshToken) error {
		_, err := u.deps.Stores.RefreshTokens.Create(ctx, in)
		return err
	})
}

// newSession mints a refresh token and hands its row to store.
func (u *Usecases) newSession(userID, email, familyID string, familyStartedAt time.Time, store func(port.NewRefreshToken) error) (*AuthResponse, error) {
	rawRefresh, err := u.deps.Tokens.CreateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	hash := sha256.Sum256([]byte(rawRefresh))
	hashStr := hex.EncodeToString(hash[:])

	expiresAt := u.clock().Add(refreshTokenTTL)
	if end := familyStartedAt.Add(u.sessionMaxAge()); end.Before(expiresAt) {
		expiresAt = end
	}
	if err := store(port.NewRefreshToken{
		UserID:          userID,
		TokenHash:       hashStr,
		ExpiresAt:       expiresAt,
		FamilyID:        familyID,
		FamilyStartedAt: familyStartedAt,
	}); err != nil {
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

	now := u.clock()
	if stored.RevokedAt != nil {
		return nil, u.refuseReuse(ctx, stored, *stored.RevokedAt)
	}

	if stored.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("refresh token has expired")
	}
	// A chain of rotations renews a week at a time. The absolute lifetime
	// ends it anyway, so a deprovisioned or stolen session cannot be kept
	// alive by refreshing. The caller sees the same error as an expired token.
	if !now.Before(stored.FamilyStartedAt.Add(u.sessionMaxAge())) {
		return nil, fmt.Errorf("refresh token has expired")
	}

	// The account is read before the token is spent, so the generation the
	// store checks at rotation is one that predates this refresh. A password
	// change, a reset or an SSO link that commits after the read bumps it and
	// the store refuses the successor; one that committed before the read has
	// already revoked this token.
	userID := stored.UserID
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New(authMsgUserNotFound)
	}
	if user.DisabledAt != nil {
		return nil, errors.New(authMsgUserNotFound)
	}

	// Rotation is atomic: the store spends the old token (a compare-and-swap
	// on revoked_at) and stores the successor in one transaction. A second,
	// concurrent rotation of the same token matches zero rows and surfaces as
	// ErrNotFound; only the single winner proceeds.
	resp, err := u.newSession(userID, user.Email, stored.FamilyID, stored.FamilyStartedAt, func(in port.NewRefreshToken) error {
		return u.deps.Stores.RefreshTokens.Rotate(ctx, stored.ID, in, user.TokenVersion)
	})
	if errors.Is(err, port.ErrNotFound) {
		// Another request rotated this token between our read and our
		// rotation, so this is a second use of it.
		return nil, u.refuseReuse(ctx, stored, now)
	}
	if errors.Is(err, port.ErrSessionStale) {
		slog.Warn("refresh: account changed during the refresh", "user_id", userID)
		return nil, errors.New("refresh token has been revoked")
	}
	if err != nil {
		return nil, err
	}

	token, err := u.deps.Tokens.CreateToken(userID, user.Email, auth.TokenRole(user.Role), user.TokenVersion)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	resp.Token = token
	return resp, nil
}

// refuseReuse handles a refresh token that was spent at rotatedAt and is
// presented again. Whoever holds it may have stolen it, so the sign-in chain it
// belongs to is revoked, successor included; the user's other sign-ins are
// separate chains and stay. A replay inside refreshReuseGrace is left alone.
// Refresh and Logout both come through here, so a stale token cannot be used
// to sign out without tripping the same detection.
func (u *Usecases) refuseReuse(ctx context.Context, stored port.RefreshToken, rotatedAt time.Time) error {
	if refreshReuseGrace > 0 && u.clock().Sub(rotatedAt) < refreshReuseGrace {
		return ErrRefreshReused
	}
	if err := u.deps.Stores.RefreshTokens.RevokeFamily(ctx, stored.FamilyID); err != nil {
		slog.Error("refresh: revoke family after reuse", "user_id", stored.UserID, "family_id", stored.FamilyID, "error", err)
	}
	return ErrRefreshReused
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

	// A token that was already spent is a replay, whether it comes to
	// refresh or to sign out. Revoke the chain the way a refresh would; the
	// caller still gets the logout it asked for.
	if stored.RevokedAt != nil {
		_ = u.refuseReuse(ctx, stored, *stored.RevokedAt)
		return nil
	}

	// Revoke is a guarded compare-and-swap: when a refresh spends the token
	// between the read above and this call it matches zero rows and reports
	// ErrNotFound. That is a replay too.
	_, err = u.deps.Stores.RefreshTokens.Revoke(ctx, stored.ID)
	if errors.Is(err, port.ErrNotFound) {
		_ = u.refuseReuse(ctx, stored, u.clock())
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
			if err := checkDisplayNameLength(trimmed); err != nil {
				return nil, fmt.Errorf("%w: %s", ErrInvalidProfileInput, err)
			}
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

// ErrWrongPassword means the current password given to ChangePassword did not
// match the account's password.
var ErrWrongPassword = errors.New("current password is incorrect")

// ErrNoLocalPassword means the account has no password because it signs in
// through an identity provider, so there is nothing to change.
var ErrNoLocalPassword = errors.New("this account has no local password")

// ErrAccountChanged means the password change committed but the account changed
// again (an SSO link, another change, a deactivation) before the caller's new
// session was stored, so no session was issued. The caller signs in again.
var ErrAccountChanged = errors.New("account changed after the password change")

// ChangePassword replaces the caller's password after checking the current one.
// The store writes the hash, starts a new token generation (which ends every
// open access token) and revokes every refresh token in one transaction under
// the account row lock, so a failure never leaves an old session alive beside a
// new password and a login in flight cannot keep a session. If the hash changed
// since the check, nothing is written and the current password counts as wrong.
// The caller gets a fresh session back and stays signed in. That session is
// stored against the hash and token generation the change wrote, the way a
// password login stores its own, so an account change that commits right after
// the password change refuses it with ErrAccountChanged instead of leaving a
// session under a generation that change did not expect.
func (u *Usecases) ChangePassword(ctx context.Context, userID, current, next string) (*AuthResponse, error) {
	id, err := validID(userID)
	if err != nil {
		return nil, err
	}
	if next == current {
		return nil, badCredentials("the new password must differ from the current one")
	}

	user, err := u.deps.Stores.Users.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user.PasswordHash == "" {
		return nil, ErrNoLocalPassword
	}
	if err := checkPassword(next, user.Email, derefStr(user.DisplayName)); err != nil {
		return nil, err
	}
	if !u.deps.Passwords.Verify(current, user.PasswordHash) {
		return nil, ErrWrongPassword
	}

	hash, err := u.deps.Passwords.Hash(next)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	version, err := u.deps.Stores.Users.ChangePasswordAndRevoke(ctx, id, hash, user.PasswordHash)
	if errors.Is(err, port.ErrPasswordStale) {
		return nil, ErrWrongPassword
	}
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	changed := port.User{ID: id, Email: user.Email, PasswordHash: hash, TokenVersion: version}
	resp, version, err := u.createLoginSession(ctx, changed)
	if errors.Is(err, port.ErrLoginStale) {
		slog.Warn("change password: account changed after the password change", "user_id", id)
		return nil, ErrAccountChanged
	}
	if err != nil {
		return nil, err
	}
	token, err := u.deps.Tokens.CreateToken(id, user.Email, auth.TokenRole(user.Role), version)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	resp.Token = token
	return resp, nil
}

// toUserProfile maps a stored account to its API shape. The password hash is
// deliberately absent: it never crosses this boundary.
func toUserProfile(user port.User) UserProfile {
	name := ""
	if user.DisplayName != nil {
		name = *user.DisplayName
	}
	profile := UserProfile{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: name,
		Role:        user.Role,
		Disabled:    user.DisabledAt != nil,
		CreatedAt:   user.CreatedAt.Format(time.RFC3339),
	}
	if user.DisabledAt != nil {
		since := user.DisabledAt.Format(time.RFC3339)
		profile.DisabledAt = &since
	}
	return profile
}

func strPtr(s string) *string { return &s }

// CreateSSOExchangeCode issues a high-entropy, short-lived (60s) single-use authorization code
// for an authenticated SSO identity. The code is delivered to the browser and exchanged via
// ExchangeSSOCode for session tokens, ensuring no bearer tokens appear in URL fragments.
func (u *Usecases) CreateSSOExchangeCode(ctx context.Context, userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate sso exchange code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(code))
	codeHash := hex.EncodeToString(hash[:])

	expiresAt := time.Now().Add(60 * time.Second)
	if err := u.deps.Stores.SSOCodes.Create(ctx, codeHash, userID, expiresAt); err != nil {
		return "", fmt.Errorf("store sso exchange code: %w", err)
	}
	return code, nil
}

// ExchangeSSOCode atomically consumes an SSO exchange code and returns an AuthResponse
// containing both an access token and a refresh token with rotation. Replayed, expired,
// or non-existent codes fail closed.
func (u *Usecases) ExchangeSSOCode(ctx context.Context, code string) (*AuthResponse, error) {
	if code == "" {
		return nil, auth.ErrInvalidCredential
	}
	hash := sha256.Sum256([]byte(code))
	codeHash := hex.EncodeToString(hash[:])

	ssoCode, err := u.deps.Stores.SSOCodes.Consume(ctx, codeHash, time.Now())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, auth.ErrInvalidCredential
		}
		return nil, fmt.Errorf("consume sso exchange code: %w", err)
	}

	user, err := u.deps.Stores.Users.GetByID(ctx, ssoCode.UserID)
	if err != nil || user.DisabledAt != nil {
		return nil, auth.ErrInvalidCredential
	}

	token, err := u.issueAccessToken(ctx, user.ID, user.Email, auth.TokenRole(user.Role))
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	resp, err := u.createSession(ctx, user.ID, user.Email)
	if err != nil {
		return nil, err
	}
	resp.Token = token
	return resp, nil
}
