package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	defaultInviteDays = 7
	maxInviteDays     = 30
	// maxPendingInvites bounds the open links a project can accumulate.
	maxPendingInvites = 100
	// maxInviteTokenLength rejects absurd path values before they are hashed.
	maxInviteTokenLength = 128
	invitePathPrefix     = "/invite/"
)

var (
	// ErrInviteNotFound covers every way a link can be dead: unknown, used,
	// revoked or expired. They answer the same, so a link cannot be probed.
	ErrInviteNotFound = errors.New("invite not found")
	// ErrInviteEmailMismatch is returned when the invite is bound to another address.
	ErrInviteEmailMismatch = errors.New("invite is for another email address")
	// ErrInvalidInviteRole is returned for a role an invite cannot carry.
	ErrInvalidInviteRole = errors.New("invalid invite role")
	// ErrInvalidInviteInput is returned for a malformed email or expiry.
	ErrInvalidInviteInput = errors.New("invalid invite")
	// ErrTooManyInvites is returned when a project has too many open links.
	ErrTooManyInvites = errors.New("too many pending invites")
)

// CreateInviteInput describes a link to create. Role is member or manager.
type CreateInviteInput struct {
	Role          string
	Email         string
	ExpiresInDays int
}

// InviteResponse is an invite as a project manager sees it. Link is set only
// on the response to creation: the token is not stored and cannot be shown again.
type InviteResponse struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	Email     string `json:"email,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Link      string `json:"link,omitempty"`
}

// InviteLookupResponse is what the accept page learns from a link.
type InviteLookupResponse struct {
	ProjectName string `json:"project_name"`
	Role        string `json:"role"`
	Email       string `json:"email,omitempty"`
}

// AcceptInviteInput is the account a newcomer creates through a link.
type AcceptInviteInput struct {
	Email       string
	Password    string
	DisplayName string
}

// AcceptInviteResponse is the new session plus the project it landed in.
type AcceptInviteResponse struct {
	AuthResponse
	ProjectSlug string `json:"project_slug"`
	Role        string `json:"role"`
}

// JoinInviteResponse reports the project a signed-in person joined.
type JoinInviteResponse struct {
	ProjectSlug string `json:"project_slug"`
	Role        string `json:"role"`
}

func hashInviteToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newInviteToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate invite token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func inviteTokenHash(token string) (string, error) {
	if token == "" || len(token) > maxInviteTokenLength {
		return "", ErrInviteNotFound
	}
	return hashInviteToken(token), nil
}

func toInviteResponse(inv port.Invite) InviteResponse {
	resp := InviteResponse{
		ID:        inv.ID,
		Role:      inv.Role,
		CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
	}
	if inv.Email != nil {
		resp.Email = *inv.Email
	}
	if inv.CreatedByEmail != nil {
		resp.CreatedBy = *inv.CreatedByEmail
	}
	return resp
}

// requireInviteManager resolves the project and checks that the caller may
// manage its members, the same bar as adding a member directly. It returns the
// project and the caller's role.
func (u *Usecases) requireInviteManager(ctx context.Context, projectSlug string) (port.Project, string, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.Project{}, "", ErrProjectAccessDenied
		}
		return port.Project{}, "", fmt.Errorf("lookup project: %w", err)
	}
	callerRole, err := u.callerProjectRole(ctx, p.ID)
	if err != nil {
		return port.Project{}, "", err
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return port.Project{}, "", ErrProjectAccessDenied
	}
	return p, callerRole, nil
}

// CreateInvite makes a single-use link that adds a person to the project. A
// manager can invite up to their own role, the same ceiling as adding a member.
func (u *Usecases) CreateInvite(ctx context.Context, projectSlug string, in CreateInviteInput) (*InviteResponse, error) {
	role := normalizeMemberRole(in.Role)
	if role != auth.RoleMember && role != auth.RoleManager {
		return nil, fmt.Errorf("%w %q: must be member or manager", ErrInvalidInviteRole, in.Role)
	}
	days := in.ExpiresInDays
	if days == 0 {
		days = defaultInviteDays
	}
	if days < 1 || days > maxInviteDays {
		return nil, fmt.Errorf("%w: expires_in_days must be between 1 and %d", ErrInvalidInviteInput, maxInviteDays)
	}
	var email *string
	if trimmed := strings.TrimSpace(in.Email); trimmed != "" {
		addr, err := mail.ParseAddress(trimmed)
		if err != nil || addr.Address != trimmed {
			return nil, fmt.Errorf("%w: invalid email address", ErrInvalidInviteInput)
		}
		normalized := auth.NormalizeEmail(addr.Address)
		email = &normalized
	}

	p, callerRole, err := u.requireInviteManager(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	if auth.RoleRank(role) > auth.RoleRank(callerRole) {
		return nil, ErrProjectAccessDenied
	}
	pending, err := u.deps.Stores.Invites.CountPending(ctx, p.ID)
	if err != nil {
		return nil, fmt.Errorf("count invites: %w", err)
	}
	if pending >= maxPendingInvites {
		return nil, ErrTooManyInvites
	}

	token, err := newInviteToken()
	if err != nil {
		return nil, err
	}
	ident := auth.ContextIdentity(ctx)
	inv, err := u.deps.Stores.Invites.Create(ctx, port.NewInvite{
		TokenHash: hashInviteToken(token),
		ProjectID: p.ID,
		Role:      role,
		Email:     email,
		CreatedBy: ident.UserID,
		ExpiresAt: time.Now().Add(time.Duration(days) * 24 * time.Hour),
	})
	if err != nil {
		return nil, fmt.Errorf("create invite: %w", err)
	}
	resp := toInviteResponse(inv)
	resp.Link = invitePathPrefix + token
	return &resp, nil
}

// ListInvites returns the project's open links, newest first, without tokens.
func (u *Usecases) ListInvites(ctx context.Context, projectSlug string) ([]InviteResponse, error) {
	p, _, err := u.requireInviteManager(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	invites, err := u.deps.Stores.Invites.ListPending(ctx, p.ID)
	if err != nil {
		return nil, fmt.Errorf("list invites: %w", err)
	}
	out := make([]InviteResponse, len(invites))
	for i, inv := range invites {
		out[i] = toInviteResponse(inv)
	}
	return out, nil
}

// RevokeInvite kills an open link. A manager cannot revoke a link that carries
// a role above their own.
func (u *Usecases) RevokeInvite(ctx context.Context, projectSlug, inviteID string) (*InviteResponse, error) {
	if _, err := validID(inviteID); err != nil {
		return nil, err
	}
	p, callerRole, err := u.requireInviteManager(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	existing, err := u.deps.Stores.Invites.GetPending(ctx, p.ID, inviteID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("lookup invite: %w", err)
	}
	if auth.RoleRank(existing.Role) > auth.RoleRank(callerRole) {
		return nil, ErrProjectAccessDenied
	}
	inv, err := u.deps.Stores.Invites.Revoke(ctx, p.ID, inviteID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("revoke invite: %w", err)
	}
	resp := toInviteResponse(inv)
	return &resp, nil
}

// LookupInvite tells the holder of a link what it is for. Any dead link
// returns ErrInviteNotFound.
func (u *Usecases) LookupInvite(ctx context.Context, token string) (*InviteLookupResponse, error) {
	hash, err := inviteTokenHash(token)
	if err != nil {
		return nil, err
	}
	view, err := u.deps.Stores.Invites.Lookup(ctx, hash)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("lookup invite: %w", err)
	}
	resp := &InviteLookupResponse{ProjectName: view.ProjectName, Role: view.Role}
	if view.Email != nil {
		resp.Email = *view.Email
	}
	return resp, nil
}

// AcceptInvite creates an account through a link, adds it to the project and
// signs it in. It works while self-service registration is closed.
func (u *Usecases) AcceptInvite(ctx context.Context, token string, in AcceptInviteInput) (*AcceptInviteResponse, error) {
	hash, err := inviteTokenHash(token)
	if err != nil {
		return nil, err
	}
	trimmedName := strings.TrimSpace(in.DisplayName)
	email, err := validateCredentials(in.Email, in.Password, trimmedName)
	if err != nil {
		return nil, err
	}
	passwordHash, err := u.deps.Passwords.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	var name *string
	if trimmedName != "" {
		name = &trimmedName
	}

	accepted, err := u.deps.Stores.Invites.AcceptWithNewAccount(ctx, hash, port.InviteeAccount{
		Email: email, DisplayName: name, PasswordHash: passwordHash,
	})
	if err != nil {
		switch {
		case errors.Is(err, port.ErrNotFound):
			return nil, ErrInviteNotFound
		case errors.Is(err, port.ErrInviteEmailMismatch):
			return nil, ErrInviteEmailMismatch
		case errors.Is(err, port.ErrEmailTaken):
			// Same answer as registration, so a link cannot be used to learn
			// which addresses already have an account.
			slog.Warn("invite: email already registered", "email", auth.MaskEmail(email))
			return nil, ErrRegistrationFailed
		}
		return nil, fmt.Errorf("accept invite: %w", err)
	}
	slog.Info("invite accepted", "invite_id", accepted.InviteID, "project", accepted.ProjectSlug, "role", accepted.Role, "user_id", accepted.User.ID)

	accessToken, err := u.issueAccessToken(ctx, accepted.User.ID, accepted.User.Email, auth.RoleViewer)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}
	resp, err := u.createSession(ctx, accepted.User.ID, accepted.User.Email)
	if err != nil {
		return nil, err
	}
	resp.Token = accessToken
	return &AcceptInviteResponse{AuthResponse: *resp, ProjectSlug: accepted.ProjectSlug, Role: accepted.Role}, nil
}

// JoinInvite adds the signed-in caller to the project through a link.
func (u *Usecases) JoinInvite(ctx context.Context, token string) (*JoinInviteResponse, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return nil, ErrProjectAccessDenied
	}
	hash, err := inviteTokenHash(token)
	if err != nil {
		return nil, err
	}
	accepted, err := u.deps.Stores.Invites.AcceptAsUser(ctx, hash, ident.UserID)
	if err != nil {
		switch {
		case errors.Is(err, port.ErrNotFound):
			return nil, ErrInviteNotFound
		case errors.Is(err, port.ErrInviteEmailMismatch):
			return nil, ErrInviteEmailMismatch
		}
		return nil, fmt.Errorf("join invite: %w", err)
	}
	slog.Info("invite joined", "invite_id", accepted.InviteID, "project", accepted.ProjectSlug, "role", accepted.Role, "user_id", ident.UserID)
	return &JoinInviteResponse{ProjectSlug: accepted.ProjectSlug, Role: accepted.Role}, nil
}
