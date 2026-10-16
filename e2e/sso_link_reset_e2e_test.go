//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/repo"
)

// TestE2E_OldResetLinkCannotGiveAPasswordToALinkedAccount walks the chain that let a squatter
// keep a way in: someone registers an address they do not own, an administrator hands them a
// reset link, the real owner then signs in through SSO and the account becomes theirs, and the
// squatter redeems the old link. The account must stay password-less, so it cannot become an
// administrator for the squatter through ADMIN_EMAILS either (that promotion needs a proven
// address, which the SSO link just provided).
func TestE2E_OldResetLinkCannotGiveAPasswordToALinkedAccount(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	stores := repo.NewPortStores(pool)

	email := "squatter-" + randomHex(4) + "@example.com"
	oldPass := "squatter-password-" + randomHex(4)
	squatter := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": email, "password": oldPass}, http.StatusCreated)
	link := request[resetLinkResponse](t, http.MethodPost, "/api/v1/users/"+squatter.UserID+"/reset-link",
		adminToken, map[string]string{}, http.StatusCreated)

	// The owner signs in through SSO with a verified email.
	_, _, err = stores.Identities.LinkRevokingKeys(ctx, squatter.UserID, "https://idp.example.com", "sub-"+randomHex(4), true)
	require.NoError(t, err)

	chosen := "chosen-by-the-squatter-" + randomHex(4)
	status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
		map[string]string{"token": resetToken(t, link.Link), "password": chosen})
	require.Equal(t, http.StatusBadRequest, status, string(raw))
	require.Equal(t, "reset_link_invalid", errorCode(t, raw), "the same answer an expired link gets")

	for name, pass := range map[string]string{"the new password": chosen, "the old password": oldPass} {
		status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"email": email, "password": pass})
		require.Equal(t, http.StatusUnauthorized, status, name+" must not sign in")
	}
	status, _ = doJSON(t, http.MethodGet, "/api/v1/me", squatter.Token, nil)
	require.Equal(t, http.StatusUnauthorized, status, "the squatter's session ended with the link")

	var hash *string
	var proven bool
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT password_hash, email_proven FROM users WHERE id = $1", squatter.UserID).Scan(&hash, &proven))
	require.Nil(t, hash, "the account stays password-less")
	require.True(t, proven, "the owner's SSO link proved the address")

	status, _ = doJSON(t, http.MethodPost, "/api/v1/users/"+squatter.UserID+"/reset-link", adminToken, map[string]string{})
	require.Equal(t, http.StatusConflict, status, "no new link is issued for an SSO account either")
}
