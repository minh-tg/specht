package auth

import (
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimIsTrue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want bool
	}{
		{"boolean true", true, true},
		{"boolean false", false, false},
		{"string true", "true", true},
		{"string true any case, padded", " TRUE ", true},
		{"string false", "false", false},
		{"unrecognised string", "yes", false},
		{"number is not a verdict", float64(1), false},
		{"absent claim", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, claimIsTrue(tc.in))
		})
	}
}

// ssoCallbackFixture drives a callback against a fake provider whose userinfo
// reports emailVerified (nil omits the claim) and whose id_token carries the
// optional extra claims.
func ssoCallbackFixture(t *testing.T, userinfoVerified any, idTokenExtra ...jwt.MapClaims) (*fakeOIDCProvider, SSOClaims) {
	t.Helper()
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)
	_, nonce := splitStateNonce(state)

	prov := newFakeOIDCProvider(t, key)
	prov.userEmailVerified = userinfoVerified
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", nonce, idTokenExtra...)

	w, claims := callbackClaims(t, mustOIDC(t, prov.srv.URL), state)
	require.Equal(t, http.StatusFound, w.Code)
	return prov, claims
}

func TestOIDC_Callback_PassesIssuerSubjectAndVerifiedEmail(t *testing.T) {
	prov, claims := ssoCallbackFixture(t, true)

	assert.Equal(t, prov.srv.URL, claims.Issuer, "the provider that vouched for the identity")
	assert.Equal(t, "oidc-user-1", claims.Subject)
	assert.Equal(t, "oidc@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
}

func TestOIDC_Callback_EmailVerifiedFollowsTheProviderClaim(t *testing.T) {
	tests := []struct {
		name     string
		userinfo any
		want     bool
	}{
		{"boolean true", true, true},
		{"string true", "true", true},
		{"boolean false", false, false},
		{"unrecognised string", "yes", false},
		{"claim absent", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, claims := ssoCallbackFixture(t, tc.userinfo)
			assert.Equal(t, tc.want, claims.EmailVerified)
		})
	}
}

func TestOIDC_Callback_SignedIDTokenCanVetoAVerifiedEmail(t *testing.T) {
	_, claims := ssoCallbackFixture(t, true, jwt.MapClaims{"email_verified": false})

	assert.False(t, claims.EmailVerified, "an explicit email_verified=false in the signed id_token wins over userinfo")
}

func TestOIDC_Callback_SignedIDTokenAloneDoesNotVouchForUserinfoEmail(t *testing.T) {
	_, claims := ssoCallbackFixture(t, nil, jwt.MapClaims{"email_verified": true})

	assert.False(t, claims.EmailVerified, "the address comes from userinfo, so userinfo has to vouch for it")
}
