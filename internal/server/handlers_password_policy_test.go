package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// passwordPolicyCases are the two password policy refusals and the code each
// one gets on every endpoint that sets a password.
var passwordPolicyCases = []struct {
	err  error
	code string
}{
	{usecase.ErrPasswordTooCommon, "password_too_common"},
	{usecase.ErrPasswordMatchesAccount, "password_matches_account"},
}

// Every endpoint that sets a password answers a policy refusal with 400, its
// own code and the usecase's message, so the form can show it on the password
// field.
func TestPasswordPolicyErrors_HaveTheirOwnCodes(t *testing.T) {
	endpoints := map[string]func(mock *mockUsecases, err error) *httptest.ResponseRecorder{
		"register": func(mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.registerFn = func(context.Context, string, string) (*usecase.AuthResponse, error) { return nil, err }
			return postJSON(testRouter(mock), "/api/v1/auth/register", `{"email":"a@example.com","password":"x"}`)
		},
		"setup": func(mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.setupFn = func(context.Context, usecase.SetupInput) (*usecase.AuthResponse, error) { return nil, err }
			return postSetup(t, mock, `{"token":"x","email":"a@example.com","password":"x"}`)
		},
		"invite join": func(mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.acceptInviteFn = func(context.Context, string, usecase.AcceptInviteInput) (*usecase.AcceptInviteResponse, error) {
				return nil, err
			}
			return inviteRequest(t, mock, "POST", "/api/v1/invites/tok123/accept", "", `{"email":"a@example.com","password":"x"}`)
		},
		"change password": func(mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.changePasswordFn = func(context.Context, string, string, string) (*usecase.AuthResponse, error) { return nil, err }
			return putPassword(t, mock, `{"current_password":"old-password","new_password":"x"}`, true)
		},
		"reset": func(mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.redeemPasswordReset = func(context.Context, string, string) error { return err }
			return postJSON(testRouter(mock), "/api/v1/auth/reset", `{"token":"tok","password":"x"}`)
		},
	}
	for name, call := range endpoints {
		for _, tc := range passwordPolicyCases {
			t.Run(name+" "+tc.code, func(t *testing.T) {
				w := call(&mockUsecases{}, tc.err)
				require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
				code, message := errorBody(t, w)
				assert.Equal(t, tc.code, code)
				assert.Equal(t, tc.err.Error(), message)
			})
		}
	}
}

// Register keeps every other failure generic, a wrapped duplicate included,
// so the two policy codes are the only specific answers it gives.
func TestRegister_PolicyCodesDoNotOpenOtherFailures(t *testing.T) {
	for name, cause := range map[string]error{
		"duplicate":         usecase.ErrRegistrationFailed,
		"other input error": usecase.NewCredentialInputError("password must be at least 8 characters"),
		"wrapped internal":  fmt.Errorf("create user: %w", usecase.ErrRegistrationFailed),
	} {
		mock := &mockUsecases{registerFn: func(context.Context, string, string) (*usecase.AuthResponse, error) { return nil, cause }}
		w := postJSON(testRouter(mock), "/api/v1/auth/register", `{"email":"a@example.com","password":"x"}`)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, name)
		assert.Equal(t, "registration_failed", errorCodeOf(t, w), name)
	}
}

// A password with no visible character is a plain credential input error. The
// endpoints that already surface those answer it with their generic password
// code and the usecase's message, so the field shows what to fix.
func TestPasswordNotVisible_ReachesTheClientWhereGenericPasswordErrorsDo(t *testing.T) {
	err := usecase.ErrPasswordNotVisible
	endpoints := map[string]struct {
		code string
		call func(mock *mockUsecases) *httptest.ResponseRecorder
	}{
		"setup": {"invalid_credentials", func(mock *mockUsecases) *httptest.ResponseRecorder {
			mock.setupFn = func(context.Context, usecase.SetupInput) (*usecase.AuthResponse, error) { return nil, err }
			return postSetup(t, mock, `{"token":"x","email":"a@example.com","password":"x"}`)
		}},
		"invite join": {"invalid_credentials", func(mock *mockUsecases) *httptest.ResponseRecorder {
			mock.acceptInviteFn = func(context.Context, string, usecase.AcceptInviteInput) (*usecase.AcceptInviteResponse, error) {
				return nil, err
			}
			return inviteRequest(t, mock, "POST", "/api/v1/invites/tok123/accept", "", `{"email":"a@example.com","password":"x"}`)
		}},
		"change password": {"invalid_password", func(mock *mockUsecases) *httptest.ResponseRecorder {
			mock.changePasswordFn = func(context.Context, string, string, string) (*usecase.AuthResponse, error) { return nil, err }
			return putPassword(t, mock, `{"current_password":"old-password","new_password":"x"}`, true)
		}},
		"reset": {"invalid_password", func(mock *mockUsecases) *httptest.ResponseRecorder {
			mock.redeemPasswordReset = func(context.Context, string, string) error { return err }
			return postJSON(testRouter(mock), "/api/v1/auth/reset", `{"token":"tok","password":"x"}`)
		}},
	}
	for name, tc := range endpoints {
		t.Run(name, func(t *testing.T) {
			w := tc.call(&mockUsecases{})
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			code, message := errorBody(t, w)
			assert.Equal(t, tc.code, code)
			assert.Equal(t, "The password must contain visible characters.", message)
		})
	}
}
