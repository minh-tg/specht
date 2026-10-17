package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// emailCharacterEndpoints are the three endpoints that take a new address.
// status is the answer a refused address already gets there, and genericCode
// is the code for any other refused address.
var emailCharacterEndpoints = map[string]struct {
	call        func(t *testing.T, mock *mockUsecases, err error) *httptest.ResponseRecorder
	status      int
	genericCode string
}{
	"register": {
		call: func(_ *testing.T, mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.registerFn = func(context.Context, string, string) (*usecase.AuthResponse, error) { return nil, err }
			return postJSON(testRouter(mock), "/api/v1/auth/register", `{"email":"a@example.com","password":"x"}`)
		},
		status:      http.StatusUnprocessableEntity,
		genericCode: "registration_failed",
	},
	"setup": {
		call: func(t *testing.T, mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.setupFn = func(context.Context, usecase.SetupInput) (*usecase.AuthResponse, error) { return nil, err }
			return postSetup(t, mock, `{"token":"x","email":"a@example.com","password":"x"}`)
		},
		status:      http.StatusBadRequest,
		genericCode: "invalid_credentials",
	},
	"invite join": {
		call: func(t *testing.T, mock *mockUsecases, err error) *httptest.ResponseRecorder {
			mock.acceptInviteFn = func(context.Context, string, usecase.AcceptInviteInput) (*usecase.AcceptInviteResponse, error) {
				return nil, err
			}
			return inviteRequest(t, mock, "POST", "/api/v1/invites/tok123/accept", "", `{"email":"a@example.com","password":"x"}`)
		},
		status:      http.StatusBadRequest,
		genericCode: "invalid_credentials",
	},
}

// A refused address with a hidden character answers invalid_email_characters
// at the endpoint's usual status, and every other refused address keeps the
// generic code.
func TestEmailCharacterErrors_HaveTheirOwnCode(t *testing.T) {
	for name, ep := range emailCharacterEndpoints {
		t.Run(name+" hidden characters", func(t *testing.T) {
			w := ep.call(t, &mockUsecases{}, usecase.ErrInvalidEmailCharacters)

			require.Equal(t, ep.status, w.Code, w.Body.String())
			code, message := errorBody(t, w)
			assert.Equal(t, "invalid_email_characters", code)
			assert.Equal(t, "invalid email address", message)
		})
		t.Run(name+" other address", func(t *testing.T) {
			w := ep.call(t, &mockUsecases{}, usecase.NewCredentialInputError("invalid email address"))

			require.Equal(t, ep.status, w.Code, w.Body.String())
			assert.Equal(t, ep.genericCode, errorCodeOf(t, w))
		})
	}
}
