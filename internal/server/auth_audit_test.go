package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/usecase"
)

func auditedRequest(t *testing.T, mock *mockUsecases, call func(*Handler, http.ResponseWriter, *http.Request), path, body string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	h := NewHandler(mock)
	h.audit = audit.NewLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.77:51234"
	w := httptest.NewRecorder()
	call(h, w, req)
	return w.Code, buf.String()
}

func TestRefresh_ReuseWritesAnAuditLineWithoutTheToken(t *testing.T) {
	mock := &mockUsecases{refreshFn: func(context.Context, string) (*usecase.AuthResponse, error) {
		return nil, usecase.ErrRefreshReused
	}}

	code, logged := auditedRequest(t, mock, (*Handler).Refresh, "/api/v1/auth/refresh", `{"refresh_token":"spent-token-value"}`)

	require.Equal(t, http.StatusUnauthorized, code)
	assert.Contains(t, logged, "audit=auth.refresh")
	assert.Contains(t, logged, "outcome=failure")
	assert.Contains(t, logged, "target=192.0.2.77")
	assert.NotContains(t, logged, "spent-token-value")
}

func TestSetup_WrongTokenWritesAnAuditLineWithoutTheToken(t *testing.T) {
	mock := &mockUsecases{setupFn: func(context.Context, usecase.SetupInput) (*usecase.AuthResponse, error) {
		return nil, usecase.ErrInvalidSetupToken
	}}

	code, logged := auditedRequest(t, mock, (*Handler).Setup, "/api/v1/setup",
		`{"token":"guessed-setup-token","email":"a@example.com","password":"a-long-unlisted-phrase"}`)

	require.Equal(t, http.StatusForbidden, code)
	assert.Contains(t, logged, "audit=setup.complete")
	assert.Contains(t, logged, "outcome=failure")
	assert.Contains(t, logged, "target=192.0.2.77")
	assert.NotContains(t, logged, "guessed-setup-token")
}

func TestRefresh_PlainFailureWritesNoReuseLine(t *testing.T) {
	mock := &mockUsecases{refreshFn: func(context.Context, string) (*usecase.AuthResponse, error) {
		return nil, assert.AnError
	}}

	_, logged := auditedRequest(t, mock, (*Handler).Refresh, "/api/v1/auth/refresh", `{"refresh_token":"expired"}`)

	assert.NotContains(t, logged, "audit=auth.refresh")
}
