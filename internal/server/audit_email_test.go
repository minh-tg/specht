package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditedAuth runs one login or register request and returns what the audit
// logger wrote.
func auditedAuth(t *testing.T, path, email string, fail bool) string {
	t.Helper()
	var buf bytes.Buffer
	mock := &mockUsecases{
		loginFn: func(context.Context, string, string) (*usecase.AuthResponse, error) {
			if fail {
				return nil, errors.New("invalid email or password")
			}
			return &usecase.AuthResponse{Token: "t"}, nil
		},
		registerFn: func(context.Context, string, string) (*usecase.AuthResponse, error) {
			if fail {
				return nil, errors.New("registration failed")
			}
			return &usecase.AuthResponse{Token: "t"}, nil
		},
	}
	h := NewHandler(mock)
	h.audit = audit.NewLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	body, err := json.Marshal(map[string]string{"email": email, "password": "correct-horse-battery"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if strings.HasSuffix(path, "login") {
		h.Login(w, req)
	} else {
		h.Register(w, req)
	}
	return buf.String()
}

func TestAuthAuditLinesMaskTheEmail(t *testing.T) {
	const email = "Victim.Person@example.com"
	for _, tc := range []struct {
		path string
		fail bool
	}{
		{"/api/v1/auth/login", true},
		{"/api/v1/auth/login", false},
		{"/api/v1/auth/register", true},
		{"/api/v1/auth/register", false},
	} {
		t.Run(fmt.Sprintf("%s failure=%v", tc.path, tc.fail), func(t *testing.T) {
			logged := auditedAuth(t, tc.path, email, tc.fail)

			require.Contains(t, logged, "audit=auth.", "an audit line was written")
			assert.NotContains(t, strings.ToLower(logged), "victim.person", "the local part must not reach the log")
			assert.Contains(t, logged, "v***@example.com", "the masked form identifies the account to an operator")
		})
	}
}

func TestAuthAuditLinesCannotBeForgedThroughTheEmail(t *testing.T) {
	forged := "x@evil.com\ntime=2026-01-01T00:00:00Z level=INFO msg=audit audit=auth.login outcome=success\x1b[2J"

	logged := auditedAuth(t, "/api/v1/auth/login", forged, true)

	assert.Equal(t, 1, strings.Count(logged, "\n"), "one audit event is one line")
	assert.NotContains(t, logged, "\x1b", "no raw escape character reaches the log")
}
