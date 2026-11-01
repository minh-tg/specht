package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/usecase"
)

type fakeRecovery struct {
	resetEmail, resetPassword string
	grantEmail                string
	resetErr, grantErr        error
	profile                   usecase.UserProfile
}

func (f *fakeRecovery) ResetPasswordByEmail(ctx context.Context, email, password string) (*usecase.UserProfile, error) {
	f.resetEmail, f.resetPassword = email, password
	if f.resetErr != nil {
		return nil, f.resetErr
	}
	p := f.profile
	if p.Email == "" {
		p.Email = email
	}
	return &p, nil
}

func (f *fakeRecovery) GrantAdminByEmail(ctx context.Context, email string) (*usecase.UserProfile, error) {
	f.grantEmail = email
	if f.grantErr != nil {
		return nil, f.grantErr
	}
	p := f.profile
	p.Email = email
	p.Role = "admin"
	return &p, nil
}

func runRecoveryForTest(svc recoveryService, stdin string, args ...string) (code int, stdout, stderr string) {
	code, stdout, stderr, _ = runRecoveryAudited(svc, stdin, args...)
	return code, stdout, stderr
}

// runRecoveryAudited also returns what the command wrote to the audit log.
func runRecoveryAudited(svc recoveryService, stdin string, args ...string) (code int, stdout, stderr, auditLog string) {
	var out, errOut, logOut bytes.Buffer
	logger := audit.NewLogger(slog.New(slog.NewTextHandler(&logOut, nil)))
	code = runRecovery(context.Background(), svc, logger, args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String(), logOut.String()
}

func TestRecovery_ResetGeneratesAPasswordAndShowsItOnce(t *testing.T) {
	svc := &fakeRecovery{}

	code, stdout, stderr := runRecoveryForTest(svc, "", "reset-password", "ada@acme.example")

	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "ada@acme.example", svc.resetEmail)
	assert.GreaterOrEqual(t, len(svc.resetPassword), 20, "a generated password is long")
	assert.Equal(t, 1, strings.Count(stdout, svc.resetPassword), "the password is printed exactly once")
	assert.Contains(t, stdout, "ended")
	assert.NotContains(t, stderr, svc.resetPassword)
}

func TestRecovery_ResetGeneratesADifferentPasswordEachTime(t *testing.T) {
	a, b := &fakeRecovery{}, &fakeRecovery{}
	runRecoveryForTest(a, "", "reset-password", "ada@acme.example")
	runRecoveryForTest(b, "", "reset-password", "ada@acme.example")
	assert.NotEqual(t, a.resetPassword, b.resetPassword)
}

func TestRecovery_ResetFromStdinNeverEchoesThePassword(t *testing.T) {
	svc := &fakeRecovery{}

	code, stdout, stderr := runRecoveryForTest(svc, "chosen-password-1\n", "reset-password", "ada@acme.example", "--password-stdin")

	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "chosen-password-1", svc.resetPassword, "one line, without its line ending")
	assert.NotContains(t, stdout, "chosen-password-1")
	assert.NotContains(t, stderr, "chosen-password-1")
}

func TestRecovery_ResetFromStdinAcceptsTheFlagFirstAndWindowsLineEndings(t *testing.T) {
	svc := &fakeRecovery{}
	code, _, stderr := runRecoveryForTest(svc, "chosen-password-1\r\n", "reset-password", "-password-stdin", "ada@acme.example")
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "chosen-password-1", svc.resetPassword)
	assert.Equal(t, "ada@acme.example", svc.resetEmail)
}

func TestRecovery_EmptyStdinIsAUsageError(t *testing.T) {
	svc := &fakeRecovery{}
	code, _, stderr := runRecoveryForTest(svc, "", "reset-password", "ada@acme.example", "--password-stdin")
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "password")
	assert.Empty(t, svc.resetEmail, "nothing is attempted")
}

func TestRecovery_ResetWarnsThatADeactivatedAccountStillCannotSignIn(t *testing.T) {
	svc := &fakeRecovery{profile: usecase.UserProfile{Disabled: true}}
	code, stdout, _ := runRecoveryForTest(svc, "", "reset-password", "ada@acme.example")
	require.Equal(t, 0, code)
	assert.Contains(t, stdout, "deactivated")
}

func TestRecovery_UsageErrorsExitWithTwo(t *testing.T) {
	for name, args := range map[string][]string{
		"no command":           {},
		"unknown command":      {"delete-everything", "ada@acme.example"},
		"reset without email":  {"reset-password"},
		"grant without email":  {"grant-admin"},
		"reset with two":       {"reset-password", "a@b.co", "c@d.co"},
		"unknown flag":         {"reset-password", "a@b.co", "--password"},
		"grant takes no flags": {"grant-admin", "a@b.co", "--password-stdin"},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &fakeRecovery{}
			code, _, stderr := runRecoveryForTest(svc, "", args...)
			assert.Equal(t, 2, code)
			assert.Contains(t, stderr, "usage")
			assert.Empty(t, svc.resetEmail+svc.grantEmail, "nothing runs on a usage error")
		})
	}
}

func TestRecovery_FailuresGivePlainMessages(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"unknown account": {usecase.ErrAccountNotFound, "no account has that email"},
		"system account":  {usecase.ErrSystemAccount, "system account"},
		"weak password":   {usecase.NewCredentialInputError("password must be at least 8 characters"), "at least 8 characters"},
		"database down":   {errors.New("dial tcp 10.0.0.5:5432: connection refused"), "could not complete"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc := &fakeRecovery{resetErr: tc.err}
			code, stdout, stderr := runRecoveryForTest(svc, "", "reset-password", "ada@acme.example")
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.want)
			assert.NotContains(t, stdout, svc.resetPassword, "a failed reset never prints a password")
			assert.NotContains(t, stderr, "10.0.0.5", "internal addresses stay out of the message")
		})
	}
}

func TestRecovery_GrantAdminReportsTheNewRole(t *testing.T) {
	svc := &fakeRecovery{}
	code, stdout, stderr := runRecoveryForTest(svc, "", "grant-admin", "Ada@Acme.Example")
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "Ada@Acme.Example", svc.grantEmail, "normalising is the use case's job")
	assert.Contains(t, stdout, "admin")

	failing := &fakeRecovery{grantErr: usecase.ErrAccountNotFound}
	code, _, stderr = runRecoveryForTest(failing, "", "grant-admin", "nobody@acme.example")
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "no account has that email")
}

func TestRecovery_ResetPasswordWritesAnAuditLine(t *testing.T) {
	svc := &fakeRecovery{profile: usecase.UserProfile{ID: "u-42"}}

	code, stdout, stderr, log := runRecoveryAudited(svc, "", "reset-password", "ada@acme.example")

	require.Equal(t, 0, code, stderr)
	assert.Contains(t, log, "audit=user.reset_password")
	assert.Contains(t, log, "outcome=success")
	assert.Contains(t, log, "principal_id=cli")
	assert.Contains(t, log, "target=u-42")
	assert.NotContains(t, log, svc.resetPassword, "the new password never reaches the log")
	assert.Contains(t, stdout, svc.resetPassword)
}

func TestRecovery_GrantAdminWritesAnAuditLine(t *testing.T) {
	svc := &fakeRecovery{profile: usecase.UserProfile{ID: "u-42"}}

	code, _, stderr, log := runRecoveryAudited(svc, "", "grant-admin", "ada@acme.example")

	require.Equal(t, 0, code, stderr)
	assert.Contains(t, log, "audit=user.role")
	assert.Contains(t, log, "outcome=success")
	assert.Contains(t, log, "principal_id=cli")
	assert.Contains(t, log, "target=u-42")
}

func TestRecovery_FailedCommandsAreAuditedWithTheTypedEmail(t *testing.T) {
	failing := &fakeRecovery{grantErr: usecase.ErrAccountNotFound, resetErr: usecase.ErrSystemAccount}

	code, _, _, log := runRecoveryAudited(failing, "", "grant-admin", "nobody@acme.example")
	assert.Equal(t, 1, code)
	assert.Contains(t, log, "audit=user.role")
	assert.Contains(t, log, "outcome=failure")
	assert.Contains(t, log, "target=nobody@acme.example")

	code, _, _, log = runRecoveryAudited(failing, "", "reset-password", "system@specht.local")
	assert.Equal(t, 1, code)
	assert.Contains(t, log, "audit=user.reset_password")
	assert.Contains(t, log, "outcome=failure")
}

func TestRecovery_UsageErrorsWriteNoAuditLine(t *testing.T) {
	code, _, _, log := runRecoveryAudited(&fakeRecovery{}, "", "grant-admin")
	assert.Equal(t, 2, code)
	assert.Empty(t, log)
}

func TestRecovery_GrantAdminExplainsADeactivatedAccount(t *testing.T) {
	svc := &fakeRecovery{grantErr: usecase.ErrAccountDeactivated}
	code, stdout, stderr := runRecoveryForTest(svc, "", "grant-admin", "ada@acme.example")
	assert.Equal(t, 1, code)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "deactivated")
	assert.Contains(t, stderr, "reactivate")
}
