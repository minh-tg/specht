package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/config"
	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/repo"
	"github.com/minh-tg/specht/internal/usecase"
)

// recoveryUsage names the program the way it was started: `specht` in the
// container image, `server` in a development build.
func recoveryUsage() string {
	prog := filepath.Base(os.Args[0])
	return fmt.Sprintf(`usage:
  %[1]s reset-password <email> [--password-stdin]
  %[1]s grant-admin <email>

These commands act directly on the database, so they are the way back in when
the only administrator has lost access. Run them inside the server container,
for example:
  docker compose exec server %[1]s reset-password ada@example.com

reset-password prints a generated password once. With --password-stdin it reads
the new password from standard input instead and prints nothing secret.`, prog)
}

// recoveryService is the part of the use cases the recovery commands call.
type recoveryService interface {
	ResetPasswordByEmail(ctx context.Context, email, password string) (*usecase.UserProfile, error)
	GrantAdminByEmail(ctx context.Context, email string) (*usecase.UserProfile, error)
}

// runRecoveryCommand opens the database the way the server does and runs one
// recovery command. It returns the process exit code.
func runRecoveryCommand(cfg *config.Server, args []string) int {
	if cfg.DBURL == "" {
		fmt.Fprintln(os.Stderr, "error: DATABASE_URL is required")
		return 1
	}
	ctx := context.Background()
	pool, err := db.ConnectPool(ctx, cfg.DBURL)
	if err != nil {
		slog.Error("recovery: connect db", "error", err)
		fmt.Fprintln(os.Stderr, "error: could not connect to the database; see the log above")
		return 1
	}
	defer pool.Close()

	uc := usecase.New(usecase.Deps{
		Stores:    repo.NewPortStores(pool),
		Passwords: auth.NewPasswordHasher(),
	})
	return runRecovery(ctx, uc, audit.NewLogger(nil), args, os.Stdin, os.Stdout, os.Stderr)
}

// recoveryActor is the principal id on the audit line of a recovery command.
// The command takes no caller identity; whoever ran it has host access.
const recoveryActor = "cli"

// auditRecovery writes the audit line for one recovery command. On success the
// target is the account id; on a failure that never resolved an account it is
// the email the operator typed.
func auditRecovery(ctx context.Context, log *audit.Logger, name string, profile *usecase.UserProfile, email string, err error) {
	event := audit.Event{Name: name, Outcome: audit.OutcomeSuccess, Actor: recoveryActor, Target: email, StartedAt: time.Now()}
	if profile != nil {
		event.Target = profile.ID
	}
	if err != nil {
		event.Outcome = audit.OutcomeFailure
		event.Error = err.Error()
	}
	log.Log(ctx, event)
}

// runRecovery parses one recovery command and runs it. Exit codes: 0 done,
// 1 the command failed, 2 the command line was wrong.
func runRecovery(ctx context.Context, svc recoveryService, auditLog *audit.Logger, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return recoveryUsageError(stderr, "a command is required")
	}
	switch args[0] {
	case "reset-password":
		return resetPasswordCommand(ctx, svc, auditLog, args[1:], stdin, stdout, stderr)
	case "grant-admin":
		return grantAdminCommand(ctx, svc, auditLog, args[1:], stdout, stderr)
	default:
		return recoveryUsageError(stderr, fmt.Sprintf("unknown command %q", args[0]))
	}
}

func resetPasswordCommand(ctx context.Context, svc recoveryService, auditLog *audit.Logger, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var email string
	fromStdin := false
	for _, a := range args {
		switch {
		case a == "--password-stdin" || a == "-password-stdin":
			fromStdin = true
		case strings.HasPrefix(a, "-"):
			return recoveryUsageError(stderr, fmt.Sprintf("unknown option %q", a))
		case email == "":
			email = a
		default:
			return recoveryUsageError(stderr, "give exactly one email address")
		}
	}
	if email == "" {
		return recoveryUsageError(stderr, "an email address is required")
	}

	var password string
	if fromStdin {
		line, err := bufio.NewReader(io.LimitReader(stdin, 1024)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(stderr, "error: could not read the password from standard input")
			return 2
		}
		password = strings.TrimRight(line, "\r\n")
		if password == "" {
			fmt.Fprintln(stderr, "error: no password on standard input")
			return 2
		}
	} else {
		generated, err := generatePassword()
		if err != nil {
			slog.Error("recovery: generate password", "error", err)
			fmt.Fprintln(stderr, "error: could not generate a password")
			return 1
		}
		password = generated
	}

	profile, err := svc.ResetPasswordByEmail(ctx, email, password)
	auditRecovery(ctx, auditLog, audit.EventResetPassword, profile, email, err)
	if err != nil {
		return reportRecoveryError(stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "Password reset for %s. Every session of this account has ended.\n", profile.Email)
	if !fromStdin {
		_, _ = fmt.Fprintf(stdout, "New password: %s\nSign in with it and change it right away.\n", password)
	}
	if profile.Disabled {
		_, _ = fmt.Fprintln(stdout, "Note: this account is deactivated and still cannot sign in. Reactivate it from the admin area.")
	}
	return 0
}

func grantAdminCommand(ctx context.Context, svc recoveryService, auditLog *audit.Logger, args []string, stdout, stderr io.Writer) int {
	var email string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-"):
			return recoveryUsageError(stderr, fmt.Sprintf("unknown option %q", a))
		case email == "":
			email = a
		default:
			return recoveryUsageError(stderr, "give exactly one email address")
		}
	}
	if email == "" {
		return recoveryUsageError(stderr, "an email address is required")
	}
	profile, err := svc.GrantAdminByEmail(ctx, email)
	auditRecovery(ctx, auditLog, audit.EventChangeUserRole, profile, email, err)
	if err != nil {
		return reportRecoveryError(stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "%s is now a global admin. A session they already have picks the role up at the next sign-in.\n", profile.Email)
	return 0
}

// reportRecoveryError turns a failure into a plain message and exit code 1.
// Detail that could name an internal address goes to the log, not the message.
func reportRecoveryError(stderr io.Writer, err error) int {
	switch {
	case errors.Is(err, usecase.ErrAccountNotFound):
		fmt.Fprintln(stderr, "error: no account has that email address")
	case errors.Is(err, usecase.ErrSystemAccount):
		fmt.Fprintln(stderr, "error: the system account cannot be changed")
	case errors.Is(err, usecase.ErrAccountDeactivated):
		fmt.Fprintln(stderr, "error: that account is deactivated; reactivate it from the admin area before granting admin")
	case errors.Is(err, usecase.ErrInvalidCredentialInput):
		fmt.Fprintf(stderr, "error: %s\n", err.Error())
	default:
		slog.Error("recovery command failed", "error", err)
		fmt.Fprintln(stderr, "error: the command could not complete; see the log above for detail")
	}
	return 1
}

func recoveryUsageError(stderr io.Writer, reason string) int {
	fmt.Fprintf(stderr, "error: %s\n\n%s\n", reason, recoveryUsage())
	return 2
}

// generatePassword returns 24 URL-safe characters (144 bits) from the system
// random source.
func generatePassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
