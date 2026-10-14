package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	waitInitialDelay  = 500 * time.Millisecond
	waitMaxDelay      = 5 * time.Second
	waitAttemptBudget = 3 * time.Second
)

// permanentError marks a failure that waiting cannot fix.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return permanentError{err: err} }

// isPermanentConnectError reports whether a connection failure is final: a
// rejected login (SQLSTATE class 28) will not get better by retrying.
func isPermanentConnectError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "28")
}

// retryClock lets tests run the retry loop without sleeping.
type retryClock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

var realClock = retryClock{
	now: time.Now,
	sleep: func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	},
}

// retryUntil calls attempt until it succeeds, fails permanently, the window
// has passed or ctx ends. The delay starts at half a second and doubles up to
// five seconds. A window of zero or less means a single attempt.
func retryUntil(ctx context.Context, window time.Duration, attempt func(context.Context) error, clock retryClock) error {
	deadline := clock.now().Add(window)
	delay := waitInitialDelay
	for n := 1; ; n++ {
		err := attempt(ctx)
		if err == nil {
			return nil
		}
		var final permanentError
		if errors.As(err, &final) {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: %w", ctxErr, err)
		}
		if clock.now().Add(delay).After(deadline) {
			return fmt.Errorf("database not reachable after %s: %w", window, err)
		}
		slog.Warn("waiting for the database", "attempt", n, "retry_in", delay.String(), "error", err)
		if sleepErr := clock.sleep(ctx, delay); sleepErr != nil {
			return fmt.Errorf("%w: %w", sleepErr, err)
		}
		delay = min(delay*2, waitMaxDelay)
	}
}

// WaitForDatabase blocks until the database answers, so a server that starts a
// moment before Postgres is ready waits instead of exiting. A malformed URL or
// a rejected login fails at once. A window of zero or less tries once.
func WaitForDatabase(ctx context.Context, databaseURL string, window time.Duration) error {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	return retryUntil(ctx, window, func(ctx context.Context) error {
		attemptCtx, cancel := context.WithTimeout(ctx, waitAttemptBudget)
		defer cancel()
		conn, err := pgx.ConnectConfig(attemptCtx, cfg)
		if err != nil {
			if isPermanentConnectError(err) {
				return permanent(err)
			}
			return err
		}
		defer func() { _ = conn.Close(context.Background()) }()
		return conn.Ping(attemptCtx)
	}, realClock)
}
