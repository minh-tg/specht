package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) clock() retryClock {
	return retryClock{
		now: func() time.Time { return c.now },
		sleep: func(ctx context.Context, d time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.sleeps = append(c.sleeps, d)
			c.now = c.now.Add(d)
			return nil
		},
	}
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
}

func TestRetryUntil_ReturnsAtOnceWhenTheFirstAttemptWorks(t *testing.T) {
	c := newFakeClock()
	attempts := 0

	err := retryUntil(context.Background(), 30*time.Second, func(context.Context) error {
		attempts++
		return nil
	}, c.clock())

	require.NoError(t, err)
	assert.Equal(t, 1, attempts)
	assert.Empty(t, c.sleeps, "no waiting when the database is already up")
}

func TestRetryUntil_KeepsTryingWithGrowingDelaysUntilItWorks(t *testing.T) {
	c := newFakeClock()
	attempts := 0

	err := retryUntil(context.Background(), 30*time.Second, func(context.Context) error {
		attempts++
		if attempts < 4 {
			return errors.New("connection refused")
		}
		return nil
	}, c.clock())

	require.NoError(t, err)
	assert.Equal(t, 4, attempts)
	assert.Equal(t, []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}, c.sleeps)
}

func TestRetryUntil_DelaysStopGrowingAtTheCap(t *testing.T) {
	c := newFakeClock()
	attempts := 0

	_ = retryUntil(context.Background(), time.Minute, func(context.Context) error {
		attempts++
		return errors.New("down")
	}, c.clock())

	require.Greater(t, len(c.sleeps), 6)
	for _, d := range c.sleeps {
		assert.LessOrEqual(t, d, waitMaxDelay)
	}
}

func TestRetryUntil_GivesUpAfterTheWindowAndKeepsTheCause(t *testing.T) {
	c := newFakeClock()
	cause := errors.New("connection refused")
	attempts := 0

	err := retryUntil(context.Background(), 10*time.Second, func(context.Context) error {
		attempts++
		return cause
	}, c.clock())

	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "10s")
	var total time.Duration
	for _, d := range c.sleeps {
		total += d
	}
	assert.LessOrEqual(t, total, 10*time.Second, "it never sleeps past the window")
	assert.Greater(t, attempts, 2)
}

func TestRetryUntil_AZeroWindowMeansOneAttempt(t *testing.T) {
	c := newFakeClock()
	attempts := 0

	err := retryUntil(context.Background(), 0, func(context.Context) error {
		attempts++
		return errors.New("down")
	}, c.clock())

	require.Error(t, err)
	assert.Equal(t, 1, attempts)
	assert.Empty(t, c.sleeps)
}

func TestRetryUntil_APermanentErrorStopsAtOnce(t *testing.T) {
	c := newFakeClock()
	attempts := 0
	cause := errors.New("password authentication failed")

	err := retryUntil(context.Background(), 30*time.Second, func(context.Context) error {
		attempts++
		return permanent(cause)
	}, c.clock())

	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, 1, attempts, "waiting longer cannot fix a wrong password")
	assert.Empty(t, c.sleeps)
}

func TestRetryUntil_StopsWhenTheContextEnds(t *testing.T) {
	c := newFakeClock()
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0

	err := retryUntil(ctx, 30*time.Second, func(context.Context) error {
		attempts++
		cancel()
		return errors.New("down")
	}, c.clock())

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, attempts)
}

func TestClassify_AuthenticationFailuresAreFinalButAMissingServerIsNot(t *testing.T) {
	assert.True(t, isPermanentConnectError(&pgconn.PgError{Code: "28P01"}), "bad password")
	assert.True(t, isPermanentConnectError(&pgconn.PgError{Code: "28000"}), "invalid authorization")
	assert.False(t, isPermanentConnectError(&pgconn.PgError{Code: "57P03"}), "the database is starting up")
	assert.False(t, isPermanentConnectError(errors.New("dial tcp: connection refused")))
}
