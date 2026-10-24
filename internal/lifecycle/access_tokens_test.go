package lifecycle

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type accessPruneFunc func(context.Context) (int64, error)

func (f accessPruneFunc) PruneExpired(ctx context.Context) (int64, error) { return f(ctx) }

func TestAccessTokenPruneRejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		require.Error(t, RunAccessTokenPrune(context.Background(), nil, interval, quietLogger()))
	}
}

func TestAccessTokenPruneStartsImmediatelyAndRetriesAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	seen := make(chan struct{}, 2)
	prune := accessPruneFunc(func(sweep context.Context) (int64, error) {
		_, bounded := sweep.Deadline()
		if !bounded {
			t.Error("a cleanup query must have a deadline")
		}
		n := calls.Add(1)
		seen <- struct{}{}
		if n == 1 {
			return 0, errors.New("temporary failure")
		}
		cancel()
		return 1, nil
	})
	require.NoError(t, RunAccessTokenPrune(ctx, prune, 10*time.Millisecond, quietLogger()))
	for i := 0; i < 2; i++ {
		select {
		case <-seen:
		case <-time.After(time.Second):
			t.Fatal("cleanup did not run")
		}
	}
}
