package cli

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/watcher"
)

func TestWatcherStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/watcher/status", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"last_successful_poll_at":"2026-09-22T12:00:00Z","last_poll_attempt_at":"2026-09-22T12:01:00Z","consecutive_failures":0,"healthy":true}`)); err != nil {
			t.Errorf("write watcher status response: %v", err)
		}
	})
	d, out, _ := testDeps(t, mux)

	if err := runCmd(t, d, "watcher", "status"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Last Successful Poll:  2026-09-22T12:00:00Z",
		"Last Poll Attempt:     2026-09-22T12:01:00Z",
		"Consecutive Failures:  0",
		"Status:                healthy",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in output %q", want, out.String())
		}
	}
}

func TestWatcherBackfill(t *testing.T) {
	var got WatcherBackfillOptions
	var out bytes.Buffer
	d := Deps{
		RunWatcherBackfill: func(opts WatcherBackfillOptions) (WatcherBackfillResult, error) {
			got = opts
			return WatcherBackfillResult{
				Outcome: watcher.PollOutcome{Projects: 2, Queried: 3, Created: 1, Skipped: 1, Unchanged: 1, Ignored: 2, OrphanSkips: 1},
			}, nil
		},
		Out:  &out,
		ErrW: &bytes.Buffer{},
	}

	if err := runCmd(t, d, "watcher", "backfill", "--since", "2026-01-01T00:00:00Z", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if !got.DryRun || !got.Since.Equal(time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("options = %+v", got)
	}
	if !strings.Contains(out.String(), "watcher backfill: projects=2 queried=3 created=1 skipped=1 unchanged=1 ignored=2 orphan_skips=1") {
		t.Fatalf("unexpected output: %q", out.String())
	}
	if !strings.Contains(out.String(), "dry-run: nothing was written") {
		t.Fatalf("missing dry-run output: %q", out.String())
	}
}

func TestWatcherBackfillInvalidSince(t *testing.T) {
	d := Deps{Out: &bytes.Buffer{}, ErrW: &bytes.Buffer{}}
	err := runCmd(t, d, "watcher", "backfill", "--since", "not-a-timestamp")
	if err == nil || !strings.Contains(err.Error(), "--since must be an ISO8601 timestamp") {
		t.Fatalf("error = %v", err)
	}
}

func TestWatcherBackfillCallbackError(t *testing.T) {
	want := errors.New("poll failed")
	d := Deps{
		RunWatcherBackfill: func(WatcherBackfillOptions) (WatcherBackfillResult, error) {
			return WatcherBackfillResult{}, want
		},
		Out:  &bytes.Buffer{},
		ErrW: &bytes.Buffer{},
	}
	if err := runCmd(t, d, "watcher", "backfill"); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}
