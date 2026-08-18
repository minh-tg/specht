package repo

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// IntervalFromDuration converts a time.Duration to a pgtype.Interval with
// microsecond precision, pgtype.Interval's native resolution. It is the
// single shared conversion point for duration-based SQL intervals across the
// repository layer, so callers (the inventory TTL, the watcher daemon) never
// hand-roll the pgtype.Interval literal. Sub-microsecond remainders are
// truncated.
func IntervalFromDuration(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
