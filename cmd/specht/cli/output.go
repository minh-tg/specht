package cli

import (
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// emit writes v as JSON when --format json was given and calls human otherwise,
// so a command has one place that decides how its result looks.
func emit(d Deps, s *settings, v any, human func(w io.Writer) error) error {
	format, err := resolveFormat(s)
	if err != nil {
		return err
	}
	if format == "json" {
		return writeJSONOut(d.Out, v)
	}
	return human(d.Out)
}

// parseWhen reads a time given on the command line. A full RFC 3339 timestamp is
// kept. A bare date means the end of that day in UTC, so "expires 2026-12-31"
// does not lapse at midnight on the morning of the 31st.
func parseWhen(flag, value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	if day, err := time.Parse("2006-01-02", value); err == nil {
		return day.Add(24*time.Hour - time.Second), nil
	}
	return time.Time{}, fmt.Errorf("%s %q is not a time: use 2026-12-31 or 2026-12-31T10:30:00Z", flag, value)
}

// splitIDs flattens repeated and comma-separated flag values into one list and
// drops blanks, so --id a,b and --id a --id b mean the same.
func splitIDs(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// limitArg turns a --limit value into the int32 the API takes. A bare int32(n) would wrap a huge
// value to a small one, so --limit 4294967297 would quietly ask for one row.
func limitArg(flag string, n int) (int32, error) {
	if n < 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("%s must be between 0 and %d", flag, math.MaxInt32)
	}
	return int32(n), nil
}
