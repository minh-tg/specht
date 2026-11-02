package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type fakeRow struct {
	superuser, owner bool
	err              error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*bool) = r.superuser
	*dest[1].(*bool) = r.owner
	return nil
}

type fakeQuerier struct{ row fakeRow }

func (q fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return q.row }

func TestRuntimeRoleWarning(t *testing.T) {
	for _, test := range []struct {
		name             string
		superuser, owner bool
		want             string
	}{
		{name: "restricted role", want: ""},
		{name: "superuser", superuser: true, want: "is a superuser"},
		{name: "superuser that owns", superuser: true, owner: true, want: "is a superuser"},
		{name: "owner", owner: true, want: "owns the schema's tables"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := RuntimeRoleWarning(context.Background(), fakeQuerier{fakeRow{superuser: test.superuser, owner: test.owner}})
			if err != nil {
				t.Fatalf("RuntimeRoleWarning: %v", err)
			}
			if test.want == "" {
				if got != "" {
					t.Fatalf("warning = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, test.want) {
				t.Fatalf("warning = %q, want it to contain %q", got, test.want)
			}
			if !strings.Contains(got, "MIGRATE_DATABASE_URL") {
				t.Fatalf("warning = %q does not name the fix", got)
			}
		})
	}
}

func TestRuntimeRoleWarningReportsQueryError(t *testing.T) {
	_, err := RuntimeRoleWarning(context.Background(), fakeQuerier{fakeRow{err: errors.New("boom")}})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the query error", err)
	}
}
