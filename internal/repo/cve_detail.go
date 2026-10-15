package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/cvedetail"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

// CVEDetailStore is the PostgreSQL side of the CVE detail feature: the
// provider cache, its fetch lease, the provider status table, and the read of
// a finding's newest occurrences per tool.
type CVEDetailStore struct {
	q *sqlc.Queries
}

// NewCVEDetailStore builds the store over pool.
func NewCVEDetailStore(pool *pgxpool.Pool) *CVEDetailStore {
	return &CVEDetailStore{q: sqlc.New(pool)}
}

var _ cvedetail.Store = (*CVEDetailStore)(nil)

// ListLatestCVEOccurrences returns the newest occurrence per tool for one
// finding, newest first, including watcher occurrences that have no report.
func (s *CVEDetailStore) ListLatestCVEOccurrences(ctx context.Context, findingID string) ([]cvedetail.Occurrence, error) {
	id, err := parseID(findingID)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListLatestCVEOccurrences(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]cvedetail.Occurrence, 0, len(rows))
	for _, r := range rows {
		out = append(out, cvedetail.Occurrence{
			ToolName:   r.ToolName,
			ReportID:   stringPtrFromUUID(r.ReportID),
			ObservedAt: r.ObservedAt.Time,
			Metadata:   r.Metadata,
		})
	}
	return out, nil
}

// ListCached implements cvedetail.Store. A row whose record does not decode
// is returned without one, which the resolver treats as missing.
func (s *CVEDetailStore) ListCached(ctx context.Context, cveID string) ([]cvedetail.CacheEntry, error) {
	rows, err := s.q.ListCVEDetailCache(ctx, cveID)
	if err != nil {
		return nil, err
	}
	out := make([]cvedetail.CacheEntry, 0, len(rows))
	for _, r := range rows {
		e := cvedetail.CacheEntry{
			Provider:   r.Provider,
			CVEID:      r.CveID,
			Status:     r.Status,
			FetchedAt:  r.FetchedAt.Time,
			ExpiresAt:  r.ExpiresAt.Time,
			LeaseUntil: timePtrFromTimestamptz(r.LeaseUntil),
		}
		if len(r.Record) > 0 {
			var rec cvedetail.Record
			if json.Unmarshal(r.Record, &rec) == nil {
				e.Record = &rec
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// AcquireLease implements cvedetail.Store.
func (s *CVEDetailStore) AcquireLease(ctx context.Context, provider, cveID string, now, until time.Time) (bool, error) {
	_, err := s.q.AcquireCVEDetailLease(ctx, sqlc.AcquireCVEDetailLeaseParams{
		Provider:   provider,
		CveID:      cveID,
		Now:        uuidFromTime(now),
		LeaseUntil: uuidFromTime(until),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// StoreAnswer implements cvedetail.Store.
func (s *CVEDetailStore) StoreAnswer(ctx context.Context, e cvedetail.CacheEntry) error {
	var record []byte
	if e.Record != nil {
		raw, err := json.Marshal(e.Record)
		if err != nil {
			return fmt.Errorf("encode cve detail record: %w", err)
		}
		if len(raw) > cvedetail.MaxRecordBytes {
			return fmt.Errorf("cve detail record is %d bytes, over the %d byte cap", len(raw), cvedetail.MaxRecordBytes)
		}
		record = raw
	}
	return s.q.StoreCVEDetail(ctx, sqlc.StoreCVEDetailParams{
		Provider:  e.Provider,
		CveID:     e.CVEID,
		Status:    e.Status,
		Record:    record,
		FetchedAt: uuidFromTime(e.FetchedAt),
		ExpiresAt: uuidFromTime(e.ExpiresAt),
	})
}

// ReleaseLease implements cvedetail.Store.
func (s *CVEDetailStore) ReleaseLease(ctx context.Context, provider, cveID string) error {
	if err := s.q.DeletePendingCVEDetail(ctx, sqlc.DeletePendingCVEDetailParams{Provider: provider, CveID: cveID}); err != nil {
		return err
	}
	return s.q.ReleaseCVEDetailLease(ctx, sqlc.ReleaseCVEDetailLeaseParams{Provider: provider, CveID: cveID})
}

// RecordSuccess implements cvedetail.Store.
func (s *CVEDetailStore) RecordSuccess(ctx context.Context, provider string, at time.Time) error {
	return s.q.RecordCVEProviderSuccess(ctx, sqlc.RecordCVEProviderSuccessParams{Provider: provider, LastSuccessAt: uuidFromTime(at)})
}

// RecordError implements cvedetail.Store.
func (s *CVEDetailStore) RecordError(ctx context.Context, provider, kind string, at, backoffUntil time.Time) error {
	return s.q.RecordCVEProviderError(ctx, sqlc.RecordCVEProviderErrorParams{
		Provider:     provider,
		LastErrorAt:  uuidFromTime(at),
		LastError:    pgtype.Text{String: kind, Valid: true},
		BackoffUntil: uuidFromTime(backoffUntil),
	})
}

// ListProviderStates implements cvedetail.Store.
func (s *CVEDetailStore) ListProviderStates(ctx context.Context) ([]cvedetail.ProviderState, error) {
	rows, err := s.q.ListCVEProviderStatus(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cvedetail.ProviderState, 0, len(rows))
	for _, r := range rows {
		out = append(out, cvedetail.ProviderState{
			Provider:      r.Provider,
			LastSuccessAt: timePtrFromTimestamptz(r.LastSuccessAt),
			LastErrorAt:   timePtrFromTimestamptz(r.LastErrorAt),
			LastError:     strVal(r.LastError),
			BackoffUntil:  timePtrFromTimestamptz(r.BackoffUntil),
		})
	}
	return out, nil
}

// Sweep implements cvedetail.Store.
func (s *CVEDetailStore) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return s.q.SweepCVEDetailCache(ctx, uuidFromTime(cutoff))
}
