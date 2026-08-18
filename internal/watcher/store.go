// The production PollStore implementation. Every created decision is
// persisted atomically via repo.WithTx: the finding row (insert-if-absent),
// its scan-equivalent dimensions, the occurrence (report_id NULL — watcher
// findings have no scan report, migration 000018), the auto_rule_applied
// event, and the evidence artifact (type 'automated', url = first advisory
// reference, description = advisory summary). The raw querybatch advisory
// bytes travel byte-exact as base64 in occurrence.metadata["raw_advisory"]
// (JSONB-safe, satisfies raw-bytes provenance).
package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/repo"
)

const (
	// occurrenceToolName is the tool_name carried by watcher occurrences;
	// the OSV querybatch endpoint is the tool that produced the advisory.
	occurrenceToolName = "osv-batch"
	// EvidenceTypeAutomated is the evidence_artifacts type for watcher
	// provenance rows (migration 000013 CHECK permits 'automated').
	EvidenceTypeAutomated = "automated"
	// MetadataRawAdvisoryKey is the occurrence.metadata key holding the
	// base64-encoded raw querybatch bytes for the advisory.
	MetadataRawAdvisoryKey = "raw_advisory"
)

// pgPollStore persists through the repository layer inside one transaction
// per decision.
type pgPollStore struct {
	repos *repo.Repos
	now   func() time.Time
}

// NewPollStore builds the production PollStore for a repository set.
func NewPollStore(repos *repo.Repos) PollStore {
	return &pgPollStore{repos: repos, now: time.Now}
}

// PersistFoundFinding implements PollStore. The insert-if-absent guard
// (CreateFindingIfAbsent) is the re-poll protection: when the fingerprint
// already exists, the whole persist is a no-op — occurrences are created only
// for genuinely new findings (UNIQUE(finding_id,
// report_id) does not dedupe NULL report_ids, so the guard is mandatory).
func (s *pgPollStore) PersistFoundFinding(ctx context.Context, d Decision) (pgtype.UUID, bool, error) {
	pid, err := uuid.Parse(d.Finding.ProjectID)
	if err != nil {
		return pgtype.UUID{}, false, fmt.Errorf("parse project id %q: %w", d.Finding.ProjectID, err)
	}
	projectID := pgtype.UUID{Bytes: pid, Valid: true}
	fp := d.Finding

	var out pgtype.UUID
	created := false
	err = s.repos.WithTx(ctx, func(q *sqlc.Queries) error {
		f, err := q.CreateFindingIfAbsent(ctx, sqlc.CreateFindingIfAbsentParams{
			ProjectID:           projectID,
			FindingKind:         fp.FindingKind,
			Fingerprint:         fp.Fingerprint,
			CurrentTitle:        fp.Title,
			CurrentSeverity:     fp.Severity,
			CurrentSeverityRank: fp.SeverityRank,
			CurrentScore:        numericScore(fp.Score),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// Re-poll hit of an existing watcher finding: nothing to do.
			// created stays false so the poll counts this as unchanged.
			return nil
		}
		if err != nil {
			return fmt.Errorf("create finding: %w", err)
		}
		out = f.ID
		created = true

		source := pgtype.Text{String: DimensionSourceValue, Valid: true}
		for _, dim := range fp.Dimensions {
			if _, err := q.UpsertDimension(ctx, sqlc.UpsertDimensionParams{
				FindingID: f.ID,
				DimKey:    dim.Key,
				DimValue:  dim.Value,
				Source:    source,
			}); err != nil {
				return fmt.Errorf("dimension %q: %w", dim.Key, err)
			}
		}

		occurrence, err := buildOccurrence(d, s.now())
		if err != nil {
			return err
		}
		occurrence.FindingID = f.ID
		if _, err := q.CreateOccurrence(ctx, occurrence); err != nil {
			return fmt.Errorf("create occurrence: %w", err)
		}

		if d.Event != nil {
			if _, err := q.CreateFindingEvent(ctx, sqlc.CreateFindingEventParams{
				FindingID: f.ID,
				EventType: d.Event.EventType,
				OldValue:  textPtr(d.Event.OldValue),
				NewValue:  textPtr(d.Event.NewValue),
				Comment:   textPtr(d.Event.Comment),
				Changes:   d.Event.Changes,
			}); err != nil {
				return fmt.Errorf("create event: %w", err)
			}
		}

		url, desc := evidencePayload(d)
		if _, err := q.CreateEvidence(ctx, sqlc.CreateEvidenceParams{
			FindingID:   f.ID,
			Type:        EvidenceTypeAutomated,
			Url:         url,
			Description: desc,
		}); err != nil {
			return fmt.Errorf("create evidence: %w", err)
		}
		return nil
	})
	if err != nil {
		return pgtype.UUID{}, false, err
	}
	return out, created, nil
}

// PersistSkipEvent implements PollStore: a single event insert on the
// suppressing finding.
func (s *pgPollStore) PersistSkipEvent(ctx context.Context, suppressingID pgtype.UUID, ev Event) error {
	return s.repos.WithTx(ctx, func(q *sqlc.Queries) error {
		_, err := q.CreateFindingEvent(ctx, sqlc.CreateFindingEventParams{
			FindingID: suppressingID,
			EventType: ev.EventType,
			OldValue:  textPtr(ev.OldValue),
			NewValue:  textPtr(ev.NewValue),
			Comment:   textPtr(ev.Comment),
			Changes:   ev.Changes,
		})
		if err != nil {
			return fmt.Errorf("create skip event: %w", err)
		}
		return nil
	})
}

// buildOccurrence computes the occurrence row for a created decision. ReportID
// is left as the zero pgtype.UUID, which encodes to NULL (watcher findings
// have no scan report). The metadata gains raw_advisory = base64 of the
// evidence bytes, byte-exact. Pure and unit-testable.
func buildOccurrence(d Decision, now time.Time) (sqlc.CreateOccurrenceParams, error) {
	fp := d.Finding

	displayJSON, err := json.Marshal(fp.Display)
	if err != nil {
		return sqlc.CreateOccurrenceParams{}, fmt.Errorf("marshal display: %w", err)
	}
	metadata := make(map[string]any, len(fp.Metadata)+1)
	for k, v := range fp.Metadata {
		metadata[k] = v
	}
	if len(d.Evidence) > 0 {
		metadata[MetadataRawAdvisoryKey] = base64.StdEncoding.EncodeToString(d.Evidence)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return sqlc.CreateOccurrenceParams{}, fmt.Errorf("marshal metadata: %w", err)
	}

	return sqlc.CreateOccurrenceParams{
		ReportID:       pgtype.UUID{}, // NULL
		Title:          fp.Title,
		Description:    textPtr(fp.Description),
		Severity:       fp.Severity,
		SeverityRank:   fp.SeverityRank,
		Score:          numericScore(fp.Score),
		ToolName:       occurrenceToolName,
		SubjectSummary: textPtr(fp.Title),
		Remediation:    textPtr(fp.Remediation),
		Display:        displayJSON,
		Metadata:       metadataJSON,
		ObservedAt:     pgtype.Timestamptz{Time: now, Valid: true},
	}, nil
}

// evidencePayload derives the evidence_artifacts row for a created decision:
// url = first advisory reference (” when none), description = advisory
// summary. Best-effort decode of the raw bytes; any failure yields empty
// values rather than a failed poll.
func evidencePayload(d Decision) (url, description string) {
	var advisory Advisory
	if err := json.Unmarshal(d.Evidence, &advisory); err != nil {
		return "", ""
	}
	if urls := advisoryURLs(advisory.Refs); len(urls) > 0 {
		url = urls[0]
	}
	return url, advisory.Summary
}

// numericScore mirrors the usecase layer's score encoding: a decimal with one
// fractional digit (score * 10, exp -1). Non-positive scores map to SQL NULL.
func numericScore(s float64) pgtype.Numeric {
	if s <= 0 {
		return pgtype.Numeric{Valid: false}
	}
	return pgtype.Numeric{Int: big.NewInt(int64(s * 10)), Exp: -1, Valid: true}
}

// textPtr maps an empty string to SQL NULL.
func textPtr(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}
