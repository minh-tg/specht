// This file implements the production PollStore. Every created decision is
// persisted atomically through the port finding store's
// PersistWatcherFinding: the finding row (insert-if-absent), its
// scan-equivalent dimensions, the occurrence (report_id NULL — watcher
// findings have no scan report, migration 000018), the auto_rule_applied
// event, and the evidence artifact (type 'automated', url = first advisory
// reference, description = advisory summary). The raw querybatch advisory
// bytes travel byte-exact as base64 in occurrence.metadata["raw_advisory"]
// (JSONB-safe by construction). This file imports no pgtype/sqlc types: the
// store adapts decisions to the port contract.
package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xMinhx/specht/internal/port"
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

// pgPollStore persists through the port finding store inside one transaction
// per decision.
type pgPollStore struct {
	stores *port.Stores
	now    func() time.Time
}

// NewPollStore builds the production PollStore for a port store aggregate.
func NewPollStore(stores *port.Stores) PollStore {
	return &pgPollStore{stores: stores, now: time.Now}
}

// PersistFoundFinding implements PollStore. The insert-if-absent guard is the
// re-poll protection: when the fingerprint already exists, the whole persist
// is a no-op (port.ErrFindingSuppressed) — occurrences are created only for
// genuinely new findings.
func (s *pgPollStore) PersistFoundFinding(ctx context.Context, d Decision) (string, bool, error) {
	fp := d.Finding
	source := DimensionSourceValue

	dimensions := make([]port.DimensionInput, len(fp.Dimensions))
	for i, dim := range fp.Dimensions {
		dimensions[i] = port.DimensionInput{
			Key:    dim.Key,
			Value:  dim.Value,
			Source: &source,
		}
	}

	occurrence, err := buildOccurrence(d, s.now())
	if err != nil {
		return "", false, err
	}

	var event *port.FindingEventInput
	if d.Event != nil {
		event = &port.FindingEventInput{
			EventType: d.Event.EventType,
			OldValue:  emptyToNil(d.Event.OldValue),
			NewValue:  emptyToNil(d.Event.NewValue),
			Comment:   emptyToNil(d.Event.Comment),
			Changes:   d.Event.Changes,
		}
	}

	url, desc := evidencePayload(d)
	var evidence *port.EvidenceInput
	if d.Evidence != nil {
		evidence = &port.EvidenceInput{
			Type:        EvidenceTypeAutomated,
			URL:         url,
			Description: desc,
		}
	}

	f, err := s.stores.Findings.PersistWatcherFinding(ctx, port.PersistWatcherFindingInput{
		Finding: port.Finding{
			ProjectID:           fp.ProjectID,
			FindingKind:         fp.FindingKind,
			Fingerprint:         fp.Fingerprint,
			CurrentTitle:        fp.Title,
			CurrentSeverity:     fp.Severity,
			CurrentSeverityRank: fp.SeverityRank,
			CurrentScore:        scorePtr(fp.Score),
		},
		Dimensions: dimensions,
		Occurrence: occurrence,
		Event:      event,
		Evidence:   evidence,
	})
	if err == port.ErrFindingSuppressed {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return f.ID, true, nil
}

// PersistSkipEvent implements PollStore: a single event insert on the
// suppressing finding.
func (s *pgPollStore) PersistSkipEvent(ctx context.Context, suppressingID string, ev Event) error {
	return s.stores.Findings.PersistWatcherSkipEvent(ctx, suppressingID, port.FindingEventInput{
		EventType: ev.EventType,
		OldValue:  emptyToNil(ev.OldValue),
		NewValue:  emptyToNil(ev.NewValue),
		Comment:   emptyToNil(ev.Comment),
		Changes:   ev.Changes,
	})
}

// buildOccurrence computes the occurrence port input for a created decision.
// ReportID is nil (watcher findings have no scan report). The metadata gains
// raw_advisory = base64 of the evidence bytes, byte-exact. Pure and
// unit-testable.
func buildOccurrence(d Decision, now time.Time) (port.OccurrenceInput, error) {
	fp := d.Finding

	displayJSON, err := json.Marshal(fp.Display)
	if err != nil {
		return port.OccurrenceInput{}, fmt.Errorf("marshal display: %w", err)
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
		return port.OccurrenceInput{}, fmt.Errorf("marshal metadata: %w", err)
	}

	return port.OccurrenceInput{
		Title:          fp.Title,
		Description:    emptyToNil(fp.Description),
		Severity:       fp.Severity,
		SeverityRank:   fp.SeverityRank,
		Score:          fp.Score,
		ToolName:       occurrenceToolName,
		SubjectSummary: emptyToNil(fp.Title),
		Remediation:    emptyToNil(fp.Remediation),
		Display:        displayJSON,
		Metadata:       metadataJSON,
		ObservedAt:     now,
	}, nil
}

// evidencePayload derives the evidence artifact fields for a created decision:
// url = first advisory reference ("" when none), description = advisory
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

// emptyToNil maps an empty string to nil.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func scorePtr(s float64) *float64 {
	if s <= 0 {
		return nil
	}
	return &s
}
