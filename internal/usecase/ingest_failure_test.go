package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

type failureRecord struct {
	status      string
	message     string
	ctxErr      error
	settled     bool
	settleCtx   error
	hasDeadline bool
}

// failureHarness makes an ingest whose finding upsert fails and records how
// the report was settled.
func failureHarness(t *testing.T) (*Usecases, *failureRecord) {
	t.Helper()
	uc, fr, rr := autofixHarness(t, "")
	rec := &failureRecord{}
	fr.upsertFn = func(context.Context, port.UpsertFindingInput) (port.Finding, error) {
		return port.Finding{}, errors.New("connection reset")
	}
	rr.updateStatusFn = func(ctx context.Context, _, _ string, status string, _ int32, msg *string) (port.Report, error) {
		rec.status, rec.ctxErr = status, ctx.Err()
		if msg != nil {
			rec.message = *msg
		}
		_, rec.hasDeadline = ctx.Deadline()
		return makeReport(), nil
	}
	rr.settleFailedFn = func(ctx context.Context, _, _ string) error {
		rec.settled, rec.settleCtx = true, ctx.Err()
		return nil
	}
	return uc, rec
}

// A client that hangs up cancels the request context. The last step of a
// failed ingest, which marks the report failed and settles its findings, must
// not die with it: the report would stay in processing.
func TestIngestReport_MarksTheReportFailedEvenWhenTheContextIsCancelled(t *testing.T) {
	uc, rec := failureHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := uc.IngestReport(ctx, IngestReportInput{ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"a":1}`)})

	require.Error(t, err)
	assert.Equal(t, "failed", rec.status)
	assert.Equal(t, reportFailureFindings, rec.message)
	assert.NoError(t, rec.ctxErr, "the status write ran on a live context")
	assert.True(t, rec.settled, "the half-written findings are settled")
	assert.NoError(t, rec.settleCtx)
	assert.True(t, rec.hasDeadline, "the detached step is still bounded")
}

func TestIngestReport_FailedReportStepOutlivesAnExpiredDeadline(t *testing.T) {
	uc, rec := failureHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	_, err := uc.IngestReport(ctx, IngestReportInput{ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"a":1}`)})

	require.Error(t, err)
	assert.Equal(t, "failed", rec.status)
	assert.NoError(t, rec.ctxErr)
}

// A report whose completion cannot be written is failed too, instead of being
// left in processing with all its occurrences.
func TestIngestReport_MarksTheReportFailedWhenCompletionCannotBeWritten(t *testing.T) {
	uc, fr, rr := autofixHarness(t, "")
	_ = fr
	var statuses []string
	rr.updateStatusFn = func(_ context.Context, _, _ string, status string, _ int32, _ *string) (port.Report, error) {
		statuses = append(statuses, status)
		if status == "completed" {
			return port.Report{}, errors.New("connection reset")
		}
		return makeReport(), nil
	}
	rr.settleFailedFn = func(context.Context, string, string) error { return nil }

	_, err := uc.IngestReport(context.Background(), IngestReportInput{ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"a":1}`)})

	require.Error(t, err)
	assert.Equal(t, []string{"completed", "failed"}, statuses)
}

func TestReportFailureReasonForResponse_KeepsTheCompletionReason(t *testing.T) {
	reason := reportFailureCompletion
	assert.Equal(t, &reason, reportFailureReasonForResponse(&reason))
}
