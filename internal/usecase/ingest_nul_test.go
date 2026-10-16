package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

var nulEscapeText = fmt.Sprintf("%cu0000", 92)

// nulHarness registers a scanner that records the bytes it parses, and returns
// the bytes the report is stored with.
func nulHarness(t *testing.T) (uc *Usecases, parsed, stored *string) {
	t.Helper()
	uc, _, rr := autofixHarness(t, domain.CompletenessUnknown)
	parsed, stored = new(string), new(string)
	s := &mockScanner{name: "recording", parseFn: func(_ context.Context, data []byte) (*domain.NormalizedReport, error) {
		*parsed = string(data)
		return &domain.NormalizedReport{
			ScanType:  domain.ScanTypeImage,
			Target:    &domain.TargetInfo{Kind: "container", Identifier: "img:latest"},
			Findings:  []domain.NormalizedFinding{{Fingerprint: "fp", FindingKind: "sca", Title: "t", Severity: domain.SeverityHigh}},
			ScanScope: &domain.ScanScope{},
		}, nil
	}}
	require.NoError(t, uc.deps.Registry.(*scanner.Registry).Register(s))
	rr.createFn = func(_ context.Context, arg port.CreateReportInput) (port.Report, error) {
		*stored = string(arg.RawData)
		return makeReport(), nil
	}
	return uc, parsed, stored
}

func TestIngestReport_DropsNULEscapesBeforeAnythingReadsTheDocument(t *testing.T) {
	uc, parsed, stored := nulHarness(t)
	doc := `{"title":"a` + nulEscapeText + `b","path":"` + nulEscapeText + `x","nested":{"k":["` + nulEscapeText + `"]}}`

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "recording", RawData: json.RawMessage(doc),
	})

	require.NoError(t, err)
	const want = `{"title":"ab","path":"x","nested":{"k":[""]}}`
	assert.Equal(t, want, *parsed, "the parser reads the document without the NUL")
	assert.Equal(t, want, *stored, "and so does the stored evidence")
}

func TestIngestReport_RefusesANULInAFieldNameAsAMalformedReport(t *testing.T) {
	uc, parsed, stored := nulHarness(t)
	doc := `{"Secr` + nulEscapeText + `et":"AKIA-VALUE"}`

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "recording", RawData: json.RawMessage(doc),
	})

	require.ErrorIs(t, err, scanner.ErrMalformedReport)
	assert.NotContains(t, err.Error(), "AKIA-VALUE")
	assert.Empty(t, *parsed, "nothing was parsed")
	assert.Empty(t, *stored, "nothing was stored")
}

func TestIngestReport_LeavesADocumentWithoutNULAsItIs(t *testing.T) {
	uc, parsed, stored := nulHarness(t)
	doc := `{"a":"` + strings.Repeat("x", 100) + `"}`

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "recording", RawData: json.RawMessage(doc),
	})

	require.NoError(t, err)
	assert.Equal(t, doc, *parsed)
	assert.Equal(t, doc, *stored)
}
