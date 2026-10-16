package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

// redactingScanner is a scanner whose redaction hook the test controls.
type redactingScanner struct {
	mockScanner
	redact func([]byte) ([]byte, error)
}

func (s *redactingScanner) RedactRaw(data []byte) ([]byte, error) { return s.redact(data) }

func newRedactingScanner(redact func([]byte) ([]byte, error)) *redactingScanner {
	return &redactingScanner{
		mockScanner: mockScanner{
			name: "redacting",
			parseFn: func(context.Context, []byte) (*domain.NormalizedReport, error) {
				return &domain.NormalizedReport{
					ScanType:     domain.ScanTypeImage,
					Completeness: domain.CompletenessUnknown,
					Target:       &domain.TargetInfo{Kind: "container", Identifier: "img:latest"},
					Findings: []domain.NormalizedFinding{{
						Fingerprint: "fp", FindingKind: "sca", Title: "t", Severity: domain.SeverityHigh,
					}},
					ScanScope: &domain.ScanScope{},
				}, nil
			},
		},
		redact: redact,
	}
}

const evidenceWithASecret = `[{"Secret":"AKIA-STORED-SECRET","x":1}]`

func TestRedactRaw_FailureStoresThePlaceholderNeverTheInput(t *testing.T) {
	hooks := map[string]func([]byte) ([]byte, error){
		"error": func([]byte) ([]byte, error) { return nil, errors.New("cannot decode") },
		"typed": func([]byte) ([]byte, error) { return nil, scanner.ErrRedactionFailed },
		"empty": func([]byte) ([]byte, error) { return nil, nil },
		"blank": func([]byte) ([]byte, error) { return []byte{}, nil },
		"panic": func([]byte) ([]byte, error) { panic("boom") },
		"input": func(b []byte) ([]byte, error) { return b, errors.New("returned the input with an error") },
	}
	for name, hook := range hooks {
		t.Run(name, func(t *testing.T) {
			stored, failed := redactRaw(newRedactingScanner(hook), []byte(evidenceWithASecret))

			assert.True(t, failed)
			assert.JSONEq(t, `{"redaction":"failed"}`, string(stored))
			assert.NotContains(t, string(stored), "AKIA-STORED-SECRET")
		})
	}
}

func TestRedactRaw_SuccessStoresTheRedactedBytes(t *testing.T) {
	hook := func([]byte) ([]byte, error) { return []byte(`[{"Secret":"[REDACTED]"}]`), nil }

	stored, failed := redactRaw(newRedactingScanner(hook), []byte(evidenceWithASecret))

	assert.False(t, failed)
	assert.JSONEq(t, `[{"Secret":"[REDACTED]"}]`, string(stored))
}

func TestRedactRaw_ScannersWithoutAHookKeepTheirBytes(t *testing.T) {
	stored, failed := redactRaw(&mockScanner{name: "plain"}, []byte(`{"a":1}`))

	assert.False(t, failed)
	assert.Equal(t, `{"a":1}`, string(stored))
}

// The failure shows up in the report that is written, not only in the helper.
func TestIngestReport_StoresThePlaceholderWhenRedactionFails(t *testing.T) {
	cases := map[string]func([]byte) ([]byte, error){
		"error": func([]byte) ([]byte, error) { return nil, errors.New("cannot decode") },
		"panic": func([]byte) ([]byte, error) { panic("boom") },
	}
	for name, hook := range cases {
		t.Run(name, func(t *testing.T) {
			uc, _, rr := autofixHarness(t, domain.CompletenessUnknown)
			require.NoError(t, uc.deps.Registry.(*scanner.Registry).Register(newRedactingScanner(hook)))
			var created port.CreateReportInput
			rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
				created = arg
				return makeReport(), nil
			}

			_, err := uc.IngestReport(context.Background(), IngestReportInput{
				ProjectSlug: "my-app", Scanner: "redacting", RawData: json.RawMessage(evidenceWithASecret),
			})

			require.NoError(t, err, "the report is still ingested, with its findings")
			assert.JSONEq(t, scanner.RedactionFailedEvidence, string(created.RawData))
			assert.NotContains(t, string(created.RawData), "AKIA-STORED-SECRET")
		})
	}
}
