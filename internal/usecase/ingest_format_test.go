package usecase

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

func builtinRegistryUsecase(t *testing.T) *Usecases {
	t.Helper()
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	pr, _, _ := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	// Only the project store is given. A refused document must not reach any other store.
	return New(Deps{Stores: &port.Stores{Projects: pr}, Registry: reg})
}

func TestIngestReport_RefusesAnotherToolsOutput(t *testing.T) {
	uc := builtinRegistryUsecase(t)
	grypeReport := `{"matches":[],"source":{},"distro":{},"descriptor":{"name":"grype","version":"0.120.0"}}`

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(grypeReport),
	})

	require.ErrorIs(t, err, scanner.ErrUnrecognizedFormat)
	var fe *scanner.UnrecognizedFormatError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, "trivy", fe.Scanner)
	assert.Equal(t, []string{"grype"}, fe.LooksLike, "the caller is told which scanner to pick")
}

func TestIngestReport_RefusesOutputOfAToolWithNoParser(t *testing.T) {
	uc := builtinRegistryUsecase(t)

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"Golang errors":{},"Issues":[],"Stats":{}}`),
	})

	require.ErrorIs(t, err, scanner.ErrUnrecognizedFormat)
	var fe *scanner.UnrecognizedFormatError
	require.ErrorAs(t, err, &fe)
	assert.Empty(t, fe.LooksLike, "nothing registered fits, so nothing is suggested")
}

func TestIngestReport_UnknownScannerIsTyped(t *testing.T) {
	uc := builtinRegistryUsecase(t)

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "no-such-tool",
		RawData:     json.RawMessage(`{}`),
	})

	require.ErrorIs(t, err, ErrUnknownScanner)
	assert.Contains(t, err.Error(), "no-such-tool")
}

func TestIngestReport_RefusesADocumentWithTooManyObjectsBeforeDecodingIt(t *testing.T) {
	uc := builtinRegistryUsecase(t)
	uc.deps.IngestMaxFindings = 5
	doc := `{"Results":[{"Target":"t","Vulnerabilities":[` + strings.TrimSuffix(strings.Repeat("{},", 5*scanner.ObjectsPerFinding+1), ",") + `]}]}`

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(doc),
	})

	require.ErrorIs(t, err, scanner.ErrTooManyFindings)
	var tooMany *scanner.TooManyFindingsError
	require.ErrorAs(t, err, &tooMany)
	assert.Equal(t, 5, tooMany.Limit, "the configured limit, not the default")
}

// The document scan in IngestReport runs before the format check. A report that
// both is not the named scanner's output and holds far too many objects must be
// refused for its size: the format check decodes the document, which is what
// the scan exists to prevent. Without the scan the answer would be
// ErrUnrecognizedFormat, and every parser's own scan would still catch real
// reports, so only the order shows that ingest calls it.
func TestIngestReport_ScansTheDocumentBeforeCheckingItsFormat(t *testing.T) {
	const limit = 5
	grypeShaped := func(items string) json.RawMessage {
		return json.RawMessage(`{"matches":[` + items + `],"descriptor":{"name":"grype","version":"0.120.0"}}`)
	}
	cases := map[string]json.RawMessage{
		"too many objects": grypeShaped(strings.TrimSuffix(strings.Repeat("{},", limit*scanner.ObjectsPerFinding+1), ",")),
		"too many values":  grypeShaped(strings.TrimSuffix(strings.Repeat("0,", limit*scanner.ValuesPerFinding+1), ",")),
		"padding values":   grypeShaped(strings.TrimSuffix(strings.Repeat("null,", 1000), ",")),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			uc := builtinRegistryUsecase(t)
			uc.deps.IngestMaxFindings = limit

			_, err := uc.IngestReport(context.Background(), IngestReportInput{ProjectSlug: "my-app", Scanner: "trivy", RawData: doc})

			require.ErrorIs(t, err, scanner.ErrTooManyFindings)
			require.NotErrorIs(t, err, scanner.ErrUnrecognizedFormat, "the format check must not have run")
		})
	}
}
