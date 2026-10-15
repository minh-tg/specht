package usecase

import (
	"context"
	"encoding/json"
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
