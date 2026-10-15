package scanner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

// graded is a scanner whose recognition depends on the first byte of the data:
// 'D' is definite, 'P' is possible, anything else is not recognized.
type graded struct{ name string }

func (g *graded) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{Name: g.name, Version: "1", ContractVersion: 1, FingerprintVersion: 1}
}

func (g *graded) Parse(context.Context, []byte) (*domain.NormalizedReport, error) {
	return &domain.NormalizedReport{}, nil
}

func (g *graded) DetectFormat(data []byte) bool { return g.Recognize(data) == scanner.Definite }

func (g *graded) Recognize(data []byte) scanner.Recognition {
	if len(data) == 0 {
		return scanner.NotRecognized
	}
	switch data[0] {
	case 'D':
		return scanner.Definite
	case 'P':
		return scanner.Possible
	}
	return scanner.NotRecognized
}

func TestRecognizeFallsBackToDetectFormat(t *testing.T) {
	plain := &testScanner{name: "plain", kind: "sca", version: "1"}
	assert.Equal(t, scanner.Definite, scanner.Recognize(plain, []byte("anything")))
	assert.Equal(t, scanner.NotRecognized, scanner.Recognize(plain, nil))
}

func TestRecognizeUsesTheScannersOwnGrade(t *testing.T) {
	g := &graded{name: "graded"}
	assert.Equal(t, scanner.Definite, scanner.Recognize(g, []byte("D")))
	assert.Equal(t, scanner.Possible, scanner.Recognize(g, []byte("P")))
	assert.Equal(t, scanner.NotRecognized, scanner.Recognize(g, []byte("x")))
}

func checkFormatRegistry(t *testing.T, names ...string) *scanner.Registry {
	t.Helper()
	r := scanner.NewRegistry()
	for _, n := range names {
		require.NoError(t, r.Register(&graded{name: n}))
	}
	return r
}

func TestCheckFormat(t *testing.T) {
	// "named" is the scanner the caller chose; "other" is a second scanner that grades the same way.
	r := checkFormatRegistry(t, "named", "other")

	t.Run("a definite match is accepted", func(t *testing.T) {
		assert.NoError(t, r.CheckFormat("named", []byte("D")))
	})

	t.Run("a possible match is accepted when no other scanner is sure", func(t *testing.T) {
		assert.NoError(t, r.CheckFormat("named", []byte("P")))
	})

	t.Run("an unrecognized document is refused and names nothing when nothing fits", func(t *testing.T) {
		err := r.CheckFormat("named", []byte("x"))
		require.ErrorIs(t, err, scanner.ErrUnrecognizedFormat)
		var fe *scanner.UnrecognizedFormatError
		require.ErrorAs(t, err, &fe)
		assert.Equal(t, "named", fe.Scanner)
		assert.Empty(t, fe.LooksLike)
	})

	t.Run("an unknown scanner is not found", func(t *testing.T) {
		assert.ErrorIs(t, r.CheckFormat("missing", []byte("D")), scanner.ErrNoMatch)
	})
}

func TestCheckFormatNamesTheScannerTheDocumentLooksLike(t *testing.T) {
	// "named" only knows 'N' (definite); "alpha" and "beta" know 'A' and 'B'.
	r := scanner.NewRegistry()
	require.NoError(t, r.Register(&prefixed{name: "named", definite: 'N', possible: 'p'}))
	require.NoError(t, r.Register(&prefixed{name: "alpha", definite: 'A'}))
	require.NoError(t, r.Register(&prefixed{name: "beta", definite: 'B'}))

	t.Run("a document that is another tool's output is refused with that tool named", func(t *testing.T) {
		err := r.CheckFormat("named", []byte("A"))
		var fe *scanner.UnrecognizedFormatError
		require.ErrorAs(t, err, &fe)
		assert.Equal(t, []string{"alpha"}, fe.LooksLike)
		assert.Contains(t, err.Error(), "alpha")
	})

	t.Run("an ambiguous empty document is refused when another tool is sure", func(t *testing.T) {
		// 'p' is possible for "named", but a second scanner definitely owns it.
		require.NoError(t, r.Register(&prefixed{name: "gamma", definite: 'p'}))
		err := r.CheckFormat("named", []byte("p"))
		var fe *scanner.UnrecognizedFormatError
		require.ErrorAs(t, err, &fe)
		assert.Equal(t, []string{"gamma"}, fe.LooksLike)
	})

	t.Run("the named scanner's own definite match is never second-guessed", func(t *testing.T) {
		assert.NoError(t, r.CheckFormat("named", []byte("N")))
	})
}

func TestUnrecognizedErrorMessageIsSafeToShow(t *testing.T) {
	err := &scanner.UnrecognizedFormatError{Scanner: "trivy", LooksLike: []string{"grype", "sarif"}}
	assert.Equal(t, "the data is not trivy output; it looks like grype or sarif output", err.Error())
	assert.Equal(t, "the data is not trivy output", (&scanner.UnrecognizedFormatError{Scanner: "trivy"}).Error())
}

func TestMalformedKeepsBothCauses(t *testing.T) {
	cause := errors.New("bad field")
	err := scanner.Malformed("trivy", cause)
	assert.ErrorIs(t, err, scanner.ErrMalformedReport)
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "trivy")
}

// prefixed grades by the first byte: its definite byte is definite, its possible byte is possible.
type prefixed struct {
	name     string
	definite byte
	possible byte
}

func (p *prefixed) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{Name: p.name, Version: "1", ContractVersion: 1, FingerprintVersion: 1}
}

func (p *prefixed) Parse(context.Context, []byte) (*domain.NormalizedReport, error) {
	return &domain.NormalizedReport{}, nil
}

func (p *prefixed) DetectFormat(data []byte) bool { return p.Recognize(data) == scanner.Definite }

func (p *prefixed) Recognize(data []byte) scanner.Recognition {
	switch {
	case len(data) == 0:
		return scanner.NotRecognized
	case data[0] == p.definite:
		return scanner.Definite
	case p.possible != 0 && data[0] == p.possible:
		return scanner.Possible
	}
	return scanner.NotRecognized
}
