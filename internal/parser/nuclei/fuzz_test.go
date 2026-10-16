package nuclei_test

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/parser/nuclei"
	"github.com/minh-tg/specht/internal/parser/parsertest"
	"github.com/minh-tg/specht/internal/scanner"
)

// FuzzParse drives Recognize and Parse with the real fixtures as seeds. It
// fails only on a panic or a broken hardening invariant; parse errors are an
// accepted outcome for hostile input.
func FuzzParse(f *testing.F) {
	parsertest.Seeds(f, "testdata")
	s := nuclei.NewScanner()
	ctx := scanner.WithFingerprintKey(context.Background(), []byte("fuzz-key-0123456789abcdef"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = s.Recognize(data)
		rep, err := s.Parse(ctx, data)
		if err != nil {
			return
		}
		parsertest.Check(t, rep)
	})
}

// FuzzRedactRaw checks RedactRaw never panics.
func FuzzRedactRaw(f *testing.F) {
	parsertest.Seeds(f, "testdata")
	s := nuclei.NewScanner()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = s.RedactRaw(data)
	})
}
