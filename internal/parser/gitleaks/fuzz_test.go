package gitleaks_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/minh-tg/specht/internal/parser/gitleaks"
	"github.com/minh-tg/specht/internal/parser/parsertest"
	"github.com/minh-tg/specht/internal/scanner"
)

// FuzzParse drives Recognize and Parse with the real fixtures as seeds. It
// fails only on a panic or a broken hardening invariant; parse errors are an
// accepted outcome for hostile input.
func FuzzParse(f *testing.F) {
	parsertest.Seeds(f, "testdata")
	s := gitleaks.NewScanner()
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

// FuzzRedactRaw checks RedactRaw never panics, returns no output with an
// error, and returns valid JSON otherwise.
func FuzzRedactRaw(f *testing.F) {
	parsertest.Seeds(f, "testdata")
	s := gitleaks.NewScanner()
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := s.RedactRaw(data)
		if err != nil {
			if out != nil {
				t.Fatalf("an error must come with no output, got %q", out)
			}
			return
		}
		if !json.Valid(out) {
			t.Fatalf("redacted evidence is not valid JSON: %q", out)
		}
	})
}
