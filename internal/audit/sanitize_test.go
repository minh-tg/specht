package audit

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode"
)

// rawHandler records attribute values exactly as the logger handed them over,
// so a test sees what a sink that does no quoting of its own would write.
type rawHandler struct{ attrs map[string]string }

func (h *rawHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *rawHandler) Handle(_ context.Context, r slog.Record) error {
	h.attrs = map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		h.attrs[a.Key] = a.Value.String()
		return true
	})
	return nil
}
func (h *rawHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *rawHandler) WithGroup(string) slog.Handler      { return h }

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}

func TestLoggerEscapesControlCharactersInAttackerControlledFields(t *testing.T) {
	forged := "victim@example.com\n2026-01-01 INFO audit audit=auth.login outcome=success\x1b[31m\r\t"
	h := &rawHandler{}

	NewLogger(slog.New(h)).Log(context.Background(), Event{
		Name:    EventLogin,
		Outcome: OutcomeFailure,
		Project: "proj\nforged",
		Target:  forged,
		Error:   errors.New(forged).Error(),
	})

	for _, key := range []string{"project", "target", "error"} {
		if hasControl(h.attrs[key]) {
			t.Errorf("%s still holds a control character: %q", key, h.attrs[key])
		}
	}
	got := h.attrs["target"]
	for _, want := range []string{`\n`, `\x1b`, `\r`, `\t`} {
		if !strings.Contains(got, want) {
			t.Errorf("target %q does not show the escaped %s", got, want)
		}
	}
	if !strings.HasPrefix(got, "victim@example.com") {
		t.Errorf("readable text must survive: %q", got)
	}
}

func TestLoggerEscapesUnicodeLineSeparators(t *testing.T) {
	h := &rawHandler{}
	NewLogger(slog.New(h)).Log(context.Background(), Event{Name: EventLogin, Target: "a b c\x7fd"})
	if hasControl(h.attrs["target"]) {
		t.Errorf("separators or DEL survived: %q", h.attrs["target"])
	}
}

func TestLoggerLeavesOrdinaryTextAlone(t *testing.T) {
	h := &rawHandler{}
	NewLogger(slog.New(h)).Log(context.Background(), Event{Name: EventLogin, Target: "Ünïcode ✓ a***@example.com"})
	if got := h.attrs["target"]; got != "Ünïcode ✓ a***@example.com" {
		t.Errorf("target = %q", got)
	}
}

func TestLoggerBoundsTheLengthOfAnAttackerControlledField(t *testing.T) {
	h := &rawHandler{}
	NewLogger(slog.New(h)).Log(context.Background(), Event{Name: EventLogin, Target: strings.Repeat("x", 1<<20)})
	if got := len(h.attrs["target"]); got > 1024 {
		t.Errorf("a megabyte target was logged at %d bytes", got)
	}
}
