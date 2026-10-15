package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestEmitWritesHumanTextByDefault(t *testing.T) {
	var out bytes.Buffer
	d := Deps{Out: &out}
	err := emit(d, &settings{}, map[string]string{"a": "b"}, func(w io.Writer) error {
		_, err := io.WriteString(w, "human\n")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "human\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestEmitWritesJSONWhenAsked(t *testing.T) {
	var out bytes.Buffer
	d := Deps{Out: &out}
	err := emit(d, &settings{format: "json"}, map[string]string{"a": "b"}, func(io.Writer) error {
		t.Fatal("the human writer must not run for --format json")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "{\n  \"a\": \"b\"\n}\n" {
		t.Fatalf("got %q", got)
	}
}

func TestEmitRefusesAnUnknownFormat(t *testing.T) {
	err := emit(Deps{Out: io.Discard}, &settings{format: "yaml"}, nil, func(io.Writer) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "yaml") {
		t.Fatalf("want an error naming the format, got %v", err)
	}
}

func TestParseWhen(t *testing.T) {
	t.Run("a full timestamp is kept", func(t *testing.T) {
		got, err := parseWhen("--expires", "2026-12-31T10:30:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(time.Date(2026, 12, 31, 10, 30, 0, 0, time.UTC)) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("a date means the end of that day, UTC", func(t *testing.T) {
		got, err := parseWhen("--expires", "2026-12-31")
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("anything else is refused and names the flag", func(t *testing.T) {
		for _, in := range []string{"tomorrow", "31/12/2026", "2026-13-01", ""} {
			_, err := parseWhen("--expires", in)
			if err == nil || !strings.Contains(err.Error(), "--expires") {
				t.Fatalf("%q: want an error naming --expires, got %v", in, err)
			}
		}
	})
}

func TestSplitIDs(t *testing.T) {
	got := splitIDs([]string{"a,b", " c ", "", "d"})
	want := []string{"a", "b", "c", "d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
