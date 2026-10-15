package cli

import (
	"bytes"
	"io"
	"math"
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

// A nil slice marshals to null, which breaks a script that loops over the result. An empty list
// has to read as [].
func TestJSONOutputWritesAnEmptyListAsAnArray(t *testing.T) {
	type row struct{ ID string }
	tests := []struct {
		name string
		v    any
		want string
	}{
		{"nil slice", []row(nil), "[]\n"},
		{"empty slice", []row{}, "[]\n"},
		{"slice with items", []row{{ID: "a"}}, "[\n  {\n    \"ID\": \"a\"\n  }\n]\n"},
		{"nil pointer stays null", (*row)(nil), "null\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeJSONOut(&out, tc.v); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("got %q, want %q", out.String(), tc.want)
			}
		})
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

func TestLimitArg(t *testing.T) {
	tests := []struct {
		in      int
		want    int32
		wantErr bool
	}{
		{0, 0, false},
		{25, 25, false},
		{math.MaxInt32, math.MaxInt32, false},
		{-1, 0, true},
		{math.MaxInt32 + 1, 0, true},
		{4294967297, 0, true}, // would wrap to 1 in an int32 conversion
	}
	for _, tc := range tests {
		got, err := limitArg("--limit", tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("limitArg(%d) = %d, %v; want %d, error %v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}
