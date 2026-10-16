package parseutil_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// FuzzReadShape checks the shape prober on arbitrary bytes.
func FuzzReadShape(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte("[]"))
	f.Add([]byte("null"))
	f.Add([]byte("nul"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, ok := parseutil.ReadShape(data)
		if ok {
			_ = s.String("x")
			_, _ = s.List("x")
			_ = s.Has("x")
		}
	})
}

// FuzzHardenExtensions checks the size cap and the NUL strip on payloads built
// from fuzzed keys and values.
func FuzzHardenExtensions(f *testing.F) {
	f.Add("key", "value", 10)
	f.Add("k\x00", "v\x00", 20000)
	f.Add("", strings.Repeat("é", 100), 3)
	f.Fuzz(func(t *testing.T, key, value string, repeat int) {
		repeat = max(0, min(repeat, 40000))
		big := strings.Repeat(value, repeat)
		in := map[string]any{
			key:      big,
			"list":   []any{big, map[string]any{key: value}},
			"strs":   []string{value, big},
			"number": 1.5,
		}
		out := parseutil.HardenExtensions(in)
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatalf("result cannot be serialized: %v", err)
		}
		if len(b) > parseutil.MaxExtensionsBytes {
			t.Fatalf("%d bytes exceed the cap", len(b))
		}
		if strings.Contains(string(b), `\u0000`) {
			t.Fatalf("NUL survives: %.80s", b)
		}
	})
}
