package repo

import "testing"

func TestEscapeLikePattern(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "underscore", input: "a_b", want: `a\_b`},
		{name: "percent", input: "a%b", want: `a\%b`},
		{name: "backslash", input: `a\b`, want: `a\\b`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeLikePattern(tt.input); got != tt.want {
				t.Errorf("escapeLikePattern(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
