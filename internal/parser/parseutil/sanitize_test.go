package parseutil

import (
	"math"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanFilePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"simple relative", "src/main.go", "src/main.go"},
		{"leading slash preserved", "/terraform/main.tf", "/terraform/main.tf"},
		{"windows backslashes", "src\\pkg\\util.go", "src/pkg/util.go"},
		{"windows drive letter", "C:\\Users\\user\\project\\main.go", "Users/user/project/main.go"},
		{"file uri with three slashes", "file:///workspace/repo/main.go", "workspace/repo/main.go"},
		{"file uri with localhost", "file://localhost/workspace/repo/main.go", "workspace/repo/main.go"},
		{"file uri relative", "file:src/index.ts", "src/index.ts"},
		{"percent encoded spaces", "my%20project/file.go", "my project/file.go"},
		{"redundant dots", "src/./pkg/../pkg/main.go", "src/pkg/main.go"},
		{"path traversal climbing out of root", "../../../../etc/passwd", "etc/passwd"},
		{"complex path traversal", "foo/../../../../var/log", "var/log"},
		{"null bytes stripped", "src/main\x00.go", "src/main.go"},
		{"control characters stripped", "src/main\x07\x1b.go", "src/main.go"},
		{"only root or dots", "../../../", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanFilePath(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCleanFilePath_BoundsLength(t *testing.T) {
	huge := strings.Repeat("a", MaxPathLength+500)
	got := CleanFilePath(huge)
	assert.LessOrEqual(t, len(got), MaxPathLength)
}

func TestSanitizeText(t *testing.T) {
	t.Run("strips null bytes", func(t *testing.T) {
		assert.Equal(t, "hello world", SanitizeText("hello\x00 world", 100))
	})

	t.Run("bounds length", func(t *testing.T) {
		assert.Equal(t, "abc", SanitizeText("abcdef", 3))
	})

	t.Run("preserves valid utf8 when truncating", func(t *testing.T) {
		// "こんにちは" is 3 bytes per char
		s := "こんにちは"
		got := TruncateString(s, 7) // 6 bytes for 2 chars
		assert.Equal(t, "こん", got)
	})
}

func TestSafeScore(t *testing.T) {
	assert.Equal(t, 0.0, SafeScore(math.NaN()))
	assert.Equal(t, 0.0, SafeScore(math.Inf(1)))
	assert.Equal(t, 0.0, SafeScore(math.Inf(-1)))
	assert.Equal(t, 0.0, SafeScore(-5.0))
	assert.Equal(t, 7.5, SafeScore(7.5))
	assert.Equal(t, 10.0, SafeScore(15.0))
}

func TestSafeLine(t *testing.T) {
	assert.Equal(t, 0, SafeLine(-10))
	assert.Equal(t, 42, SafeLine(42))
}

func TestBoundFingerprint_OverlongFingerprintsSharingAPrefixStayDistinct(t *testing.T) {
	shared := make([]byte, MaxFingerprintLength*3)
	for i := range shared {
		shared[i] = 'a'
	}
	a := BoundFingerprint(string(shared) + "x")
	b := BoundFingerprint(string(shared) + "y")
	if a == b {
		t.Fatalf("overlong fingerprints differing only at the end collapsed to %q", a)
	}
	if len(a) > MaxFingerprintLength || len(b) > MaxFingerprintLength {
		t.Fatalf("bounded fingerprints exceed the limit: %d and %d bytes", len(a), len(b))
	}
}

func TestBoundFingerprint(t *testing.T) {
	short := "sast:rule-1:main.go"
	assert.Equal(t, short, BoundFingerprint(short))

	huge := "sast:" + strings.Repeat("long-rule-id-part-", 50) + ":main.go"
	bounded := BoundFingerprint(huge)
	assert.LessOrEqual(t, len(bounded), MaxFingerprintLength)
	assert.Contains(t, bounded, ":")
}

func TestHardenFinding(t *testing.T) {
	finding := domain.NormalizedFinding{
		Fingerprint: strings.Repeat("f", 600),
		Title:       "Title with null\x00 and " + strings.Repeat("a", MaxTitleLength+10),
		Description: "Desc with null\x00 and " + strings.Repeat("b", MaxDescriptionLength+10),
		Location:    "loc\x00",
		Score:       math.NaN(),
		CodeLocation: &domain.CodeLocation{
			File:        "../../../../etc/passwd\x00",
			StartLine:   -5,
			EndLine:     -10,
			StartColumn: -1,
			Snippet:     "snippet\x00",
		},
		CVSS: &domain.CVSSInfo{
			Score:  math.Inf(1),
			Vector: "AV:N/\x00",
		},
		Dimensions: []domain.Dimension{
			{Key: "key\x00", Value: "val\x00" + strings.Repeat("v", MaxDimensionValueLength+20)},
		},
		Aliases: []string{"CVE-2024-0001\x00"},
		Fix: &domain.FixInfo{
			Summary: "fix\x00",
			URL:     "http://example.com/\x00",
		},
	}

	hardened := HardenFinding(finding)

	assert.NotContains(t, hardened.Title, "\x00")
	assert.LessOrEqual(t, len(hardened.Title), MaxTitleLength)

	assert.NotContains(t, hardened.Description, "\x00")
	assert.LessOrEqual(t, len(hardened.Description), MaxDescriptionLength)

	assert.NotContains(t, hardened.Location, "\x00")
	assert.Equal(t, 0.0, hardened.Score)

	require.NotNil(t, hardened.CodeLocation)
	assert.Equal(t, "etc/passwd", hardened.CodeLocation.File)
	assert.Equal(t, 0, hardened.CodeLocation.StartLine)
	assert.Equal(t, 0, hardened.CodeLocation.EndLine)

	require.NotNil(t, hardened.CVSS)
	assert.Equal(t, 0.0, hardened.CVSS.Score)
	assert.Equal(t, "AV:N/", hardened.CVSS.Vector)

	assert.Equal(t, "key", hardened.Dimensions[0].Key)
	assert.NotContains(t, hardened.Dimensions[0].Value, "\x00")
	assert.LessOrEqual(t, len(hardened.Dimensions[0].Value), MaxDimensionValueLength)

	assert.Equal(t, "CVE-2024-0001", hardened.Aliases[0])

	require.NotNil(t, hardened.Fix)
	assert.Equal(t, "fix", hardened.Fix.Summary)
	assert.Equal(t, "http://example.com/", hardened.Fix.URL)

	assert.LessOrEqual(t, len(hardened.Fingerprint), MaxFingerprintLength)
}

func FuzzCleanFilePath(f *testing.F) {
	f.Add("")
	f.Add("src/main.go")
	f.Add("../../../etc/passwd")
	f.Add("C:\\Users\\admin\\file.txt")
	f.Add("file:///workspace/repo/main.go")
	f.Add("file\x00name.go")
	f.Add("/terraform/main.tf")

	f.Fuzz(func(t *testing.T, in string) {
		got := CleanFilePath(in)
		assert.NotContains(t, got, "\x00")
		assert.LessOrEqual(t, len(got), MaxPathLength)
		assert.False(t, strings.HasPrefix(got, "../"))
	})
}

func FuzzHardenFinding(f *testing.F) {
	f.Add("rule-1", "path/to/file.go", "title", "description")
	f.Add("rule-2\x00", "../../../etc/passwd", "long title\x00", "desc")

	f.Fuzz(func(t *testing.T, ruleID, file, title, desc string) {
		finding := domain.NormalizedFinding{
			Fingerprint: "sast:" + ruleID + ":" + file,
			Title:       title,
			Description: desc,
			Location:    file,
		}
		hardened := HardenFinding(finding)
		assert.NotContains(t, hardened.Fingerprint, "\x00")
		assert.NotContains(t, hardened.Title, "\x00")
		assert.NotContains(t, hardened.Description, "\x00")
		assert.LessOrEqual(t, len(hardened.Fingerprint), MaxFingerprintLength)
		assert.LessOrEqual(t, len(hardened.Title), MaxTitleLength)
	})
}
