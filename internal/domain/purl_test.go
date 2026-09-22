package domain_test

import (
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestNormalizePURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "quality-free purl passes through",
			in:   "pkg:golang/github.com/gogo/protobuf@v1.3.1",
			want: "pkg:golang/github.com/gogo/protobuf@v1.3.1",
		},
		{
			name: "qualifiers are stripped",
			in:   "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64&distro=3.20.3",
			want: "pkg:apk/alpine/libcrypto3@3.3.2-r0",
		},
		{
			name: "subpath is stripped",
			in:   "pkg:generic/foo/bar@1.2.3#/sub/path",
			want: "pkg:generic/foo/bar@1.2.3",
		},
		{
			name: "qualifiers and subpath both stripped",
			in:   "pkg:maven/com.example/lib@1.0.0?type=jar#/base",
			want: "pkg:maven/com.example/lib@1.0.0",
		},
		{
			name: "empty string passes through",
			in:   "",
			want: "",
		},
		{
			name: "non-purl passes through",
			in:   "libcrypto3@3.3.2-r0",
			want: "libcrypto3@3.3.2-r0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, domain.NormalizePURL(tt.in))
		})
	}
}

func TestSplitPURL(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantType    string
		wantName    string
		wantVersion string
	}{
		{
			name:        "maven group and artifact",
			in:          "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
			wantType:    "maven",
			wantName:    "org.apache.logging.log4j/log4j-core",
			wantVersion: "2.17.0",
		},
		{
			name:        "go module",
			in:          "pkg:golang/github.com/gogo/protobuf@v1.3.1",
			wantType:    "golang",
			wantName:    "github.com/gogo/protobuf",
			wantVersion: "v1.3.1",
		},
		{
			name:        "qualifiers ignored",
			in:          "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64",
			wantType:    "apk",
			wantName:    "alpine/libcrypto3",
			wantVersion: "3.3.2-r0",
		},
		{
			name:     "no version",
			in:       "pkg:generic/foo/bar",
			wantType: "generic",
			wantName: "foo/bar",
		},
		{
			name:     "type only",
			in:       "pkg:maven",
			wantType: "maven",
		},
		{
			name: "non-purl yields empty components",
			in:   "example.com/foo@1.0.0",
		},
		{
			name: "empty string yields empty components",
			in:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgType, name, version := domain.SplitPURL(tt.in)
			assert.Equal(t, tt.wantType, pkgType)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

// TestPurlIdentityIsSharedBetweenFindingsAndInventory guards the version-1
// invariant that findings and inventory normalize purls through the same
// function (internal/domain owns the single normalization path).
func TestPurlIdentityIsSharedBetweenFindingsAndInventory(t *testing.T) {
	assert.Equal(t,
		domain.NormalizePURL("pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64&distro=3.20.3"),
		domain.NormalizePURL("pkg:apk/alpine/libcrypto3@3.3.2-r0"),
	)
}
