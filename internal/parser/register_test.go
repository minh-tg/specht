package parser_test

import (
	"testing"

	"github.com/xMinhx/specht/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestBuiltinsIncludesExpectedParsers(t *testing.T) {
	builtins := parser.Builtins()
	names := make([]string, len(builtins))
	for i, s := range builtins {
		names[i] = s.Descriptor().Name
	}

	expected := []string{"trivy", "osv-scanner", "semgrep", "checkov", "dependency-check", "grype"}
	for _, e := range expected {
		assert.Contains(t, names, e, "expected builtin scanner %q", e)
	}
}

func TestBuiltinsDescriptorsAreNonEmpty(t *testing.T) {
	for _, s := range parser.Builtins() {
		d := s.Descriptor()
		assert.NotEmpty(t, d.Name, "descriptor name must be non-empty")
		assert.NotEmpty(t, d.FindingKinds, "%q must declare at least one finding kind", d.Name)
		assert.NotEmpty(t, d.ScanTypes, "%q must declare at least one scan type", d.Name)
		assert.NotZero(t, d.ContractVersion, "%q must declare a contract version", d.Name)
		assert.NotZero(t, d.FingerprintVersion, "%q must declare a fingerprint version", d.Name)
	}
}

func TestBuiltinsRegisterCleanly(t *testing.T) {
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	require.Len(t, reg.List(), 6)

	for _, s := range parser.Builtins() {
		got, err := reg.Get(s.Descriptor().Name)
		require.NoError(t, err, "scanner %q must be registered", s.Descriptor().Name)
		assert.Equal(t, s.Descriptor().Name, got.Descriptor().Name)
	}
}

func TestBuiltinsCount(t *testing.T) {
	assert.Len(t, parser.Builtins(), 6)
}

func TestBuiltinsDetectFormats(t *testing.T) {
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "osv-scanner detects osv format",
			data: []byte(`{"results":[{"source":{"path":"test","type":"lockfile"},"packages":[]}]}`),
			want: "osv-scanner",
		},
		{
			name: "trivy detects trivy format",
			data: []byte(`[{"Target":"alpine:3.20","Class":"os-pkgs","Type":"alpine"}]`),
			want: "trivy",
		},
		{
			name: "semgrep detects sarif format",
			data: []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","version":"1.0.0"}},"results":[]}]}`),
			want: "semgrep",
		},
		{
			name: "checkov detects checkov json format",
			data: []byte(`{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[],"parsing_errors":[]},"summary":{"passed":0,"failed":0,"skipped":0,"parsing_errors":0}}`),
			want: "checkov",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := reg.Detect(tt.data)
			require.NoError(t, err, "no parser detected for data, want %q", tt.want)
			assert.Equal(t, tt.want, p.Descriptor().Name)
		})
	}

	t.Run("empty data matches nothing", func(t *testing.T) {
		_, err := reg.Detect([]byte(`{}`))
		assert.ErrorIs(t, err, scanner.ErrNoMatch)
	})
}

func TestBuiltinsScanTypesMatchDatabase(t *testing.T) {
	// The database scan_type check (000007_create_findings era) accepts the
	// six ScanType constants; every descriptor's declared scan types must be
	// among them.
	valid := map[domain.ScanType]bool{
		domain.ScanTypeImage:      true,
		domain.ScanTypeFilesystem: true,
		domain.ScanTypeRepository: true,
		domain.ScanTypeIaC:        true,
		domain.ScanTypeSBOM:       true,
		domain.ScanTypeLockfile:   true,
	}
	for _, s := range parser.Builtins() {
		for _, st := range s.Descriptor().ScanTypes {
			assert.True(t, valid[st], "%q declares invalid scan type %q", s.Descriptor().Name, st)
		}
	}
}
