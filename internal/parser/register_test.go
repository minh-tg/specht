package parser_test

import (
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuiltinsIncludesExpectedParsers(t *testing.T) {
	builtins := parser.Builtins()
	names := make([]string, len(builtins))
	for i, s := range builtins {
		names[i] = s.Descriptor().Name
	}

	expected := []string{"trivy", "osv-scanner", "semgrep", "checkov", "dependency-check", "grype", "sbom", "sarif", "gitleaks", "tfsec", "nuclei"}
	for _, e := range expected {
		assert.Contains(t, names, e, "expected builtin scanner %q", e)
	}
}

func TestBuiltinsDescriptorsAreNonEmpty(t *testing.T) {
	for _, s := range parser.Builtins() {
		d := s.Descriptor()
		assert.NotEmpty(t, d.Name, "descriptor name must be non-empty")
		if d.ProvidesPackages && len(d.FindingKinds) == 0 {
			continue
		}
		assert.NotEmpty(t, d.FindingKinds, "%q must declare at least one finding kind", d.Name)
		assert.NotEmpty(t, d.ScanTypes, "%q must declare at least one scan type", d.Name)
		assert.NotZero(t, d.ContractVersion, "%q must declare a contract version", d.Name)
		assert.NotZero(t, d.FingerprintVersion, "%q must declare a fingerprint version", d.Name)
	}
}

func TestBuiltinsRegistryOnboardingContract(t *testing.T) {
	builtins := parser.Builtins()
	registry := scanner.NewRegistry()
	seen := make(map[string]struct{}, len(builtins))

	expectedIncremental := map[string]bool{
		"checkov":          true,
		"gitleaks":         true,
		"semgrep":          true,
		"tfsec":            true,
		"dependency-check": false,
		"grype":            false,
		"nuclei":           false,
		"osv-scanner":      false,
		"sarif":            false,
		"sbom":             false,
		"trivy":            false,
	}

	for _, s := range builtins {
		d := s.Descriptor()
		require.NotEmpty(t, d.Name)
		_, duplicate := seen[d.Name]
		assert.False(t, duplicate, "scanner names must be unique: %q", d.Name)
		seen[d.Name] = struct{}{}
		require.NoError(t, registry.Register(s), "register %q", d.Name)
		assert.Equal(t, expectedIncremental[d.Name], scanner.SupportsIncremental(s),
			"%q must explicitly declare its incremental capability", d.Name)
	}
	assert.Len(t, seen, len(expectedIncremental))

	// Detection of an unsupported payload is stable across repeated calls.
	payload := []byte("not a scanner report")
	_, firstErr := registry.Detect(payload)
	_, secondErr := registry.Detect(payload)
	require.ErrorIs(t, firstErr, scanner.ErrNoMatch)
	require.ErrorIs(t, secondErr, scanner.ErrNoMatch)
	assert.Equal(t, firstErr.Error(), secondErr.Error())

	// Re-registering any built-in must never silently replace the adapter.
	for _, s := range builtins {
		assert.ErrorIs(t, registry.Register(s), scanner.ErrDuplicateName,
			"duplicate scanner %q must be rejected", s.Descriptor().Name)
	}
}

func TestBuiltinsRegisterCleanly(t *testing.T) {
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	require.Len(t, reg.List(), 11)

	for _, s := range parser.Builtins() {
		got, err := reg.Get(s.Descriptor().Name)
		require.NoError(t, err, "scanner %q must be registered", s.Descriptor().Name)
		assert.Equal(t, s.Descriptor().Name, got.Descriptor().Name)
	}
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
			name: "semgrep sarif is claimed by both sarif adapters",
			data: []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","version":"1.0.0"}},"results":[]}]}`),
			want: "ambiguous",
		},
		{
			name: "sarif detects non-semgrep sarif",
			data: []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","version":"3.0"}},"results":[]}]}`),
			want: "sarif",
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
			if tt.want == "ambiguous" {
				assert.ErrorIs(t, err, scanner.ErrAmbiguousMatch,
					"semgrep SARIF matches two adapters; ingest selects by explicit name")
				return
			}
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
		domain.ScanTypeDAST:       true,
	}
	for _, s := range parser.Builtins() {
		for _, st := range s.Descriptor().ScanTypes {
			assert.True(t, valid[st], "%q declares invalid scan type %q", s.Descriptor().Name, st)
		}
	}
}
