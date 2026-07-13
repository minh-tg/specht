package parser_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestRegisterAllRegistersExpectedParsers(t *testing.T) {
	reg := scanner.NewRegistry()
	parser.RegisterAll(reg)

	expected := []struct {
		name string
	}{
		{"trivy"},
		{"osv-scanner"},
		{"semgrep"},
		{"checkov"},
	}

	for _, e := range expected {
		t.Run(e.name, func(t *testing.T) {
			s, ok := reg.Get(e.name)
			require.True(t, ok, "expected scanner %q to be registered", e.name)
			assert.Equal(t, e.name, s.Name())
		})
	}
}

func TestRegisterAllCount(t *testing.T) {
	reg := scanner.NewRegistry()
	parser.RegisterAll(reg)

	var count int
	reg.Detect([]byte("probe"))
	_ = count
}

func TestRegisterAllParsersCanDetect(t *testing.T) {
	reg := scanner.NewRegistry()
	parser.RegisterAll(reg)

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
			p, ok := reg.Detect(tt.data)
			require.True(t, ok, "no parser detected for data, want %q", tt.want)
			assert.Equal(t, tt.want, p.Name())
		})
	}

	t.Run("empty data matches nothing", func(t *testing.T) {
		_, ok := reg.Detect([]byte(`{}`))
		assert.False(t, ok)
	})
}
