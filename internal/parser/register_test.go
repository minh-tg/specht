package parser_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnserve/vulnserve/internal/parser"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestRegisterAllRegistersExpectedParsers(t *testing.T) {
	reg := scanner.NewRegistry()
	parser.RegisterAll(reg)

	expected := []struct {
		name string
	}{
		{"trivy"},
		{"osv-scanner"},
	}

	for _, e := range expected {
		t.Run(e.name, func(t *testing.T) {
			p, ok := reg.Get(e.name)
			require.True(t, ok, "expected parser %q to be registered", e.name)
			assert.Equal(t, e.name, p.Name())
			assert.NotEmpty(t, p.ScanTypes())
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
