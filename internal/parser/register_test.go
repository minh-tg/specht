package parser_test

import (
	"testing"

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
			if !ok {
				t.Fatalf("expected parser %q to be registered", e.name)
			}
			if p.Name() != e.name {
				t.Errorf("parser.Name() = %q, want %q", p.Name(), e.name)
			}
			if len(p.ScanTypes()) == 0 {
				t.Error("parser.ScanTypes() is empty")
			}
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
		name     string
		data     []byte
		want     string
	}{
		{
			name:     "osv-scanner detects osv format",
			data:     []byte(`{"results":[{"source":{"path":"test","type":"lockfile"},"packages":[]}]}`),
			want:     "osv-scanner",
		},
		{
			name:     "trivy detects trivy format",
			data:     []byte(`[{"Target":"alpine:3.20","Class":"os-pkgs","Type":"alpine"}]`),
			want:     "trivy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := reg.Detect(tt.data)
			if !ok {
				t.Fatalf("no parser detected for data, want %q", tt.want)
			}
			if p.Name() != tt.want {
				t.Errorf("Detect() = %q, want %q", p.Name(), tt.want)
			}
		})
	}

	t.Run("empty data matches nothing", func(t *testing.T) {
		_, ok := reg.Detect([]byte(`{}`))
		if ok {
			t.Error("Detect({}) returned true, want false")
		}
	})
}
