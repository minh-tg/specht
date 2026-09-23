package usecase

import (
	"testing"

	"github.com/minh-tg/specht/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListScannersReturnsRegisteredCapabilitiesInOrder(t *testing.T) {
	registry := scanner.NewRegistry()
	require.NoError(t, registry.Register(&mockScanner{name: "trivy"}))
	require.NoError(t, registry.Register(&mockScanner{name: "semgrep"}))
	uc := New(Deps{Registry: registry})

	got := uc.ListScanners()

	require.Len(t, got, 2)
	assert.Equal(t, ScannerDescriptorResponse{
		Name:                  "trivy",
		Version:               "test",
		FindingKinds:          []string{"sca", "test"},
		ScanTypes:             []string{"image", "filesystem"},
		ProvidesPackages:      true,
		SupportsAutoDetection: false,
	}, got[0])
	assert.Equal(t, "semgrep", got[1].Name)
	assert.Equal(t, []string{"sca", "test"}, got[1].FindingKinds)
}

func TestListScannersReturnsNilWithoutARegistry(t *testing.T) {
	uc := New(Deps{})

	assert.Nil(t, uc.ListScanners())
}
