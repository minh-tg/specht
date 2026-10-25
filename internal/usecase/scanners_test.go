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
		DisplayName:           "trivy",
		Version:               "test",
		Formats:               []ScannerFormatResponse{},
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

// describedScanner is a scanner that tells people about its files.
type describedScanner struct{ mockScanner }

func (d *describedScanner) Descriptor() scanner.Descriptor {
	desc := d.mockScanner.Descriptor()
	desc.DisplayName = "Semgrep"
	desc.Formats = []scanner.Format{
		{Name: "JSON", Extensions: []string{".json"}, Command: "semgrep scan --json", TestedWith: "Semgrep 1.172.0"},
		{Name: "SARIF", Extensions: []string{".json", ".sarif"}, Command: "semgrep scan --sarif", TestedWith: "Semgrep 1.172.0", Note: "Same findings."},
	}
	return desc
}

func TestListScannersTellsPeopleWhatEachOneReads(t *testing.T) {
	registry := scanner.NewRegistry()
	require.NoError(t, registry.Register(&describedScanner{mockScanner{name: "semgrep"}}))

	got := New(Deps{Registry: registry}).ListScanners()

	require.Len(t, got, 1)
	assert.Equal(t, "semgrep", got[0].Name, "the registered name is still the identifier")
	assert.Equal(t, "Semgrep", got[0].DisplayName)
	assert.Equal(t, []ScannerFormatResponse{
		{Name: "JSON", Extensions: []string{".json"}, Command: "semgrep scan --json", TestedWith: "Semgrep 1.172.0"},
		{Name: "SARIF", Extensions: []string{".json", ".sarif"}, Command: "semgrep scan --sarif", TestedWith: "Semgrep 1.172.0", Note: "Same findings."},
	}, got[0].Formats)
}

// closingScanner can prove a fix.
type closingScanner struct{ mockScanner }

func (c *closingScanner) SupportsAutoClose() bool { return true }

func TestListScannersSaysWhichOnesCanCloseFindings(t *testing.T) {
	registry := scanner.NewRegistry()
	require.NoError(t, registry.Register(&closingScanner{mockScanner{name: "trivy"}}))
	require.NoError(t, registry.Register(&mockScanner{name: "gitleaks"}))

	got := New(Deps{Registry: registry}).ListScanners()

	require.Len(t, got, 2)
	assert.True(t, got[0].SupportsAutoClose)
	assert.False(t, got[1].SupportsAutoClose)
}

func TestFindingScannerNamesTheLastObserver(t *testing.T) {
	registry := scanner.NewRegistry()
	require.NoError(t, registry.Register(&closingScanner{mockScanner{name: "trivy"}}))
	require.NoError(t, registry.Register(&mockScanner{name: "gitleaks"}))
	uc := New(Deps{Registry: registry})

	assert.Equal(t, &FindingScannerResponse{Name: "trivy", DisplayName: "trivy", SupportsAutoClose: true}, uc.findingScanner("trivy"))
	assert.False(t, uc.findingScanner("gitleaks").SupportsAutoClose)
	assert.Nil(t, uc.findingScanner("unregistered"))
	assert.Nil(t, uc.findingScanner(""))
	assert.Nil(t, New(Deps{}).findingScanner("trivy"))
}
