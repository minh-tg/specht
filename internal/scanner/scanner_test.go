package scanner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testScanner struct {
	name    string
	kind    scanner.FindingKind
	version string
}

func (s *testScanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  s.name,
		Version:               s.version,
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{s.kind},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

func (s *testScanner) Parse(_ context.Context, _ []byte) (*domain.NormalizedReport, error) {
	return &domain.NormalizedReport{ScanType: domain.ScanTypeFilesystem}, nil
}

func (s *testScanner) DetectFormat(data []byte) bool {
	return len(data) > 0
}

// selectiveScanner only matches data prefixed with matchPrefix.
type selectiveScanner struct {
	name        string
	matchPrefix []byte
}

func (s *selectiveScanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  s.name,
		Version:               "1",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"selective"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem},
		SupportsAutoDetection: true,
	}
}

func (s *selectiveScanner) Parse(_ context.Context, _ []byte) (*domain.NormalizedReport, error) {
	return &domain.NormalizedReport{}, nil
}

func (s *selectiveScanner) DetectFormat(data []byte) bool {
	return len(s.matchPrefix) > 0 && len(data) > 0 && len(data) >= len(s.matchPrefix) && string(data[:len(s.matchPrefix)]) == string(s.matchPrefix)
}

// incrementalScanner opts into incremental analysis.
type incrementalScanner struct {
	testScanner
}

func (s *incrementalScanner) SupportsIncremental() bool { return true }

func TestSupportsIncremental(t *testing.T) {
	assert.False(t, scanner.SupportsIncremental(&testScanner{name: "full-only"}))
	assert.True(t, scanner.SupportsIncremental(&incrementalScanner{testScanner{name: "sast"}}))
	assert.False(t, scanner.SupportsIncremental(nil))
}

func TestSeverityValues(t *testing.T) {
	tests := []struct {
		severity domain.Severity
		name     string
		want     int
	}{
		{domain.SeverityUnknown, "unknown", 0},
		{domain.SeverityLow, "low", 1},
		{domain.SeverityMedium, "medium", 2},
		{domain.SeverityHigh, "high", 3},
		{domain.SeverityCritical, "critical", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int(tt.severity))
		})
	}
}

func TestSCAFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		vulnID string
		purl   string
		want   domain.Fingerprint
	}{
		{"standard", "CVE-2024-1234", "pkg:npm/foo@1.0.0", "CVE-2024-1234:pkg:npm/foo@1.0.0"},
		{"empty vuln id", "", "pkg:npm/foo", ":pkg:npm/foo"},
		{"empty purl", "CVE-2024-1234", "", "CVE-2024-1234:"},
		{"both empty", "", "", ":"},
		{"ghsa format", "GHSA-xxxx-xxxx-xxxx", "pkg:golang/foo/bar", "GHSA-xxxx-xxxx-xxxx:pkg:golang/foo/bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domain.SCAFingerprint(tt.vulnID, tt.purl)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewRegistry(t *testing.T) {
	r := scanner.NewRegistry()
	require.NotNil(t, r)
}

func TestRegistryRegisterGet(t *testing.T) {
	r := scanner.NewRegistry()
	p := &testScanner{name: "test-parser", kind: "test"}
	require.NoError(t, r.Register(p))

	got, err := r.Get("test-parser")
	require.NoError(t, err)
	assert.Equal(t, "test-parser", got.Descriptor().Name)
}

func TestRegistryGetUnknown(t *testing.T) {
	r := scanner.NewRegistry()
	_, err := r.Get("nonexistent")
	assert.ErrorIs(t, err, scanner.ErrNoMatch)
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	r := scanner.NewRegistry()
	p1 := &testScanner{name: "overwrite-me", kind: "test"}
	p2 := &testScanner{name: "overwrite-me", kind: "test"}
	require.NoError(t, r.Register(p1))
	err := r.Register(p2)
	assert.ErrorIs(t, err, scanner.ErrDuplicateName)
	// First registration wins; registration order retained.
	got, err := r.Get("overwrite-me")
	require.NoError(t, err)
	assert.Equal(t, "overwrite-me", got.Descriptor().Name)
}

func TestRegistryRegisterNilAndInvalid(t *testing.T) {
	r := scanner.NewRegistry()
	assert.ErrorIs(t, r.Register(nil), scanner.ErrInvalidDescriptor)
	assert.ErrorIs(t, r.Register(&testScanner{kind: "test"}), scanner.ErrInvalidDescriptor)
}

func TestRegistryDetect(t *testing.T) {
	r := scanner.NewRegistry()
	p := &testScanner{name: "detect-parser", kind: "test"}
	require.NoError(t, r.Register(p))

	matched, err := r.Detect([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, "detect-parser", matched.Descriptor().Name)
}

func TestRegistryDetectNoMatch(t *testing.T) {
	r := scanner.NewRegistry()
	_, err := r.Detect([]byte("data"))
	assert.ErrorIs(t, err, scanner.ErrNoMatch)
}

func TestRegistryDetectEmptyData(t *testing.T) {
	r := scanner.NewRegistry()
	require.NoError(t, r.Register(&testScanner{name: "p", kind: "test"}))
	_, err := r.Detect([]byte{})
	assert.ErrorIs(t, err, scanner.ErrNoMatch)
}

func TestScanTypeConstants(t *testing.T) {
	tests := []struct {
		scanType domain.ScanType
		name     string
		want     string
	}{
		{domain.ScanTypeImage, "image", "image"},
		{domain.ScanTypeFilesystem, "filesystem", "filesystem"},
		{domain.ScanTypeRepository, "repository", "repository"},
		{domain.ScanTypeIaC, "iac", "iac"},
		{domain.ScanTypeSBOM, "sbom", "sbom"},
		{domain.ScanTypeLockfile, "lockfile", "lockfile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.scanType))
		})
	}
}

func TestRegistryDetectAmbiguous(t *testing.T) {
	r := scanner.NewRegistry()
	require.NoError(t, r.Register(&testScanner{name: "scanner-a", kind: "test"}))
	require.NoError(t, r.Register(&testScanner{name: "scanner-b", kind: "test"}))
	require.NoError(t, r.Register(&testScanner{name: "scanner-c", kind: "test"}))

	_, err := r.Detect([]byte("data"))
	assert.ErrorIs(t, err, scanner.ErrAmbiguousMatch)
}

func TestRegistryDetectWithSelectiveMatchers(t *testing.T) {
	// Test that a scanner matching only specific data works when it is the only match.
	r := scanner.NewRegistry()
	selective := &selectiveScanner{name: "selective", matchPrefix: []byte("secret")}
	require.NoError(t, r.Register(selective))

	got, err := r.Detect([]byte("secret stuff"))
	require.NoError(t, err)
	assert.Equal(t, "selective", got.Descriptor().Name)

	// Test that a non-matching prefix returns nothing (not detected by selective scanner).
	_, err = r.Detect([]byte("other data"))
	assert.ErrorIs(t, err, scanner.ErrNoMatch)

	// Separate registry: a generic (all-non-empty) scanner alone.
	r2 := scanner.NewRegistry()
	require.NoError(t, r2.Register(&testScanner{name: "generic", kind: "test"}))

	got2, err2 := r2.Detect([]byte("other data"))
	require.NoError(t, err2)
	assert.Equal(t, "generic", got2.Descriptor().Name)
}

func TestRegistryListOrdered(t *testing.T) {
	r := scanner.NewRegistry()
	require.NoError(t, r.Register(&testScanner{name: "z-first", kind: "a"}))
	require.NoError(t, r.Register(&testScanner{name: "a-second", kind: "b"}))
	require.NoError(t, r.Register(&testScanner{name: "m-third", kind: "c"}))

	list := r.List()
	require.Len(t, list, 3)
	assert.Equal(t, "z-first", list[0].Name)
	assert.Equal(t, "a-second", list[1].Name)
	assert.Equal(t, "m-third", list[2].Name)
}

func TestDescriptorForKind(t *testing.T) {
	r := scanner.NewRegistry()
	require.NoError(t, r.Register(&testScanner{name: "multi-a", kind: "sca"}))
	require.NoError(t, r.Register(&testScanner{name: "multi-b", kind: "iac"}))

	sca := r.DescriptorForKind("sca")
	require.Len(t, sca, 1)
	assert.Equal(t, "multi-a", sca[0].Name)

	iac := r.DescriptorForKind("iac")
	require.Len(t, iac, 1)
	assert.Equal(t, "multi-b", iac[0].Name)

	assert.Empty(t, r.DescriptorForKind("secret"))
}

func TestScannerInterfaceIsDomainBoundary(t *testing.T) {
	// Parse returns *domain.NormalizedReport — the scanner package no longer
	// defines the normalized model.
	var s scanner.Scanner = &testScanner{name: "boundary", kind: "test"}
	nr, err := s.Parse(context.Background(), nil)
	require.NoError(t, err)
	assert.NotNil(t, nr)
	_ = domain.NormalizedReport{}
}

func TestFingerprintType(t *testing.T) {
	// Fingerprint is a distinct named type, not just a string alias
	var fp domain.Fingerprint = "custom-fp"
	assert.Equal(t, "custom-fp", string(fp))

	// Empty Fingerprint is valid
	var empty domain.Fingerprint
	assert.Equal(t, "", string(empty))
	assert.Equal(t, 0, len(empty))
}

func TestGetReturnsScannerNotFoundError(t *testing.T) {
	r := scanner.NewRegistry()
	_, err := r.Get("missing")
	assert.True(t, errors.Is(err, scanner.ErrNoMatch))
}
