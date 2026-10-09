// Package sbom adapts CycloneDX and SPDX SBOM documents to the normalized
// domain model. SBOMs are inventory: the adapter emits package references
// and no findings. Vulnerability correlation happens downstream — the
// watcher gap-fills inventory against OSV, and SCA findings match the same
// normalized purls.
//
// Supported envelopes (documented behavior):
//   - CycloneDX 1.x JSON (bomFormat "CycloneDX"): components[] with name,
//     version, purl, and type. The root metadata.component becomes the scan
//     target; document serialNumber/tool flow into scan-scope extensions.
//   - SPDX 2.x JSON (spdxVersion "SPDX-2.x"): packages[] with name,
//     versionInfo, supplier, and externalRefs (purl references preferred).
//
// Explicitly out of the normalized model: per-component licenses,
// dependency graphs, hashes, and signatures. PackageRef carries identity
// (purl, ecosystem, name, version); richer SBOM content stays in the raw
// report bytes. Malformed documents fail Parse; valid documents with zero
// components yield an empty package list, never an error.
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

// Scanner adapts SBOM documents to the normalized domain model.
type Scanner struct{}

// NewScanner builds the SBOM adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "sbom",
		Version:               "1",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          nil,
		ScanTypes:             []domain.ScanType{domain.ScanTypeSBOM},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.BOMFormat == "CycloneDX" || strings.HasPrefix(probe.SPDXVersion, "SPDX-")
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("sbom: parse json: %w", err)
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(data)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-"):
		return parseSPDX(data)
	default:
		return nil, fmt.Errorf("sbom: unrecognized document (want CycloneDX bomFormat or SPDX spdxVersion)")
	}
}

type cyclonedxDoc struct {
	SerialNumber string `json:"serialNumber"`
	SpecVersion  string `json:"specVersion"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"components"`
		} `json:"tools"`
		Component *struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

func parseCycloneDX(data []byte) (*domain.NormalizedReport, error) {
	var doc cyclonedxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("sbom: parse cyclonedx: %w", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessComplete,
		ScanType:           domain.ScanTypeSBOM,
		ScanScope:          &domain.ScanScope{},
	}
	nr.ScanScope.Ext = map[string]string{"sbom_format": "CycloneDX"}
	if doc.SpecVersion != "" {
		nr.ScanScope.Ext["sbom_spec_version"] = doc.SpecVersion
	}
	if doc.SerialNumber != "" {
		nr.ScanScope.Ext["sbom_serial"] = doc.SerialNumber
	}
	if doc.Metadata.Component != nil {
		nr.Target = &domain.TargetInfo{
			Kind:       "package",
			Identifier: doc.Metadata.Component.Name + "@" + doc.Metadata.Component.Version,
		}
		if doc.Metadata.Component.Type != "" {
			nr.ScanScope.Ext["sbom_component_type"] = doc.Metadata.Component.Type
		}
	}
	for _, c := range doc.Components {
		if c.Name == "" {
			continue
		}
		nr.Packages = append(nr.Packages, parseutil.HardenPackage(domain.PackageRef{
			PURL:      c.PURL,
			Ecosystem: ecosystemFromPURL(c.PURL),
			Name:      c.Name,
			Version:   c.Version,
		}))
	}
	return nr, nil
}

type spdxDoc struct {
	SPDXVersion  string `json:"spdxVersion"`
	Name         string `json:"name"`
	DocumentName string `json:"documentName"`
	Packages     []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		Supplier     string `json:"supplier"`
		ExternalRefs []struct {
			ReferenceType string `json:"referenceType"`
			Reference     string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func parseSPDX(data []byte) (*domain.NormalizedReport, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("sbom: parse spdx: %w", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessComplete,
		ScanType:           domain.ScanTypeSBOM,
		ScanScope: &domain.ScanScope{Ext: map[string]string{
			"sbom_format":  "SPDX",
			"spdx_version": doc.SPDXVersion,
		}},
	}
	name := doc.DocumentName
	if name == "" {
		name = doc.Name
	}
	if name != "" {
		nr.Target = &domain.TargetInfo{Kind: "package", Identifier: name}
	}
	for _, p := range doc.Packages {
		if p.Name == "" {
			continue
		}
		purl := ""
		for _, r := range p.ExternalRefs {
			if r.ReferenceType == "purl" {
				purl = r.Reference
				break
			}
		}
		if p.VersionInfo == "" && purl == "" {
			continue
		}
		nr.Packages = append(nr.Packages, parseutil.HardenPackage(domain.PackageRef{
			PURL:      purl,
			Ecosystem: ecosystemFromPURL(purl),
			Name:      p.Name,
			Version:   p.VersionInfo,
		}))
	}
	return nr, nil
}

// ecosystemFromPURL derives the ecosystem from a package URL type
// (pkg:npm/... -> npm). Empty when no purl is present.
func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.Index(rest, "/"); i >= 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}
