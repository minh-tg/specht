package usecase

import "github.com/minh-tg/specht/internal/scanner"

// ScannerDescriptorResponse is the API representation of one scanner
// capability. It is capability discovery for compile-time plugins — never
// runtime code loading.
type ScannerDescriptorResponse struct {
	Name string `json:"name"`
	// DisplayName is what people call the tool; Name is the identifier to send.
	DisplayName           string   `json:"display_name"`
	Version               string   `json:"version"`
	FindingKinds          []string `json:"finding_kinds"`
	ScanTypes             []string `json:"scan_types"`
	ProvidesPackages      bool     `json:"provides_packages"`
	SupportsAutoDetection bool     `json:"supports_auto_detection"`
	// SupportsAutoClose is true when a report from this scanner can prove a
	// finding is gone. False means findings it reports are never closed by a
	// later scan that omits them.
	SupportsAutoClose bool                    `json:"supports_auto_close"`
	Formats           []ScannerFormatResponse `json:"formats"`
}

// ScannerFormatResponse describes one file a scanner reads and how to make it.
type ScannerFormatResponse struct {
	Name       string   `json:"name"`
	Extensions []string `json:"extensions"`
	Command    string   `json:"command"`
	TestedWith string   `json:"tested_with"`
	Note       string   `json:"note,omitempty"`
}

// ListScanners returns every registered scanner's capability descriptor in
// deterministic (registration) order.
func (u *Usecases) ListScanners() []ScannerDescriptorResponse {
	if u.deps.Registry == nil {
		return nil
	}
	descriptors := u.deps.Registry.List()
	out := make([]ScannerDescriptorResponse, len(descriptors))
	for i, d := range descriptors {
		kinds := make([]string, len(d.FindingKinds))
		for j, k := range d.FindingKinds {
			kinds[j] = string(k)
		}
		types := make([]string, len(d.ScanTypes))
		for j, t := range d.ScanTypes {
			types[j] = string(t)
		}
		formats := make([]ScannerFormatResponse, len(d.Formats))
		for j, f := range d.Formats {
			formats[j] = ScannerFormatResponse{
				Name: f.Name, Extensions: f.Extensions, Command: f.Command, TestedWith: f.TestedWith, Note: f.Note,
			}
		}
		autoClose := false
		if sc, err := u.deps.Registry.Get(d.Name); err == nil {
			autoClose = scanner.SupportsAutoClose(sc)
		}
		out[i] = ScannerDescriptorResponse{
			Name:                  d.Name,
			DisplayName:           d.ShownName(),
			Formats:               formats,
			Version:               d.Version,
			FindingKinds:          kinds,
			ScanTypes:             types,
			ProvidesPackages:      d.ProvidesPackages,
			SupportsAutoDetection: d.SupportsAutoDetection,
			SupportsAutoClose:     autoClose,
		}
	}
	return out
}
