package usecase

// ScannerDescriptorResponse is the API representation of one scanner
// capability. It is capability discovery for compile-time plugins — never
// runtime code loading.
type ScannerDescriptorResponse struct {
	Name                  string   `json:"name"`
	Version               string   `json:"version"`
	FindingKinds          []string `json:"finding_kinds"`
	ScanTypes             []string `json:"scan_types"`
	ProvidesPackages      bool     `json:"provides_packages"`
	SupportsAutoDetection bool     `json:"supports_auto_detection"`
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
		out[i] = ScannerDescriptorResponse{
			Name:                  d.Name,
			Version:               d.Version,
			FindingKinds:          kinds,
			ScanTypes:             types,
			ProvidesPackages:      d.ProvidesPackages,
			SupportsAutoDetection: d.SupportsAutoDetection,
		}
	}
	return out
}
