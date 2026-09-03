// Package cvss is a thin facade over the go-cvss library: it detects the CVSS
// version from a vector prefix and delegates scoring to the matching
// sub-version implementation. Callers never import go-cvss directly.
package cvss

import (
	"fmt"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

func Calculate(vector string) (float64, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return calculate40(vector)
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		return calculate31(vector)
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return calculate30(vector)
	case strings.HasPrefix(vector, "CVSS:2.0/"):
		return calculate20(vector)
	default:
		return 0, fmt.Errorf("cvss: unsupported or malformed vector: %q", vector)
	}
}

func calculate20(vector string) (float64, error) {
	v, err := gocvss20.ParseVector(vector[len("CVSS:2.0/"):])
	if err != nil {
		return 0, fmt.Errorf("cvss: %w", err)
	}
	return v.BaseScore(), nil
}

func calculate30(vector string) (float64, error) {
	v, err := gocvss30.ParseVector(vector)
	if err != nil {
		return 0, fmt.Errorf("cvss: %w", err)
	}
	return v.BaseScore(), nil
}

func calculate31(vector string) (float64, error) {
	v, err := gocvss31.ParseVector(vector)
	if err != nil {
		return 0, fmt.Errorf("cvss: %w", err)
	}
	return v.BaseScore(), nil
}

func calculate40(vector string) (float64, error) {
	v, err := gocvss40.ParseVector(vector)
	if err != nil {
		return 0, fmt.Errorf("cvss: %w", err)
	}
	return v.Score(), nil
}
