package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// CVE detail provider names accepted in CVE_DETAIL_PROVIDERS.
const (
	CVEProviderNVD       = "nvd"
	CVEProviderVulnCheck = "vulncheck"
	CVEProviderOSV       = "osv"
)

// Defaults for the CVE detail providers. NVD allows 5 requests in 30 seconds
// without a key and 50 with one; the rates stay just under those limits.
const (
	DefaultCVEDetailTTL         = 24 * time.Hour
	DefaultCVEDetailNegativeTTL = 6 * time.Hour
	DefaultCVEDetailTimeout     = 10 * time.Second
	DefaultCVEDetailNVDRPS      = 0.16
	DefaultCVEDetailNVDKeyedRPS = 1.6
	DefaultCVEDetailVulnRPS     = 1.0
	DefaultCVEDetailOSVRPS      = 1.0
)

// CVEDetailConfig configures the external CVE detail providers. With no
// providers listed the server makes no CVE detail calls at all.
type CVEDetailConfig struct {
	// Providers lists the enabled providers in lookup order.
	Providers []string
	// NVDAPIKey and VulnCheckAPIKey are secrets: they are sent only as
	// request headers and never logged or returned by any API.
	NVDAPIKey       string
	VulnCheckAPIKey string
	// Base URLs override the vendor endpoints for tests and mirrors. Empty
	// means the vendor URL. They must be https.
	NVDBaseURL       string
	VulnCheckBaseURL string
	OSVBaseURL       string
	// AllowPrivateMirror lets a base URL resolve to a private address.
	AllowPrivateMirror bool
	TTL                time.Duration
	NegativeTTL        time.Duration
	Timeout            time.Duration
	// RPS is the request rate per provider name, in requests per second.
	RPS map[string]float64
}

// Enabled reports whether any provider is configured.
func (c CVEDetailConfig) Enabled() bool { return len(c.Providers) > 0 }

// LogValue keeps the API keys out of any log line that prints the config.
func (c CVEDetailConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("providers", c.Providers),
		slog.Bool("nvd_key_configured", c.NVDAPIKey != ""),
		slog.Bool("vulncheck_key_configured", c.VulnCheckAPIKey != ""),
		slog.Bool("allow_private_mirror", c.AllowPrivateMirror),
	)
}

// String keeps the API keys out of fmt output.
func (c CVEDetailConfig) String() string {
	return fmt.Sprintf("CVEDetailConfig{providers=%v nvd_key_configured=%t vulncheck_key_configured=%t}",
		c.Providers, c.NVDAPIKey != "", c.VulnCheckAPIKey != "")
}

// GoString keeps the API keys out of %#v output.
func (c CVEDetailConfig) GoString() string { return c.String() }

// loadCVEDetail reads the CVE_DETAIL_* variables. Unknown provider names are
// always an error. The other settings are validated only when a provider is
// listed, so a stray value cannot stop a server that never calls out.
func loadCVEDetail(s *Server) error {
	c := CVEDetailConfig{
		NVDAPIKey:        os.Getenv("CVE_DETAIL_NVD_API_KEY"),
		VulnCheckAPIKey:  os.Getenv("CVE_DETAIL_VULNCHECK_API_KEY"),
		NVDBaseURL:       os.Getenv("CVE_DETAIL_NVD_BASE_URL"),
		VulnCheckBaseURL: os.Getenv("CVE_DETAIL_VULNCHECK_BASE_URL"),
		OSVBaseURL:       os.Getenv("CVE_DETAIL_OSV_BASE_URL"),
		TTL:              DefaultCVEDetailTTL,
		NegativeTTL:      DefaultCVEDetailNegativeTTL,
		Timeout:          DefaultCVEDetailTimeout,
	}
	providers, err := parseCVEProviders(os.Getenv("CVE_DETAIL_PROVIDERS"))
	if err != nil {
		return err
	}
	c.Providers = providers
	nvdRPS := DefaultCVEDetailNVDRPS
	if c.NVDAPIKey != "" {
		nvdRPS = DefaultCVEDetailNVDKeyedRPS
	}
	c.RPS = map[string]float64{
		CVEProviderNVD:       nvdRPS,
		CVEProviderVulnCheck: DefaultCVEDetailVulnRPS,
		CVEProviderOSV:       DefaultCVEDetailOSVRPS,
	}
	s.CVEDetail = c
	if !c.Enabled() {
		return nil
	}

	var problems []error
	if v := os.Getenv("CVE_DETAIL_ALLOW_PRIVATE_MIRROR"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			problems = append(problems, fmt.Errorf("CVE_DETAIL_ALLOW_PRIVATE_MIRROR is invalid: %q (want true or false)", v))
		}
		c.AllowPrivateMirror = b
	}
	for _, d := range []struct {
		name string
		dst  *time.Duration
	}{
		{"CVE_DETAIL_TTL", &c.TTL},
		{"CVE_DETAIL_NEGATIVE_TTL", &c.NegativeTTL},
		{"CVE_DETAIL_TIMEOUT", &c.Timeout},
	} {
		if v := os.Getenv(d.name); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil || parsed <= 0 {
				problems = append(problems, fmt.Errorf("%s must be a positive duration, got %q", d.name, v))
				continue
			}
			*d.dst = parsed
		}
	}
	for _, name := range []string{CVEProviderNVD, CVEProviderVulnCheck, CVEProviderOSV} {
		env := "CVE_DETAIL_" + strings.ToUpper(name) + "_RPS"
		if v := os.Getenv(env); v != "" {
			rps, err := strconv.ParseFloat(v, 64)
			if err != nil || rps <= 0 || rps > 100 {
				problems = append(problems, fmt.Errorf("%s must be a number above 0 and at most 100, got %q", env, v))
				continue
			}
			c.RPS[name] = rps
		}
	}
	for _, u := range []struct{ name, value string }{
		{"CVE_DETAIL_NVD_BASE_URL", c.NVDBaseURL},
		{"CVE_DETAIL_VULNCHECK_BASE_URL", c.VulnCheckBaseURL},
		{"CVE_DETAIL_OSV_BASE_URL", c.OSVBaseURL},
	} {
		if u.value != "" && !isHTTPSURL(u.value) {
			problems = append(problems, fmt.Errorf("%s must be an https URL without credentials, got %q", u.name, redactURL(u.value)))
		}
	}
	for _, p := range c.Providers {
		if p == CVEProviderVulnCheck && c.VulnCheckAPIKey == "" {
			problems = append(problems, errors.New("CVE_DETAIL_VULNCHECK_API_KEY is required when CVE_DETAIL_PROVIDERS lists vulncheck"))
		}
	}
	s.CVEDetail = c
	return errors.Join(problems...)
}

// parseCVEProviders reads the ordered provider list, refusing unknown names
// and duplicates.
func parseCVEProviders(v string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(v, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		switch name {
		case CVEProviderNVD, CVEProviderVulnCheck, CVEProviderOSV:
		default:
			return nil, fmt.Errorf("CVE_DETAIL_PROVIDERS lists unknown provider %q (want nvd, vulncheck or osv)", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("CVE_DETAIL_PROVIDERS lists %q twice", name)
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// redactURL drops credentials and the query from a URL before it is echoed
// in an error.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable URL)"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}
