package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// EnvAllowInsecureHTTP names the variable that lets a client send its key over
// plain http to a host that is not on the loopback interface.
const EnvAllowInsecureHTTP = "SPECHT_ALLOW_INSECURE_HTTP"

// DefaultAPIURL is the server the command-line tools talk to when no URL is
// configured.
const DefaultAPIURL = "http://localhost:8080"

// EnvAPIURL returns the Specht base URL from API_URL, or from its alias
// SPECHT_API_URL when API_URL is empty. The order matches the adapter.
func EnvAPIURL(getenv func(string) string) string {
	return firstEnv(getenv, "API_URL", "SPECHT_API_URL")
}

// ResolveAPIURL returns the checked Specht base URL: the environment value, or
// DefaultAPIURL when none is set.
func ResolveAPIURL(getenv func(string) string) (string, error) {
	apiURL := EnvAPIURL(getenv)
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	if err := CheckAPIURL(apiURL, getenv); err != nil {
		return "", err
	}
	return apiURL, nil
}

// CheckAPIURL refuses an API URL that would send the bearer key or session
// token in clear text: a plain http URL whose host is not loopback. The
// variable named by EnvAllowInsecureHTTP set to 1 or true opts out, for a
// server that sits behind a trusted network. The check looks at the host name
// only and does not resolve it, so a name that points at a loopback address
// still needs https.
func CheckAPIURL(rawURL string, getenv func(string) string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("API_URL must be an http:// or https:// URL such as https://specht.example.com")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		switch strings.ToLower(strings.TrimSpace(getenv(EnvAllowInsecureHTTP))) {
		case "1", "true":
			return nil
		}
		return fmt.Errorf("API_URL uses plain http to %s, which would send the API key unencrypted; use https, or set %s=1 to allow it", u.Host, EnvAllowInsecureHTTP)
	default:
		return fmt.Errorf("API_URL must be an http:// or https:// URL such as https://specht.example.com")
	}
}

// isLoopbackHost reports whether host names this machine: localhost, a name
// under .localhost, or a loopback IP address.
func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// EnvAPIKey returns the API key from API_KEY, or from its alias
// SPECHT_API_KEY when API_KEY is empty. The order matches the adapter.
func EnvAPIKey(getenv func(string) string) string {
	return firstEnv(getenv, "API_KEY", "SPECHT_API_KEY")
}

func firstEnv(getenv func(string) string, names ...string) string {
	for _, name := range names {
		if v := getenv(name); v != "" {
			return v
		}
	}
	return ""
}
