package main

import (
	"net"
	"net/url"
	"strings"
)

// insecureDBTransport returns a warning when dbURL sends database traffic
// over a connection TLS does not protect to a host other than this machine,
// and "" otherwise. sslmode disable and allow never encrypt when the server
// permits plaintext, and prefer (also the driver default when unset) can be
// downgraded by anyone who can interfere with the connection. The warning
// never includes credentials.
func insecureDBTransport(dbURL string) string {
	host, mode, ok := dbTransportSettings(dbURL)
	if !ok || isLocalDBHost(host) {
		return ""
	}
	switch mode {
	case "disable", "allow", "prefer":
	case "":
		mode = "prefer"
	default:
		return ""
	}
	return "database connection to " + host + " is not protected by verified TLS (sslmode=" + mode +
		"); set sslmode=require or verify-full unless this is a trusted local network"
}

// dbTransportSettings returns the host and sslmode of a Postgres connection
// string, in either URL form or keyword/value form. ok is false when the string
// is neither.
func dbTransportSettings(dbURL string) (host, mode string, ok bool) {
	if u, err := url.Parse(dbURL); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		host = u.Hostname()
		if host == "" {
			host = u.Query().Get("host")
		}
		return host, u.Query().Get("sslmode"), true
	}
	if !strings.Contains(dbURL, "=") {
		return "", "", false
	}
	params := map[string]string{}
	for _, field := range strings.Fields(dbURL) {
		if key, value, found := strings.Cut(field, "="); found {
			params[key] = strings.Trim(value, "'")
		}
	}
	return params["host"], params["sslmode"], true
}

// isLocalDBHost reports whether host is this machine: empty (the default
// socket), a Unix socket path, localhost, or a loopback address.
func isLocalDBHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "/") || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
