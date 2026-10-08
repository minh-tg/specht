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
	u, err := url.Parse(dbURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		host = u.Query().Get("host")
	}
	if isLocalDBHost(host) {
		return ""
	}
	mode := u.Query().Get("sslmode")
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

// isLocalDBHost reports whether host is this machine: empty (the default
// socket), a Unix socket path, localhost, or a loopback address.
func isLocalDBHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "/") || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
