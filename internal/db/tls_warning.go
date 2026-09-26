package db

import (
	"log/slog"
	"net"
	"net/url"
	"strings"
)

// WarnInsecureMigrationURL logs a warning when startup migrations use a
// non-local database without TLS. It returns true when the warning applies.
func WarnInsecureMigrationURL(databaseURL string) bool {
	if !insecureRemoteURL(databaseURL) {
		return false
	}
	u, _ := url.Parse(databaseURL)
	slog.Warn("startup migrations are connecting to a non-local database with TLS disabled; set POSTGRES_SSLMODE=require or verify-full", "database_host", u.Hostname())
	return true
}

func insecureRemoteURL(databaseURL string) bool {
	u, err := url.Parse(databaseURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(u.Query().Get("sslmode"), "disable") {
		return false
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		return !ip.IsLoopback()
	}
	return !strings.EqualFold(u.Hostname(), "localhost")
}
