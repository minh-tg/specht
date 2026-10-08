package main

import (
	"strings"
	"testing"
)

func TestInsecureDBTransport(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string // substring of the warning, "" for none
	}{
		{"remote with TLS required", "postgres://u:p@db.internal:5432/x?sslmode=require", ""},
		{"remote verify-full", "postgres://u:p@db.internal/x?sslmode=verify-full", ""},
		{"remote with TLS disabled", "postgres://u:p@db.internal:5432/x?sslmode=disable", "sslmode=disable"},
		{"compose service name, disabled", "postgres://u:p@db:5432/x?sslmode=disable", "sslmode=disable"},
		{"remote, sslmode unset", "postgres://u:p@db.internal/x", "sslmode=prefer"},
		{"remote, opportunistic", "postgres://u:p@db.internal/x?sslmode=prefer", "sslmode=prefer"},
		{"localhost, disabled", "postgres://u:p@localhost:5432/x?sslmode=disable", ""},
		{"loopback, disabled", "postgres://u:p@127.0.0.1/x?sslmode=disable", ""},
		{"ipv6 loopback", "postgres://u:p@[::1]:5432/x?sslmode=disable", ""},
		{"unix socket", "postgres:///x?host=/var/run/postgresql&sslmode=disable", ""},
		{"not a URL", "host=db user=u", ""},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := insecureDBTransport(tc.url)

			if tc.want == "" && got != "" {
				t.Fatalf("unexpected warning %q", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("warning = %q, want it to mention %q", got, tc.want)
			}
			if strings.Contains(got, "p@") || strings.Contains(got, ":p") {
				t.Fatalf("the warning must not echo the password: %q", got)
			}
		})
	}
}
