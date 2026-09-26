package db

import "testing"

func TestInsecureRemoteURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "remote disabled", url: "postgres://user:pass@db.example.test/specht?sslmode=disable", want: true},
		{name: "localhost disabled", url: "postgres://user:pass@localhost/specht?sslmode=disable", want: false},
		{name: "loopback disabled", url: "postgres://user:pass@127.0.0.1/specht?sslmode=disable", want: false},
		{name: "remote required", url: "postgres://user:pass@db.example.test/specht?sslmode=require", want: false},
		{name: "remote default", url: "postgres://user:pass@db.example.test/specht", want: false},
		{name: "unix socket", url: "postgres:///specht?sslmode=disable", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := insecureRemoteURL(tt.url); got != tt.want {
				t.Fatalf("insecureRemoteURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
