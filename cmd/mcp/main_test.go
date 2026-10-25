package main

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/version"
)

func TestInfoFlagsPrintAndStop(t *testing.T) {
	for _, flag := range []string{"-version", "--version", "-v"} {
		var out bytes.Buffer
		if !handleInfoFlags([]string{flag}, &out) {
			t.Fatalf("%s should be handled", flag)
		}
		if got := strings.TrimSpace(out.String()); got != "specht-mcp "+version.String() {
			t.Fatalf("%s printed %q", flag, got)
		}
	}

	for _, flag := range []string{"-help", "--help", "-h"} {
		var out bytes.Buffer
		if !handleInfoFlags([]string{flag}, &out) {
			t.Fatalf("%s should be handled", flag)
		}
		for _, want := range []string{"API_KEY", "API_URL", "MCP_ALLOW_MUTATIONS", "stdio"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%s output does not mention %s:\n%s", flag, want, out.String())
			}
		}
	}
}

func TestAPIConfigReadsBothNames(t *testing.T) {
	cases := []struct {
		name             string
		env              map[string]string
		wantURL, wantKey string
	}{
		{"aliases only", map[string]string{"SPECHT_API_URL": "https://alias", "SPECHT_API_KEY": "alias-key"}, "https://alias", "alias-key"},
		{"plain names win", map[string]string{"API_URL": "https://plain", "SPECHT_API_URL": "https://alias", "API_KEY": "plain-key", "SPECHT_API_KEY": "alias-key"}, "https://plain", "plain-key"},
		{"url defaults", map[string]string{"API_KEY": "plain-key"}, "http://localhost:8080", "plain-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, key, err := apiConfig(func(name string) string { return tc.env[name] })
			if err != nil {
				t.Fatal(err)
			}
			if url != tc.wantURL || key != tc.wantKey {
				t.Fatalf("got %q %q, want %q %q", url, key, tc.wantURL, tc.wantKey)
			}
		})
	}
	if _, _, err := apiConfig(func(string) string { return "" }); err == nil {
		t.Fatal("expected a missing key error")
	}
}

func TestInfoFlagsLeaveEverythingElseToTheServer(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"serve"}, {"-x"}} {
		var out bytes.Buffer
		if handleInfoFlags(args, &out) {
			t.Fatalf("%v should start the server", args)
		}
		if out.Len() != 0 {
			t.Fatalf("%v wrote %q", args, out.String())
		}
	}
}

func TestServerReportsTheReleaseVersion(t *testing.T) {
	session := connectMCPServer(t, &mockClient{})
	if got := session.InitializeResult().ServerInfo.Version; got != version.String() {
		t.Fatalf("server version = %q, want the release version %q", got, version.String())
	}
}

// The setup guide lists every tool, so a tool cannot be added or removed without the guide
// following.
func TestSetupGuideListsEveryToolAndNoOther(t *testing.T) {
	raw, err := os.ReadFile("../../docs/mcp.md")
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|").FindAllStringSubmatch(string(raw), -1) {
		documented[m[1]] = true
	}

	session := connectMCPServer(t, &mockClient{})
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, tool := range result.Tools {
		registered[tool.Name] = true
	}

	var missing, stale []string
	for name := range registered {
		if !documented[name] {
			missing = append(missing, name)
		}
	}
	for name := range documented {
		if !registered[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		t.Fatalf("docs/mcp.md is out of date: tools missing from it %v, tools it lists that do not exist %v", missing, stale)
	}
}
