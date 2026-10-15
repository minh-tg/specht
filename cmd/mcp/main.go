package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/minh-tg/specht/internal/client"
	"github.com/minh-tg/specht/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const usage = `specht-mcp serves a Specht server to an AI assistant over the Model Context Protocol (stdio).

It takes no arguments. Configure it with environment variables:

  API_KEY              a project API key or a session token (required)
  API_URL              the Specht server (default http://localhost:8080)
  MCP_ALLOW_MUTATIONS  true to also offer the tools that change state (default false)

Run specht-mcp -version to print its version.
`

// handleInfoFlags answers -version and -help without needing a server or a key, and
// reports whether it did. Anything else starts the server.
func handleInfoFlags(args []string, out io.Writer) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "-version", "--version", "-v":
		_, _ = fmt.Fprintf(out, "specht-mcp %s\n", version.String())
		return true
	case "-help", "--help", "-h":
		_, _ = fmt.Fprint(out, usage)
		return true
	}
	return false
}

func main() {
	if handleInfoFlags(os.Args[1:], os.Stdout) {
		return
	}
	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("API_KEY environment variable is required")
	}

	opts, err := loadToolOptions(apiKey, os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	api := client.New(apiURL, client.WithToken(apiKey))
	server := newMCPServer(api, opts)
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
