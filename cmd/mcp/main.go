package main

import (
	"context"
	"log"
	"os"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
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
