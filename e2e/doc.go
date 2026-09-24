// Package e2e hosts the end-to-end test suite. The suite boots a real
// PostgreSQL, the real cmd/server, cmd/adapter, and cmd/specht binaries,
// and drives the public contracts over HTTP and process exit codes — the
// same paths a self-hoster and a CI pipeline use. Test files carry the
// "e2e" build tag: `make e2e` runs them, plain `go test ./...` skips them.
package e2e
