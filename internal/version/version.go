// Package version carries the build-time version of the Specht server. The
// values are injected at build time via -ldflags (see Makefile / release
// workflow); the defaults keep local `go run` builds unambiguous.
package version

// Version is the semantic version of this build. Overridden at release time
// with -ldflags "-X github.com/xMinhx/specht/internal/version.Version=vX.Y.Z".
var Version = "dev"

// Commit is the short git SHA this build was produced from. Overridden at
// build time with -ldflags "-X .../version.Commit=<sha>".
var Commit = "unknown"
