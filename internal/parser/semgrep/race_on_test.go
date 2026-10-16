//go:build race

package semgrep_test

// The race detector slows CPU-bound parsing by about ten times, so time bounds
// scale with it.
const timeBoundFactor = 10
