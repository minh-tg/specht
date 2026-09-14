// Package policy resolves organization-wide policy baselines (SOLO-185)
// with project-level overrides: template <- override <- built-in default,
// with per-key provenance so developers can see which policy caused a
// gate. Waivers remain the exception mechanism (owner, reason, expiry).
package policy
