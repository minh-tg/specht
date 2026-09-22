// Package provider defines the repository-provider seam between Specht's
// core and code-hosting platforms: the Provider interface a
// platform adapter implements, the deterministic registry that maps
// provider names to implementations, and the provider-neutral
// pull-request check and annotation model.
//
// The seam is pure planning: adapters transform findings into check plans
// (conclusion, summary, inline annotations) with no network I/O, no
// credentials, and no webhook handling. Publishing a plan to a live
// platform (app OAuth, webhook verification, PR event ingestion) is
// explicitly out of scope — previews render the exact payload that would
// be published, so reruns stay reproducible and reviewable.
package provider
