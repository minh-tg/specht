// Package patch plans safe, deterministic remediation proposals (SOLO-182)
// as pure data: affected files, rationale, confidence, and source evidence.
// Proposals are preview-only — automation is opt-in at a higher layer and
// can never merge or deploy by itself. Anything outside the explicitly
// supported low-risk classes yields an unsupported outcome, never a
// partial patch. Secret material is never patched, only rotated by hand.
package patch
