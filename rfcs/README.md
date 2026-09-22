# Specht RFCs (Request for Comments)

The Specht RFC process provides a structured, collaborative path for substantial architectural changes, cross-cutting feature additions, and breaking design modifications to the platform.

---

## When to Write an RFC

### Requires an RFC
- **New Scanner Kinds or Paradigms**: Introducing new finding kinds (e.g., runtime security, cloud posture) or fundamental changes to the `Scanner` adapter contract.
- **Vulnerability & Fingerprint Identity**: Modifications to fingerprint algorithms, finding deduplication rules, or canonical CVE resolution.
- **Database Schema & Data Models**: Non-trivial table restructuring, partition strategies, or modifications to historical finding storage.
- **Gate Evaluation & Policy Engine**: Structural modifications to how deployment gates evaluate waivers, reachability, or threshold breaches.
- **Public API Breaking Changes**: Changes to `/api/v1/` endpoint contracts or authentication models.

### Does NOT Require an RFC
- Bug fixes, regression fixes, and performance optimizations.
- Minor parser enhancements (e.g., adding an alias field or extracting additional metadata from an existing scanner report).
- UI component styling, layout tweaks, or dashboard ergonomics.
- Internal code refactoring that preserves existing interfaces and behavior.
- Documentation and unit test improvements.

---

## Lifecycle States

```
[ Idea / Discussion ] ──> [ PR (Under Review) ] ──> [ Final Comment Period (FCP) ] ──> [ Merged (Accepted) ] ──> [ Implemented ]
                                                              │
                                                              └──> [ Closed (Rejected) ]
```

| State | Description |
|-------|-------------|
| **Draft** | Work in progress, not yet ready for formal review. |
| **Under Review** | Proposed via an open GitHub Pull Request with active community review. |
| **Final Comment Period (FCP)** | Consensus reached; a 7-day window is opened for final objections. |
| **Accepted** | Merged into the `master` branch. The design is approved for implementation. |
| **Implemented** | All implementation PRs are merged and shipped in Specht. |
| **Superseded** | Replaced by a newer RFC (referenced in `superseded_by`). |
| **Rejected** | Not accepted; preserved or documented with rationale for future reference. |

---

## How to Submit an RFC

1. **Pre-RFC Alignment**: Open a GitHub Discussion or Issue to gauge interest and gather initial feedback on the problem.
2. **Copy the Template**:
   ```bash
   cp rfcs/0000-template.md rfcs/0000-my-feature.md
   ```
3. **Author the Proposal**: Fill in all sections of the template. Address cross-scanner impact, gate evaluation effects, and database migration feasibility.
4. **Open a Pull Request**: Title the PR `rfc: [Short Title]` and label it with `rfc` and `rfc:under-review`.
5. **Iterate**: Address feedback via line-by-line GitHub review comments.
6. **Final Comment Period (FCP)**: Once consensus is reached, maintainers announce a 7-day FCP.
7. **Merge & Numbering**: Upon acceptance, the file is assigned the next sequential number (e.g. `rfcs/0002-my-feature.md`), its status is updated to `Accepted`, and it is merged into `master`.
8. **Implementation Tracking**: A tracking issue is opened referencing the RFC to coordinate implementation PRs.

---

## RFC Index

| RFC | Title | Author | Status | Created |
|-----|-------|--------|--------|---------|
| [0001](0001-unified-fingerprinting.md) | Unified Finding Fingerprinting & Identity Specification | minh-tg | Implemented | 2026-09-09 |
| [0002](0002-staged-bulk-ingest-and-change-gating.md) | Staged Bulk Ingest Pipeline & Change-Scoped CI Gating | minh-tg | Accepted | 2026-09-17 |
