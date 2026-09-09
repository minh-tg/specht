---
rfc: 0001
title: Unified Finding Fingerprinting & Identity Specification
author: Specht Core Engineering
status: Implemented
created: 2026-09-09
updated: 2026-09-09
applies_to:
  - internal/domain
  - internal/scanner
  - internal/gate
  - internal/correlate
---

# RFC 0001: Unified Finding Fingerprinting & Identity Specification

## 1. Summary

This RFC establishes a unified, scanner-agnostic specification for vulnerability and finding identity in Specht. It decouples physical finding persistence (storage deduplication and rescan state tracking) from semantic vulnerability matching (waivers, correlation, and external tracking).

## 2. Motivation

Specht ingests reports from diverse scanners across five domains:
- **SCA**: Trivy, Grype, OSV-Scanner, Dependency-Check, CVE Watcher
- **SAST**: Semgrep, generic SARIF producers
- **IaC**: Checkov, tfsec, Trivy misconfig
- **Secrets**: Gitleaks, Trivy secrets
- **DAST**: Nuclei

In the database, findings are uniquely constrained by `(project_id, finding_kind, fingerprint)`. Previously, each scanner computed fingerprints ad-hoc with inconsistent semantics:

1. **SCA Divergence**: Scanners emitted differing primary identifiers for the same vulnerability (e.g., Trivy preferred `CVE-2024-1234` while Grype emitted `GHSA-xxxx-yyyy`). The CVE Watcher hashed `sha256(purl + "|" + primary)` into a 64-character hex string. As a result, the same vulnerability in the same package resulted in multiple divergent finding rows.
2. **SAST Line Fragility**: Semgrep included physical source lines (`sast:rule:file:line`). Any modification earlier in a source file shifted line numbers, triggering false "fix" and "new finding" churn on subsequent scans.
3. **Waiver Matching Conflation**: The waiver policy evaluator matched `cve_id` conditions via exact string equality against `fingerprint`. Because real SCA fingerprints are compound strings (`CVE-2024-1234:pkg:npm/lodash@4.17.20`), waivers targeting CVE IDs failed to match.

## 3. Architecture & Core Principles

Finding identity is partitioned into two distinct layers:

```
+-------------------------------------------------------------------------+
|                              FINDING                                    |
|                                                                         |
|  1. Physical Fingerprint (Persistence Identity)                         |
|     - Deterministic compound string                                     |
|     - Stable across rescans of the same artifact                        |
|     - Scoped by (project_id, finding_kind)                              |
|                                                                         |
|  2. Semantic Dimensions (Policy & Matching Identity)                    |
|     - vulnerability_id, alias[], package_name, purl, rule_id, file...  |
|     - Used by waiver evaluation, correlation, and intelligence feeds    |
+-------------------------------------------------------------------------+
```

1. **Physical Fingerprints are Provider-Agnostic and Human-Readable**:
   Fingerprints use a colon-delimited namespaced URI format:
   `<kind>:<primary-identity>:<target-anchor>[:<disambiguator>]`
2. **Canonical Vulnerability Identifier Resolution**:
   When multiple aliases exist (e.g., GHSA, CVE, OSV, PYSEC), standard CVE identifiers (`CVE-YYYY-NNNNN`) take precedence as the canonical vulnerability key.
3. **Immunity to Volatile Edits**:
   Volatile source-code attributes (such as line numbers) are excluded from primary identity. Disambiguation uses AST / match context hashes when provided by tools (such as SARIF `matchBasedFingerprint/v1`).
4. **Waiver Matching Evaluates Semantic Dimensions**:
   Waivers never require reverse-engineering physical compound strings. Conditions match against structured dimensions (`vulnerability_id`, `alias`, `package_name`, `rule_id`, `resource`) while maintaining backwards-compatible exact fingerprint pinning.

## 4. Specification by Finding Kind

### 4.1 SCA (Software Composition Analysis)

* **Format**: `sca:<canonical_vuln_id>:<normalized_purl>`
* **Canonical Vulnerability ID Algorithm**:
  1. Inspect primary vulnerability ID and all reported aliases.
  2. If any identifier matches `^CVE-\d{4}-\d+$` (case-insensitive), uppercase that CVE ID as the canonical key.
  3. Otherwise, use the scanner's primary identifier (e.g., `GHSA-...`).
* **PURL Normalization**:
  PURL qualifiers (e.g. repository URLs, architecture) and subpaths are stripped. Name and version are lowercased where ecosystem-appropriate.
* **Example**:
  `sca:CVE-2024-21538:pkg:npm/lodash@4.17.20`

### 4.2 SAST (Static Application Security Testing)

* **Format**: `sast:<rule_id>:<relative_path>[:<context_hash>]`
* **Rules**:
  - `relative_path` is normalized relative to repository root (no absolute paths).
  - Line numbers are strictly omitted from primary identity.
  - When the scanner supplies a SARIF `matchBasedFingerprint/v1` or stable AST hash, it is appended as `context_hash` to disambiguate multiple occurrences of the same rule in a single file.
  - If no context hash exists, `sast:<rule_id>:<relative_path>` serves as the file-level finding anchor.
* **Example**:
  `sast:go.sql.sqli:internal/db/users.go:7f9a1b2c`

### 4.3 IaC (Infrastructure as Code)

* **Format**: `iac:<rule_id>:<resource_address>`
* **Rules**:
  - Infrastructure identity is rooted in the declarative resource address (e.g. Terraform `aws_s3_bucket.audit_logs`, Kubernetes `Deployment/production/web`).
  - File moves and module restructuring preserve finding identity as long as the deployed resource identity remains stable.
* **Example**:
  `iac:CKV_AWS_18:aws_s3_bucket.access_logs`

### 4.4 Secrets

* **Format**: `secret:<rule_id>:<relative_path>:<anchor_hash>`
* **Rules**:
  - Plaintext secrets MUST NEVER appear in fingerprints.
  - `anchor_hash` is a truncated non-reversible hash (e.g., SHA256 truncated to 16 hex chars) of the secret's contextual surrounding lines or entropy key.
* **Example**:
  `secret:aws-access-key-id:deploy/.env.prod:b3d1f890`

### 4.5 DAST (Dynamic Application Security Testing)

* **Format**: `dast:<template_id>:<normalized_url>[:<parameter>]`
* **Rules**:
  - URLs are normalized: query parameters, transient session tokens, and URL fragments are stripped from the endpoint path.
  - The vulnerable parameter name is passed as the disambiguator.
* **Example**:
  `dast:cwe-89-sqli:https://api.example.com/v1/auth:username`

## 5. Waiver & Gate Integration

The waiver evaluator (`internal/gate`) decouples from string inspection of physical fingerprints:

1. `cve_id` condition matching:
   - Compares target CVE against finding canonical `vulnerability_id` and all `aliases`.
   - Checks if `f.Fingerprint` contains or begins with the target CVE.
   - Checks if `f.CurrentTitle` contains the target CVE.
2. `package_name` condition matching:
   - Matches the finding's `package_name` dimension or extracted PURL component.
3. `rule_id` condition matching:
   - Matches the finding's `rule_id` dimension (covering SAST, IaC, and Secrets).
4. `fingerprint` condition matching:
   - Retains exact equality matching for pinning waivers to a specific finding row.

## 6. Compatibility & Rollout

- **Contract Version**: Retained at version 1. Existing finding rows continue to be read without database migration.
- **Rollout**: New parser versions adopt canonical vulnerability resolution and line-shift immunity on subsequent ingestion.
