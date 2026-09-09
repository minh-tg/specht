---
rfc: 0000 # Assigned sequentially upon merge
title: "[Short, Descriptive Title]"
author: "[Your Name or GitHub Handle]"
status: Draft # [Draft | Under Review | Final Comment Period | Accepted | Implemented | Superseded | Rejected]
created: YYYY-MM-DD
updated: YYYY-MM-DD
pr: null
tracking_issue: null
applies_to: [] # e.g. [internal/scanner, internal/gate, internal/server, frontend]
superseded_by: null
---

# RFC 0000: [Title]

## 1. Summary
A concise (1–2 paragraph) executive summary of the proposed change, its scope, and why it is being introduced.

## 2. Motivation & Problem Statement
- **Problem**: What specific limitation, defect, or architectural bottleneck does this solve?
- **User / Developer Impact**: Who experiences this pain today (e.g., security engineers, CI/CD pipelines, frontend users, scanner authors)?
- **Goals**: What will be true once this RFC is implemented?
- **Non-Goals**: What is explicitly out of scope for this change?

## 3. Detailed Design

### 3.1 Architecture & Flow
Detailed explanation of the solution. Include diagrams, component relationships, or state flow where helpful.

### 3.2 Data Model & Schema Changes
- Changes to database tables, indexes, or enums.
- Migration strategy (`golang-migrate` files, index concurrency, locks).
- Backfill plan for existing rows, if applicable.

### 3.3 Public & Internal API Contracts
- Changes to REST endpoints (`/api/v1/...`), request/response JSON payloads, or HTTP status codes.
- Changes to internal Go interfaces (e.g., `Scanner`, `Usecase`, `Repository`).

### 3.4 Scanner & Ecosystem Impact
How does this proposal interact with supported scanners (Trivy, Semgrep, Checkov, OSV-Scanner, Gitleaks, Grype, Nuclei) and future scanner adapters?

### 3.5 Gate Policy & Evaluation Impact
Does this change alter how deployment gates evaluate blocking findings, waivers, reachability, or threshold breaches?

## 4. Drawbacks & Trade-offs
- What are the costs, risks, or complexities introduced by this change?
- Does it increase ingestion latency, database storage, memory consumption, or code maintenance overhead?

## 5. Alternatives Considered
- What alternative architectures, libraries, or design patterns were evaluated?
- Why were they rejected in favor of this proposal?
- What is the cost of doing nothing (the status quo)?

## 6. Adoption & Migration Strategy
- Is this a breaking change for existing clients, scanners, or database states?
- How will the rollout be staged across backend, database migrations, and frontend?

## 7. Unresolved Questions
- What technical details, edge cases, or design decisions are open for discussion during review?
