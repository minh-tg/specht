---
rfc: 0002
title: Staged Bulk Ingest Pipeline & Change-Scoped CI Gating
author: minh-tg
status: Accepted
created: 2026-09-17
updated: 2026-09-17
applies_to:
  - internal/usecase
  - internal/gate
  - internal/repo
  - internal/db
  - cmd/adapter
  - sqlc
superseded_by: null
---

# RFC 0002: Staged Bulk Ingest Pipeline & Change-Scoped CI Gating

## 1. Summary

This RFC establishes two foundational architectural evolutions for Specht:
1. **A 4-phase staged bulk ingestion pipeline** utilizing PostgreSQL 17 `UNNEST(arrays)` with deterministic row-level sorting, reducing database round-trips from $O(N)$ (~4,500 queries per 500 findings) to $O(1)$ (exactly 4 queries per report).
2. **Materialized change-scoped gating & differential attribution**, replacing the fragile global scalar `findings.introduced_by_report_id` with an explicit per-report relation `report_introduced_findings`. This guarantees that CI/CD deployment gates evaluate strictly against the set difference between the pull-request head and the target baseline ($\text{Findings}(HEAD) \setminus \text{ActiveBaseline}(base\_ref)$), eliminating alert fatigue from legacy debt and preventing multi-PR and regression bypasses.

---

## 2. Motivation & Problem Statement

### 2.1 The Ingest N+1 Bottleneck
In Specht's existing implementation ([`internal/usecase/ingest.go`](../internal/usecase/ingest.go)), every finding in a scanner report is processed through an iterative row-by-row loop:
1. `GetByFingerprint` (1 query)
2. `Upsert` (1 query)
3. `SetFindingIntroducedBy` (1 query)
4. `HasOccurrence` (1 query)
5. `CreateOccurrence` (1 query)
6. `UpsertDimension` (1 query per dimension; typically 3–5 queries)

For a report containing 1,000 findings and 4 dimensions per finding, this triggers **~9,000 sequential database round-trips**. Ingestion latency scales linearly to 15–45 seconds, starving the database connection pool during concurrent CI runs.

### 2.2 The Multi-PR & Regression Gating Flaw
Previously, introduced-by attribution was stored as a global scalar column on the finding row: `findings.introduced_by_report_id`. This created severe correctness defects:
- **Multi-PR Race Condition**: If PR #1 and PR #2 both introduce the same dependency vulnerability, the first PR to ingest claims `introduced_by_report_id`. When PR #2 runs, `f.IntroducedByReportID == PR_2.ReportID` evaluates to `false`. PR #2's gate passes, allowing an introduced vulnerability into production.
- **Regression Bypass**: When a finding previously marked `fixed` is reintroduced in a commit, Specht marks `state = 'reopened'`, but leaves `introduced_by_report_id` pointing to the historical report from months ago. The introduced-only gate ignores it, treating a backslide as legacy debt.
- **Retention Pruning Loss**: When reports are purged after 30 days, `ON DELETE SET NULL` wipes `findings.introduced_by_report_id`, permanently destroying historical audit reproducibility.
- **Multi-Commit PR Flaw**: In a 2-commit PR, if Commit 1 introduces a vulnerability and Commit 2 fixes a typo, Commit 2's scan generates a report where the vulnerability is not "new" relative to Commit 1. Evaluating single-commit equality fails to block the PR.

### 2.3 Goals
- **Sub-250ms Ingest**: Complete ingestion of 10,000 findings in under 250ms.
- **Zero Deadlocks**: Guarantee safe concurrent ingestion across parallel CI matrix jobs (e.g. Trivy and Semgrep running on the same commit).
- **Accurate Change-Scoped Gating**: Gate strictly on $\text{Findings}(HEAD) \setminus \text{ActiveBaseline}(base\_ref)$, including regressions.
- **Clean Architecture & Reproducibility**: Retain all business and policy logic in Go; ensure historical gate evaluations are immutable.

### 2.4 Non-Goals
- Real-time streaming or message-broker ingestion (Kafka/RabbitMQ).
- Changing scanner output normalization or RFC 0001 fingerprint formats.

---

## 3. Detailed Design

### 3.1 The 4-Phase Staged Bulk Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Ingest Pipeline (4 Phases)                      │
├───────────────────┬───────────────────┬────────────────┬───────────────┤
│ 1. Pre-fetch      │ 2. Classify (Go)  │ 3. Bulk Write  │ 4. Scoped Gate│
│ - Known Fingerp.  │ - Identify New    │ - Bulk Upsert  │ - Read        │
│ - Baseline Occurs │ - Detect Regress. │ - Bulk Occurs  │   introduced  │
│   (2 SQL queries) │ - Material Change │ - Bulk Dims    │   findings    │
│                   │   (0 SQL queries) │ (3 SQL queries)│ (1 SQL query) │
└───────────────────┴───────────────────┴────────────────┴───────────────┘
```

#### Phase 1: Pre-fetch (2 SQL Queries)
Before touching write locks, load existing project state in constant time:
1. `ListFindingsByFingerprints`: Selects existing findings matching `project_id`, `finding_kind`, and `ANY($1::text[])`.
2. `ListFindingIDsPresentInReport`: If a baseline report exists, selects all finding IDs from `finding_occurrences` for that baseline report matching `ANY($1::uuid[])`.

#### Phase 2: In-Memory Classification & Canonical Sort (Go)
1. **Deduplication**: Deduplicate incoming findings by `(finding_kind, fingerprint)` to prevent PostgreSQL `21000` (`ON CONFLICT DO UPDATE cannot affect row a second time`).
2. **Canonical Sort**: Sort the finding slice by `(finding_kind, fingerprint)` ascending. This ensures every transaction acquires row locks in identical lexicographical order, completely preventing PostgreSQL `40P01` deadlocks.
3. **Classification**:
   - `New`: Fingerprint absent in database $\rightarrow$ Introduced.
   - `Regression`: Existing finding whose current database state is `fixed` $\rightarrow$ Introduced (Regression).
   - `Baseline Diff`: Existing finding absent from the baseline report occurrences $\rightarrow$ Introduced.
   - `Pre-Existing`: Present in baseline $\rightarrow$ Excluded from introduced set.

#### Phase 3: Atomic Bulk Persistence (Single DB Transaction)
All writes execute within a single database transaction (`tx, err := pool.Begin(ctx)`):
1. **Length Validation**: Go validates `len(kinds) == len(fingerprints) == ...` before dispatch, preventing PostgreSQL `UNNEST` silent NULL-padding.
2. **Bulk Upsert Findings (`sqlc`)**:
   ```sql
   WITH input_rows AS (
       SELECT
           $1::uuid AS project_id,
           u.finding_kind, u.fingerprint, u.title,
           u.severity, u.severity_rank, u.score,
           $2::timestamptz AS observed_at
       FROM unnest(
           $3::text[], $4::text[], $5::text[],
           $6::text[], $7::smallint[], $8::numeric[]
       ) AS u(finding_kind, fingerprint, title, severity, severity_rank, score)
       ORDER BY u.finding_kind, u.fingerprint
   )
   INSERT INTO findings (
       project_id, finding_kind, fingerprint,
       current_title, current_severity, current_severity_rank,
       current_score, state, triage_status,
       first_seen_at, last_seen_at
   )
   SELECT
       ir.project_id, ir.finding_kind, ir.fingerprint,
       ir.title, ir.severity, ir.severity_rank,
       ir.score, 'open', 'untriaged',
       ir.observed_at, ir.observed_at
   FROM input_rows ir
   ON CONFLICT (project_id, finding_kind, fingerprint) DO UPDATE SET
       current_title = EXCLUDED.current_title,
       current_severity = EXCLUDED.current_severity,
       current_severity_rank = EXCLUDED.current_severity_rank,
       current_score = EXCLUDED.current_score,
       last_seen_at = GREATEST(findings.last_seen_at, EXCLUDED.last_seen_at),
       state = CASE WHEN findings.state = 'fixed' THEN 'reopened' ELSE findings.state END,
       updated_at = NOW()
   RETURNING id, fingerprint;
   ```
3. **Bulk Insert Occurrences**: Inserts occurrences via `UNNEST` referencing the returned finding IDs.
4. **Bulk Upsert Dimensions**: Inserts deduplicated dimensions via `UNNEST`.
5. **Materialize Introduced Set**: Bulk inserts the classified introduced findings into `report_introduced_findings`.
6. **Report Completion**: Update `reports SET status = 'completed', total_findings = $1 WHERE id = $2` inside the transaction.
7. **Commit & Outbox Dispatch**: Commit transaction. External side effects (`Tracker.Dispatch`) are triggered strictly post-commit.

---

### 3.2 Change-Scoped Gating & Attribution

#### The Relation Schema
```sql
CREATE TABLE report_introduced_findings (
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    baseline_report_id UUID REFERENCES reports(id) ON DELETE SET NULL,
    change_type TEXT NOT NULL, -- 'new' | 'regression'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (report_id, finding_id)
);

CREATE INDEX idx_report_introduced_findings_report_id
ON report_introduced_findings (report_id);
```

#### Invariants
1. **Change Delta Invariant**:
   $$F \in \text{Introduced}(R) \iff F \in \text{Findings}(R) \land F \notin \text{ActiveBaseline}(R_{\text{base}})$$
2. **Regression Equivalence Invariant**: If a finding is present in $R$ and its state on the base branch is `fixed`, it is marked `change_type = 'regression'` and participates in gate blocking.
3. **Retention Immunity**: Because `report_introduced_findings` cascades on report deletion, prunes never leave corrupted or half-null rows.
4. **Temporal Waiver Invariant**: Active waivers are evaluated dynamically at evaluation time:
   ```sql
   WHERE enabled = true AND (expires_at IS NULL OR expires_at > NOW())
   ```

---

### 3.3 CLI Ergonomics (`specht-adapter`)

The adapter CLI auto-detects CI environments and supports change-scoped workflows:
```bash
specht-adapter \
  --tool=trivy \
  --file=scan.json \
  --project=my-app \
  --introduced-only \
  --base-ref=main \
  --baseline-policy=warn
```

#### Baseline Fallback Policies
- `warn` (Default for onboarding): If no baseline exists for `main`, ingest findings, print a clear warning banner, and exit `0`.
- `fail` (Strict compliance): If no baseline exists on `main`, fail with exit code `1`.

#### Terminal Output Partitioning
Outputs clearly distinguish between introduced blocking risks and pre-existing project debt:
```text
❌ SPECHT SECURITY GATE: FAILED
Project: my-app | Scanner: trivy | Branch: feat/auth -> main

🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS PR (1)
  [CRITICAL] CVE-2023-45853 in zlib 1.2.11
  Location: go.mod:34 (pkg:golang/github.com/madler/zlib)
  Remediation: Upgrade zlib to >= 1.2.12

ℹ️ PRE-EXISTING DEBT IN BASELINE (14 findings ignored for this PR gate)
  14 vulnerabilities already exist on branch 'main'.
```

---

## 4. Alternatives Considered

1. **Iterative Single-Finding Ingestion (Status Quo)**:
   - Rejected: $O(N)$ sequential queries cause severe latency (15–45s) and DB pool exhaustion.
2. **PostgreSQL Temporary Staging Table (`COPY` + PL/pgSQL)**:
   - Rejected: Leaks business logic (material change detection, policy, event emission) into complex SQL; breaks Clean Architecture; bloats Postgres catalogs `pg_class`/`pg_attribute`.
3. **Asynchronous CQRS / Event-Sourced Ingest**:
   - Rejected: Eventual consistency breaks synchronous CI/CD gating where `specht-adapter` requires an immediate pass/fail exit code.

---

## 5. Migration Strategy

1. **Migration `000034_report_introduced_findings`**:
   - Creates `report_introduced_findings` table and indexes.
   - Updates `sqlc/queries/waivers.sql` to filter `expires_at > NOW()`.
2. **Backward Compatibility**:
   - `findings.introduced_by_report_id` is retained as a legacy informational field, but deprecated from gate evaluation logic.
   - Existing endpoints and tests continue to function.

---

## 6. Implementation Checklist

- [ ] Add migration `migrations/000034_report_introduced_findings.up.sql`
- [ ] Add `BulkUpsertFindings`, `BulkInsertOccurrences`, `BulkUpsertDimensions` to `sqlc/queries/findings.sql`
- [ ] Fix `ListActiveWaivers` in `sqlc/queries/waivers.sql` to enforce `expires_at`
- [ ] Implement 4-phase staged pipeline in `internal/usecase/ingest.go`
- [ ] Refactor `EvaluateIntroducedOnly` in `internal/gate/gate.go` to join `report_introduced_findings`
- [ ] Add `--introduced-only` and CI auto-detection in `cmd/adapter/main.go`
