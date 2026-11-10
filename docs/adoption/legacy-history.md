<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Legacy history obligations

`HistoryStatus` (`tools/adoption/history.go`) tracks the duties around a customer's retained legacy history and says whether they **block closing the adoption**. Legacy history is never silently imported, never silently deleted: it stays in its original system, read-only, with a visible boundary in the product, until the history's owner completes the obligations through a separately authorized and audited action.

**This tool never performs that action and never implies it.** It has no code path that deletes, removes, exports, imports, renames or truncates anything (a test parses the source and fails on filesystem-mutating, process or network imports and calls). There is no importer, mandatory or optional. A blocked or clear status never authorizes deletion or export. "Clear" means only that history does not block closure; obligations may still be open, and open obligations keep retention in force.

## Trust boundaries and what is synthetic

- The input (`HistoryObligations`) and the full `HistoryReport` are **private operator material**. They belong in the operator-controlled private directory used by the other adoption subcommands (outside every checkout, restrictive permissions; on Windows add `--private-directory-acl-confirmed` only after verifying the NTFS ACL). Actual retained history and any export stay in the owning environment's private storage; the tool reads digests of records, never history content.
- The clock is the caller's. `HistoryObligations.Now` is not part of the JSON file (a file that tries to supply `now` is refused as an unknown field); the CLI uses the process UTC clock and the library takes whatever the caller sets. Evidence age is bounded by `max_evidence_age_seconds` (1 second to 30 days). Future-dated and stale observations are blockers, never "corrected".
- Reader identities appear **only as keyed hashes**: `HistoryReaderKey(key, identity)` is domain-separated HMAC-SHA-256 in lowercase hex. The key (at least 32 bytes) and raw identities never leave the operator. A grant whose `reader_key` is not 64 lowercase hex characters (for example a raw address) is a blocker.
- Digests (`*_digest`) are SHA-256 hex of records that stay private (origin proof, authorization, audit entry, boundary metadata, retention/export records). The tool checks the format only; it does not fetch or verify the underlying record.
- Everything in this repository's tests is **synthetic**: generated keys, labels, digests and times, in-process evaluation, local temporary directories. No customer system, hostname, path, credential or inventory is read, contacted, discovered or assumed, and no result is customer acceptance. The public projection always carries `customer_acceptance: false`.

## Input

| Field | Meaning |
| --- | --- |
| `observed_at`, `max_evidence_age_seconds` | When the snapshot was taken and how old it may be at the caller's clock. |
| `origin` | `read_only` (no principal can change the legacy system), `retained` (the history still exists), `evidence_digest`. |
| `access[]` | One authorization to reach legacy history: `reader_key` (keyed hash), `mode` (`read` or `write`), `not_before`, `expires_at`, optional `revoked_at`, `authorization_digest`. |
| `boundary` | Product-side deep-link metadata: `cutover_at`, `visible` (the product shows where history before the cutover lives), `links` (count, at least 1), `links_read_only`, `links_require_authorization`, `metadata_digest`. |
| `obligations[]` | `kind` = `retention`, `hold` or `export`; `due_at`; `record_digest`; `reminder_lead_days` (1-365); and, only once an authorized audited action completed it elsewhere: `completed`, `completed_at`, `authorization_digest`, `audit_digest`. |
| `completion_steps[]` | The steps the closure plan lists. Only `retain`, `remind` and `verify_read_only` are accepted. |

Retention and export are required exactly once each; holds are optional and may repeat.

## Blockers (closed vocabulary)

| Code | Meaning |
| --- | --- |
| `evidence_stale`, `evidence_future_dated` | Snapshot missing, older than the bound, or dated after the caller's clock. |
| `legacy_not_read_only` | Origin not read-only or no origin evidence. |
| `legacy_write_access` | Any write grant that is not provably over (expired or revoked at or before now). A grant that has not started yet, is revoked in the future, has no usable window, or has an unknown mode counts as write access. |
| `access_invalid`, `access_unauthorized`, `reader_identity_not_keyed` | Grant without a valid window or mode, without an authorization digest, or whose reader is not a keyed hash. |
| `retention_obligation_missing`, `export_obligation_missing`, `export_record_missing`, `obligation_record_missing` | A required obligation or its record is absent. A missing export record always blocks, also on a completion claim. |
| `retention_overdue`, `export_overdue`, `hold_overdue` | Due date reached (due time equal to now is overdue) while not completed. |
| `reminder_missing` | An open obligation without a reminder lead (1-365 days). The report lists reminders that are due now. |
| `completion_unaudited`, `completion_invalid` | A completion claim without both authorization and audit digests, or with a missing or future completion time. |
| `obligation_invalid`, `obligation_duplicate` | Unknown kind or no due date; second retention or export obligation. |
| `history_removed_before_obligations` | `retained` is false while any obligation is open or none is recorded. Retention continues until every obligation is complete. |
| `boundary_missing`, `boundary_not_visible`, `boundary_links_not_read_only`, `boundary_links_not_authorized` | No usable boundary metadata (absent, no links, no digest, cutover missing or in the future), boundary not shown, links writable, or links not authorization-gated. |
| `implicit_removal_step`, `mandatory_import_step`, `unsupported_step` | A completion step that deletes/removes/purges (or similar), imports/migrates (or similar), or anything outside the three accepted steps. |

## Output

`HistoryReport` (private): clear flag, sorted blockers, per-obligation state (`open`, `overdue`, `completed`, `invalid`), days remaining and reminder-due flags, open/overdue/completed counts, active read and write grant counts, boundary visibility and a SHA-256 digest of the report.

`HistoryPublicSummary` (public, closed shape): integers, booleans, members of the blocker enum, and `customer_acceptance: false`. It has no identifier, reader key, digest, path, label or time.

## Command

```
go run ./tools/adoption closure --mode history --ledger <private-history.json> \
  --private-output <external-private-directory> --public-summary <new-summary-file> [--private-directory-acl-confirmed]
```

Writes `history.json` (private, exclusive creation) and the public summary; a blocked status is written and then returns a non-zero error. The subcommand is `runClosure`; see [closure.md](closure.md) for the whole flag set.

## Not done by this tool

The separately authorized, audited export or deletion of legacy history; collecting real retention/export records; proving that a customer's legacy system is actually read-only; running the real read-only deep-link service. These are owner actions outside this repository and, for any real customer, need that owner's authorization.
