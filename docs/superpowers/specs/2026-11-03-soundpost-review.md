# Soundpost design review and verification record

Date: 2026-11-03. This record concerns design artifacts only. The product is not implemented. No server/SDK/native profiler/browser/runtime/conformance/benchmark/failure test was run, and no production change or public publication was performed.

## Authorization and latest scope

The owner selected initialization and design first; full architecture approval and execution-method choice are outstanding. The owner directly clarified own contracts throughout and explicitly retained PromQL/LogQL **language semantics**, not upstream backend HTTP/API compatibility. Active requirements/design/plans use that distinction; unchanged original comparisons are isolated in the historical research archive.

## Independent reviews actually performed

A fresh builder review of requirements/design/contracts raised ten material questions. A targeted recovery recheck of the revised design raised three more invariant gaps. A separate security review identified two material authorization/restore gaps. Both targeted reviewers subsequently inspected their fixes and reported their exact findings resolved **at design/contract level**. This is not proof of an implementation or a guarantee no other flaw exists.

| Finding family | Adopted design/contract resolution | Planned behavioral proof |
|---|---|---|
| Control ReadIndex cannot linearize unrelated shard writes | C12 durable closing/barrier/completion saga;202 fencing is not success; old-epoch order explicitly defined |01 T2/T8 concurrent old-grant/admission/derived-effect races |
| Old backup can predate completed deletion | Independent durable monotonic deletion authority checkpoint before completion; restore current ledger or fail closed |01 T9,07 T2/T7 |
| Snapshot manifest may omit authoritative/replay bytes | Full bytes or verified pinned transfers; C/H/D cuts with post-H evidence pin/replay-or-gap certificates |01 T7,09 T1 |
| Post-control-cut admissions lose global quota charges on restore | Data cut includes reservation-consumption/live-charge/release proofs; exact reconstruction and readiness certificate |01 T7/T9 |
| Global quota reservations refunded on ambiguous append | Durable charged reservation; cancel fence plus owner-group no-commit proof before release |01 T2 |
| Undefined deletion selector/new-write behavior | Explicit retirement/historical-range/entity modes, hold state, persistent late-write predicate |01 T8 |
| Pipeline lag silently drops unprocessed lifecycle evidence | Declared safe90-day journal, durable gap/unknown before expiry; retain/backpressure if gap cannot commit |01 T8,06 T2/T4 |
| Cross-project/producer series identity ambiguous | Project-local language evaluation; canonical project/name/labels owner slot; equal-time conflicts at ordered apply |01 T2/T4,02 T3/T8/T9 |
| Native log has no defined LogQL input line | Immutable safe template-revision render; stream labels and structured metadata separate |01 T2,02 T5/T9,03 T1 |
| Float wire fields lose integer histogram precision | Tagged IntegerHistogram/FloatHistogram; decimal64 counts/deltas, no premature float conversion |01 T2/T4,02 T4/T8,03 T1/T3 |
| Mixed signal retention and historical retry ambiguity | Per-signal deadlines/minimum receipt; authenticated receipt lookup distinct from new admission; revoked/retired denied |01 T3,03 T3,04 T7 |
| Shared cache lacks named-source visibility identity | C02 principal/effective-entitlement VisibilityFingerprint on caches/cursors/live/export |01 T5,02 T9/T10,05 T2 |
| Restore can reactivate revoked accounts/grants/tokens | Fresh bootstrap-only auth generation; all recovered auth/grants/OIDC inactive until audited reconciliation |01 T9,05 T1,06 T9,07 T7 |

## Plan integration self-review

- Assigned one owner for auth/session, actual artifact/symbolication/replay backend, native profile reads, C11 investigation, shared rule evaluator/internal output outbox and external notifications.
- Removed duplicate rule/conformance implementation ownership. Deployment orchestrates the query plan's existing semantic harness instead of establishing a second comparator or inventory.
- Added real committed subscriptions rather than live polling; explicit per-session native Correlator prevents global cross-target state.
- Added plan09 for actual server artifact/source-map/replay modules; SDK/UI integration cannot pass against assumed or canned backend behavior.
- Folded initial Go/TS/app configuration into first functional tasks, rather than standalone scaffold acceptance. Shared TS dependency workspace has one lock convention; Node and Bun qualification remain separate.
- Shared plan index maps every R01–R24 requirement to concrete subsystem tasks and cumulative real-smoke/release gates.

## Local environment observations

- Git2.52.0.windows.1 initialized a new local repository; no remote was configured.
- GitHub CLI authentication is available. The checked personal `soundpost` repository name did not resolve; this is not a registry/legal availability claim. No remote repository was created or pushed.
- Node24.16.0 and Python3.14.2 are available locally. `go version` reported command not found; no compiler/dependencies were installed during this design task.
- Apache-2.0 text was obtained from the Apache Foundation. Repository-local author name is Aryn Yklas; global Git identity was not changed.

## Approval boundary

Owner review must accept/revise the proposed architecture/contracts, runtime/browser/native limitations, numerical resource/SDK budgets, policy defaults, retention/restore/deletion semantics and cumulative acceptance gates. After approval choose Subagent-driven or Native execution. Customer rollout and disruptive production drills remain separately authorized. Saving local design history does not approve architecture or authorize publication.

## Artifact checks executed

- A throwaway local document-graph check read18 Markdown files, resolved49 relative links with zero broken targets, found closed code fences, and verified every R01–R24 ID in the requirement-to-plan coverage table.
- The same check found9 subsystem plans and78 numbered behavioral tasks with draft/constraint/review/checklist sections. These counts establish artifact completeness, not implementation correctness.
- Byte comparison confirmed the archived four-report source pack is identical to the received portable source. Archive SHA-256: `5c22fcd0064b32f1f19da2f39949e89c8d99e68aef86d86b9a76f763da9a254e`.
- Root Apache license SHA-256: `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
- Public-material search found no source customer repository/host naming, internal domains, private addresses, private ADR IDs or private current-ref hashes.
- Source-file inventory found no Go/Python/TypeScript/TSX source, package.json or go.mod. This confirms the design-only implementation gate remains intact; it is not a build pass.

No product test command printed anywhere in the plans has been run or claimed passing.
