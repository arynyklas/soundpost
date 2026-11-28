# Soundpost Rust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** APPROVED by the owner on 2026-11-29 (decision D109), AMENDED the same day by owner decision D110: the Go build is a difference detector, not an oracle; a batch's payload lives in its group's Raft WAL; erasure works by file generations. Execution method: subagent-driven. Model routing set by the owner: `m3` (Sonnet 5.5, high) for scouting and bug review; `m5` (Opus 5.5, high) for backend work, hard bugs and duplicate review; `m6` (GPT-6.2 Astra, high) only for the hardest tasks, sparingly; `m5` for design and UI; `m1` (GPT-6.2 Sol) and `m2` (inkling-2-mini) for review of ideas, architecture and plans. Phase 0 and Phase 1 are detailed. Each later phase plan is a draft until its predecessor passes its exit gate.

**Goal:** Replace every line of Go in this repository with Rust and ship the product the spec describes: its documented external contracts, every promised language semantic and every durable-ACK guarantee, each proven from the spec rather than from the Go build.

**Architecture:** One Cargo workspace. The durability- and order-critical parts (group WAL and apply, replication driver, control state machine, rule scheduler, outbox, query admission) are deterministic sans-IO cores: they take events and emit actions, and touch time, randomness, disk and network only through injected seams. Two drivers run the same cores: a production driver (owner threads per core plus a tokio network shell) and `sp-sim`, a seeded single-threaded simulator with a faulty disk, network and clock. Client-visible histories from the simulator are checked for linearizability and durability against models written from the spec. The protocols the Go build got wrong are modelled in TLA+ before their code. Every test cites an obligation ID from `docs/obligations/`. The frozen Go build (`go-reference`) is a difference detector: a difference is a finding to rule on against the spec, never an expected value.

**Tech Stack:** Rust stable, pinned in `rust-toolchain.toml` and installed offline; `x86_64-unknown-linux-musl` static release binaries; tokio, hyper/axum, rustls; raft-rs behind an audited adapter; redb for small typed metadata; serde; vendored crates (`cargo vendor`, `--locked --offline`). Verification tools on lab VMs only: TLA+ tools (TLC) with a Debian Java runtime, `cargo-fuzz`, `cargo-mutants`. The TS/Python SDKs and the React console are unchanged.

**Spec:** [design](../specs/2026-11-03-soundpost-design.md), [contracts](../specs/2026-11-03-soundpost-contracts.md), [requirements](../specs/2026-11-03-soundpost-requirements.md), protocol documents in `docs/protocol/`, decisions D1–D110 (`.superpowers/sdd/approved-product/decisions-2026-11-13.md`). Where the design says "Go", D109 overrides it. Every other obligation stands.

## Owner decisions this plan implements

| Question | Decision |
|---|---|
| The Go implementation (D109, D110) | Frozen on branch `go-reference` (tag `go-reference-2026-11-29`) as a reference and **difference detector**. It is not an oracle. No Go 0.1.0 release. |
| Scope (D109) | All Go code: `internal/`, `cmd/`, `tools/`, `fixtures/` (Go parts), `build/`, `third_party/` Go ports. The SDKs (`packages/`, `sdk/`) and the console (`web/`) stay. |
| Data compatibility (D109) | None. Fresh on-disk and peer format version 1. 0.1.0-preview.1 installs are reinstalled. No import tool and no mixed Go/Rust cluster. |
| Authority (D110) | requirements → design/contracts/protocol docs → decisions → independent oracles (pinned upstream Prometheus/Loki images for language semantics; models written from the spec) → Go reference (differences only). A spec gap is an owner decision and a spec amendment. |
| Payload (D110) | A batch's bytes live in its owning group's Raft WAL (design §7.1), written once per storing voter. No second ACK-time payload log. Big values and per-record index bodies stay out of the metadata B-tree (the D89 lesson). |
| Erasure (D110) | Logical deny at once (C12 barrier); physical removal by a filtered snapshot and a new file generation; superseded files deleted within the 24 h healthy cleanup target; replicated entries never rewritten in place; a canary byte scan of every file after cleanup is a gate. Sector remapping and governed backups before their 30-day expiry are outside the guarantee. |

## Global Constraints

- License: first-party code is Apache-2.0, including SSO, isolation, replay and profiling. Every crate keeps its own notice in `THIRD_PARTY_NOTICES`. No AGPL or GPL code or test corpora; LogQL implementation and tests are authored independently.
- Authority: no test asserts "equals the Go build". A test's expected value comes from the obligation it cites. `sp-diffref` and Go-harness comparisons produce discrepancy records in `docs/obligations/discrepancies.md` (ID, observation, spec text, ruling, regression test); each gets a ruling (Rust matches spec / Go matches spec / spec silent → owner) before the phase gate that owns it. A later explicit owner amendment governs its named scope; contradictory spec prose without an amendment blocks the ruling and goes to the owner.
- External compatibility = the documented contracts: HTTP paths, status codes and the fault envelope (`code`, `retryable`, `detail`, `request_id`) as the contracts and protocol docs define them; the ingestion/artifact/replay protocol v1 bytes (`docs/protocol/*.md`); CLI names and flags of `soundpost`, `soundpost-agent`, `soundpost-perf-acquire`, `soundpost-querycheck`, `soundpost-symbolicate`; the configuration file; the documented behaviour in `docs/`. The unchanged TS/Python SDK suites, the console e2e and the black-box harnesses must pass against the Rust build. Undocumented Go behaviour is adopted only by a ruling, and then documented.
- Full PromQL and LogQL semantics, matched against the locked upstream oracle images (`conformance/query`), with 0 mismatches on the release matrix. RE2, `text/template` and number-formatting behaviour is reproduced as each pinned profile observably exposes it, verified against those images (and, for primitives, a fresh build of the exact upstream Go standard-library release the profile pins) — never against Soundpost's Go code.
- Durability: an ACK only after quorum durable persistence, ordered durable apply, view publication and the protocol's release checks — five distinct milestones, each with its own event and test. Persist comes before send and before ACK. No deferred fsync. A sync error is an unknown persistence outcome: the store latches failed, nothing that depends on it is sent or released, the sync is never retried to certify the old write, and recovery is required. WAL durability frontier: persistence of a batch (entries and hard state) is certified only after its frames are synced **and** a checksummed frontier record naming the last certified frame `{segment, offset, index, term, frame checksum}` and the hard state has been written to one of two alternating slots of the group's frontier file and synced. Each slot is exactly one aligned 4 KiB sector carrying its slot number and a sequence; sector writes are atomic in the fault model, so after a crash a slot holds its old or its new record. On reopen the valid slot with the highest sequence is the proven prefix; a slot that fails its checksum or position check is media corruption, never a torn update, and the store refuses service (no rollback to the other slot); any checksum or position failure of a frame inside the proven prefix is corruption; frames beyond it were never certified and are truncated. Linearizable control reads keep their ReadIndex.
- Fault classification at the public operation boundary uses the typed cause **and** the stage reached: not committed, ambiguous (optionally with a local latch), applied, or applied-and-rejected (an ordered durable rejection such as a conflict). A fault is retryable only when its producer knows it is transient: no leader, a lost quorum on a read fence, an explicitly retryable refusal. Failed-closed engines, fail-stopped groups, closing nodes and untyped errors answer `retryable:false` without `Retry-After`. `Retry-After` is a random 1–3 s unless the route sets its own. Invalid code/retry combinations are unrepresentable in the type, not debug assertions.
- Determinism: cores never perform I/O; they consume events and emit actions. Drivers execute actions (production: owner event loops plus bounded I/O worker pools; simulation: inline in the `sp-sim` executor with fault injection) and feed completions back as events carrying a completion identity `{incarnation, group, generation, seq, op}`; stale or duplicate completions are dropped. No core calls `std::time`, `thread_rng`, `std::fs` or sockets (`xtask lint-seams` enforces it). Every simulator failure prints a one-line repro (seed, build digest, suite).
- Crash evidence has three kinds, named honestly: simulated power loss (`sp-sim`, every operation boundary), process kill (a `CrashPoints` hook blocks the child at a named point and signals the parent, which SIGKILLs it while blocked, then reopens in a fresh process; this proves restart, not power loss), and physical power loss (sysrq/hypervisor drills). No test name claims more than its kind.
- Isolation: no storage, query or workflow interface accepts an org/project ID or a grant without the opaque `sp_auth::Scope` (private fields, no `Deserialize`, constructed only inside `sp-auth`). The minimal `sp-auth` scope seam lands in Phase 1; tests obtain scopes from `sp_auth::testing` behind a `testing` feature, and `xtask deps check` fails if any non-dev dependency edge enables that feature. Deletion and maintenance entry points take a capability issued by `sp-auth`, not a bare predicate.
- Release binaries are static (`x86_64-unknown-linux-musl`) and reproducible from `xtask release`. Evidence is bound to the source digest of the release commit (D60). The agent also builds for Windows (`x86_64-pc-windows-msvc`) where the Go agent did.
- `#![forbid(unsafe_code)]` in every crate except the listed FFI/syscall modules: `sp-durablefs`, `sp-native` perf ring and seccomp, and the `sp-native` Windows collector. Those crates set `unsafe_code = "deny"` and allow it on the listed module only; each unsafe block carries a `// SAFETY:` comment and a test.
- Dependencies: no crate enters `Cargo.lock` without a row in `docs/support/rust-dependencies.md` (name, version, license, purpose, approver). `cargo deny check` gates CI. Lab-only verification tools are recorded in `docs/support/rust-toolchain.md`.
- Owner rules for lab and repo: no builds or tests on the owner's Windows PC; builds and tests run on lab VMs. Commits are by `aryn@sek.su`, SSH-signed. No lab names, IPs or credentials in committed files. LF only. Red first. Flakes are defects. Never weaken a test, budget or gate row.

## Review Focus

Failure classes most likely to bite a user. Each was a real defect in the Go build; each is a mandatory **scenario** with its expected outcome taken from the spec, pinned to an owning task.

1. **Power loss mid-write leaves ACKed records unreadable, or recovery discards a durable frame as a "torn tail".** Pinned in Task 1.4 (WAL recovery rule), Task 1.6 (sim crash at every operation boundary), Task 1.9 (sysrq drill) and the Phase 8 power-cut drill.
2. **Raft ticks starve behind persist/apply, so leaders change spuriously.** Go D103. Phase 2: tick and peer processing never block on fsync, decode, apply or disk-backed reads; tick-lag test with 200 proposers across all 65 groups.
3. **Per-commit cost grows with total state.** Task 1.5 (bytes per ACK), Task 1.6 (cut cost), Phase 2/5 bytes-per-commit tests.
4. **A permanent failure answered as retryable, or a transient one as final.** Go 3178b07 / 11f21e6. Task 1.1 (fault and outcome types) and the Phase 3 per-operation status table.
5. **Reads hold a global lock across decode or authority reads.** Task 1.7: readers get immutable applied views, never a lock guard.
6. **A lost proposal starves a writer under saturating intake.** Phase 2: a control write completes while every voter's intake is saturated and proposals are dropped; reproduced deterministically in `sp-sim`.
7. **Send or ACK before the local fsync.** Task 1.6 (single voter: milestone order, early-ACK schedule, process kill with a reply witness) and Phase 2 (three voters): a crash between persist and send/ACK never yields an ACKed entry absent after restart; no message leaves before its entries are durable.
8. **Erased bytes survive in some file.** Task 1.8: canary proven present in every encoding, then absent from every file, raw and decoded, after cleanup.

## Workspace layout and crate map

The Go tree stays on the rewrite branch until Phase 8 as the difference detector. Rust lives in `crates/` and `xtask/`; protocol models in `models/` (TLA+); obligations in `docs/obligations/`. The Go code is removed in one commit at the Phase 8 cutover; `go-reference` keeps it.

| Crate (path `crates/<name>`) | Replaces Go | Owns |
|---|---|---|
| `sp-sim` (new) | — | deterministic executor, `Clock`/`Rng`/disk/network seams and their simulated implementations with fault models, seed runner, trace format, linearizability/durability history checker |
| `sp-model` | `internal/model`, `link`, `privacl`, `third_party/timezone` | IDs, cursors, faults and operation outcomes, `Ctx`, telemetry DTOs, canonical JSON and hashes, the locked timezone data |
| `sp-durablefs` | `internal/durablefs` | the production disk seam: fsync of file and dir, atomic replace, generation roots |
| `sp-gofmt` | `third_party/format`, `portablemath` | number formatting and parsing as the pinned profiles expose them |
| `sp-goregex` | `third_party/regex` (go123/124/126), `internal/query/regexcompat` | RE2 semantics per pinned profile edition, Unicode tables, literal sets |
| `sp-gotemplate` | `third_party/templateprimitives` | `text/template` behaviour with the LogQL function whitelist |
| `sp-gojson` | `third_party/jsonparser` | byte-level JSON field extraction as the LogQL `json` parser exposes it |
| `sp-storage` | `internal/storage` | group WAL, apply and applied views, segments, windows, indexes, scans, subscriptions, deletion/erasure generations, receipts, blobs, pressure |
| `sp-replica` | `internal/replica` | raft-rs adapter and ready driver, mTLS transport, snapshots/install, membership, leader calls, ReadIndex |
| `sp-control` | `internal/control` | control state machine on per-record ledger tables, admission/settlement, authority, rules ledger, outbox records |
| `sp-auth` | `internal/auth`, `egress`, `config` | `Scope` and capabilities (minimal seam in Phase 1, Task 1.2), sessions, OIDC, tokens, scopes, argon2, egress policy, config file |
| `sp-ingest` | `internal/ingest`, `policy`, `sources`, `adapters` | admission path, normalisation, source fences, input adapters |
| `sp-query` | `internal/query/**`, `third_party/promhistbounds` | syntax, PromQL, LogQL, scan/value, profiles, live, scheduler and admission cores, caches, native histogram bounds |
| `sp-rules` | `internal/rules`, `conditions` | rule scheduler core, recording output, conditions |
| `sp-workflow` | `incidents`, `issues`, `jobs`, `notify`(+providers), `gitlab`, `releases`, `releaseevidence`, `retention`, `backup`, `exports`, `health` | lifecycle and notification workflow, outbox core |
| `sp-artifacts` | `artifacts`, `sourcemap`, `symbolicate`, `replays`, `profiles`, `traces` | artifact bytes, sandboxed symbolication, replay chain, profile reads |
| `sp-native` | `nativeperf`, `host`, `agent` | perf acquisition, ring parsing, seccomp, host collectors (Linux, Windows) |
| `sp-httpapi` | `internal/httpapi`, `uibundle` | every HTTP route, console bundle embedding |
| `sp-app` | `internal/appcore`, `diagstat`, `smokecluster` | wiring, production drivers, workers, diag page |
| `sp-conformance` | `internal/conformance` | query conformance harness and comparators |
| `soundpost`, `soundpost-agent`, `soundpost-perf-acquire`, `soundpost-querycheck`, `soundpost-symbolicate` | `cmd/*` | binaries with the documented CLIs |
| `xtask` | `build/` | `source-digest`, `release`, `gate`, `obligations`, `lint-seams`, notices, SBOM |
| `sp-tools-smoke`, `sp-tools-qualify`, `sp-tools-pcut`, `sp-tools-drills`, `sp-tools-adoption`, `sp-tools-browserevidence`, `sp-fixtures` | `tools/*`, `fixtures/**/*.go` | harnesses, validators, gate runners, overhead and native fixtures |
| `sp-diffref` (new) | — | differential runner: the same request stream against the Go reference and the Rust build, emitting discrepancy records |

## Dependency candidates (approved or replaced in Task 0.4)

| Need | Candidate | License | Note |
|---|---|---|---|
| Raft | `raft` (tikv/raft-rs) with prost codec | Apache-2.0 | sans-IO `Ready` API fits the cores; 0.7.0 draws election timeouts from `rand::thread_rng`, so it is used only through an audited adapter with a deterministic timeout seam (a recorded vendored patch if needed); the Phase 2 plan starts with that audit and may replace the library |
| Embedded B-tree store | `redb` | MIT OR Apache-2.0 | small typed metadata only; its `StorageBackend` trait is the simulation seam (verify on the pinned version) |
| Async runtime / HTTP | `tokio`, `hyper`, `axum`, `tower` | MIT | network shell only |
| TLS | `rustls` + `rustls-pemfile`, crypto provider `ring` or `aws-lc-rs` | Apache/MIT/ISC (check the provider's exact terms at approval) | mTLS peer transport, HTTPS |
| Serialisation | `serde`, `serde_json`, `prost` | MIT OR Apache-2.0 | canonical JSON is owned code in `sp-model` |
| Checksums | `crc32c` | MIT OR Apache-2.0 (verify) | WAL and segment frames |
| YAML config | maintained YAML crate chosen at approval (D111), or an owned parser for the config subset | — | `serde_yaml` is archived; do not use it |
| Password hashing / crypto | `argon2`, `sha2`, `hmac`, `rand` (RustCrypto) | MIT OR Apache-2.0 | parameters from the contracts |
| OIDC | `openidconnect` or owned code on `jsonwebtoken` | MIT | discovery, JWKS, ID-token checks per design §4 |
| SMTP / HTTP client | `lettre`, `hyper-util` client | MIT | providers |
| Syscalls / seccomp | `rustix`, `libc`, `seccompiler` | Apache-2.0 / MIT | perf_event_open, ring mmap, filters |
| CLI | `clap` (derive) | MIT OR Apache-2.0 | flags as documented |
| Tests | `proptest`, `tempfile` | MIT OR Apache-2.0 | dev only |

## Format baseline (fresh version 1)

There are no installed Rust nodes, so version 1 starts from the spec. The upgrade machinery stays for later versions: declared protocol per member, expand/contract, refusing members that cannot read the layout.

- Per-group segmented WAL holding hard state and Raft entries; entries carry the batch payload (D110). Frames are sector-aligned; each frame's checksum covers group identity, file generation, segment number, offset, index, term, kind, length and bytes; a valid frame at another position is rejected. A per-group frontier file with two alternating checksummed slots holds the certified prefix and hard state (Global Constraints).
- Apply indexes each committed batch into the group's open window as an immutable applied view whose rows reference WAL frames by the locator `{group, generation, segment, offset, index, term, record}` (D110 "segments are built at apply": the window is the apply product; sealing it writes segments in a new generation). WAL files are reclaimed only after a verified generation covers them and every file handle on them is closed. Receipts are logical (`cursor`, hash, deadlines), never byte locators.
- Each write domain (one data group; control) has exactly one durable `CURRENT` file naming a checksummed generation root: the generation, cut, deny generation, the digests of its **sealed immutable** files (segments, snapshot), and the identity (incarnation ID, format version, initial state) of its **mutable** files (active WAL segments, frontier file, redb database), which their own protocols verify on reopen. Appends never rewrite the root. A generation is live only when `CURRENT` names it.
- Small typed metadata (applied cut, receipts, manifests, generation roots, control ledger tables) in redb, one database per write domain (control separate from data).
- Control state in per-record ledger tables from the start (D84, D85, D108); no whole-state blob. Scoped preconditions for login and instance scope (D102).
- Erasure by generation replacement (D110); snapshots are filtered at an applied, committed cut.
- `docs/storage/format-v1.md` is rewritten for the Rust format in Phase 1. The Go document stays on `go-reference`.

## Phases and exit gates

Durations are estimates, not measurements. Phase 0 and Phase 1 are detailed below. Each later phase gets its own detailed plan, written when the previous phase passes its exit gate, and reviewed by `m1` and `m2` before execution. The exit gate is the only way into the next phase.

| Phase | Builds | Exit gate | Estimate |
|---|---|---|---|
| 0 | Freeze, workspace, toolchain, vendoring, dependency ledger, obligation ledger, `sp-sim` and history checker, first TLA+ model, `xtask`, CI | `cargo build/test/clippy/deny` green in CI and on a lab VM; `xtask obligations run --phase 0` (every Phase 0 row's cited tests executed and passing); history checker agrees with brute force on the defined tiny-history domain; TLC checks the single-voter write-path model and finds each seeded mutant; `xtask source-digest` matches the documented D60 rule on the D60 fixture tree | 2 weeks |
| 1 | `sp-model`, minimal `sp-auth` scope seam, `sp-durablefs`, `sp-storage` single voter | `xtask obligations run --phase 1` passing; simulator suites at their measured budgets with 0 failures; process-kill tests; erasure canary scan (raw and format-aware); write-set and cut-cost bounds; concurrent scan/append; sysrq power-loss drill | 5–7 weeks |
| 2 | `sp-replica`, `sp-control` | raft-rs adapter audit and deterministic seam; TLA+ 3-voter commit/apply/ACK, snapshot install/rejoin and membership models; sim suites over 3 voters × 65 groups; 3-node qualification with skewed intake: tick lag with 200 proposers, kill -9 rejoin, disk loss after ACK, snapshot install, membership, idempotent leader calls; per-commit bytes independent of state | 5–7 weeks |
| 3 | `sp-auth`, `sp-ingest`, `sp-httpapi`, `sp-app`, `soundpost` serve | per-operation status/fault/action table authored from the contracts; SDK suites and console e2e (Chromium) pass against the Rust server; `sp-diffref` discrepancy ledger fully ruled | 4 weeks |
| 4 | `sp-gofmt`, `sp-goregex`, `sp-gotemplate`, `sp-gojson`, `sp-query`, `sp-rules`, `sp-conformance`, `soundpost-querycheck` | conformance against the pinned upstream images: 8/8 matrix rows, 0 mismatches; differential fuzz of primitives against the images/pinned stdlib; query/rule cores in `sp-sim`; rules 100 evaluations/min under ingest | 6–8 weeks |
| 5 | `sp-workflow`, `sp-artifacts`, `soundpost-symbolicate` | TLA+ models of the quota-reservation saga, the C12 deletion barrier saga and the outbox fenced claim checked; outbox delivers each durable intent with fenced attempts under crash at every step (repeat possible after provider acceptance, design §7.2); sandbox escape tests | 4–6 weeks |
| 6 | `sp-native`, `soundpost-agent`, `soundpost-perf-acquire` | real-kernel 6.1/6.6 runs, privacy canary, seccomp allowlist, mutation battery as for 04.02 | 3–4 weeks |
| 7 | `xtask` release/gate, all `sp-tools-*`, `sp-fixtures` | each Rust harness's verdict derives from the obligations it cites; on the same recorded run, differences from the Go harness are discrepancy records, each ruled | 3–4 weeks |
| 8 | Qualification and cutover | single-host, distributed (1 h, kill -9, FULL read-back), queries (24 h) gates; power-cut and qm-stop drills; erasure cleanup within 24 h with canary scan on every replica; e2e in three browsers including headed; evidence envelopes; release notes; Go code removed | 3–4 weeks plus gate wall time |

Phases 4–6 depend only on Phase 1 (scan API) and Phase 3 (wiring), so they can run as parallel lanes. Phase 2 can run beside Phase 3 once `sp-storage` exposes its append, apply and scan seams. Before its predecessor gate, a lane may design, write models and test against seams; no phase exits on stand-ins where its gate names real replication, control or authority.

**Lab:** the current lab VMs carry remove-by 2026-12-06; the owner chose an extension (platform MR, new remove-by 2027-01-31, pending a human merge). Phases 0–1 run on any Linux VM. A 3-node lab with independent storage is needed from Phase 2, and the full gate lab (3 nodes on distinct hypervisors, query host, generators, a power-cut VM) from Phase 8.

**Go gates never met (context for Phase 8):** the Go build never passed the distributed gate (the 1 h run with kill -9 and FULL read-back was never run; the 20 min serial run at 5k gave a p95 of 449 ms with 2 of 20 minutes ≥ 500 ms, an earlier run 614 ms; the LogQL read-back answered 504 and found 16–18% of logs, unexplained) or the queries gate (24 h never run; rules reached 103 evaluations/min against the 98 required). Phase 8 gates are first-time passes, not regressions against a passing baseline.

---

## Phase 0: freeze, workspace, toolchain and the verification base

Execution order: 0.1, 0.2, 0.3, 0.4, 0.7, 0.8, 0.9, 0.10, 0.5, 0.6. Task numbers are identities, not sequence. Every task that adds a crate adds its `Cargo.toml` and workspace membership first; every task that adds a dependency adds its ledger row, re-runs `cargo vendor`, `cargo deny check` and `cargo xtask deps check`, and commits the updated `Cargo.lock` and `vendor/`. Every obligation row names its owning task; `xtask obligations check` (per commit) covers rows of landed tasks; `xtask obligations run --phase N` (phase gate) executes the cited tests and fails on any failure.

### Task 0.1: Freeze the Go reference (DONE 2026-11-29: `b0db3cb`, tag `go-reference-2026-11-29`, merge `f2660ab`, doc `2840cff`)

**Files:**
- Create: branch `go-reference` from the integration tree; tag `go-reference-2026-11-29`
- Create: `docs/support/go-reference.md`

**Interfaces:**
- Produces: the reference commit SHA, plus the reference binaries `soundpost` (plain and `soundpost_diag`, `soundpost_faults` builds) with their sha256, stored at a lab path named in `docs/support/go-reference.md` (no host names). Under D110 these are a difference detector.

- [x] **Step 1:** Diff `O:\integ` against its frozen copy `O:\integsnap` and list any partial edits left by the stopped IntegFix lane; keep or drop each, with the reason in the commit message. `O:\integ` is `11f21e6` plus the uncommitted admission, BeginFix, CutFix, AdmitFlakes, ctllane (rounds 1–5), qg4 (rounds 4–9) and rules lanes: 260 files (140 new, 120 modified), carrying decisions D104–D108.
- [x] **Step 2:** Copy the integration tree over a branch made from `11f21e6`. Commit it signed, with a message that lists what is unverified: the two open flakes (`TestAPolicyWriteIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake` under -race, 2/11; `TestMixedBinaryPreviousReleaseVoterOnAFreshInstallation` 503 once, then 3/3), the unmeasured distributed and queries gates, the LogQL read-back 504 question, and the protocol-5 declaration after a rolling upgrade from 1.0.0.
- [x] **Step 3:** Archive every stopped lane's reports in the ledger repo under `.superpowers/sdd/approved-product/go-final/<lane>/`, and commit them there signed. Sources (each under `<checkout>\.superpowers\sdd\approved-product\`): `O:\integ` (integ-report.md, integ-changed.txt), `O:\admit` (admit-report.md, admit-merge-report.md, admit-final-report.md, latgrow-report.md), `O:\admfin` (roundclimb-report.md), `O:\admbegin` (beginfix-report.md), `O:\admbegsnap` (turn-review-m4.md), `O:\admcut` (cutfix-report.md), `O:\admsnap` (admit-pcut-report.md, admit-delta-review-m4.md), `O:\admitrev` (admit-review-m4.md), `O:\ctllane` (ctllane-report.md), `O:\rules` (rules-report.md), `O:\rulessnap` (rules-review-m4.md), `O:\qg4` (qg4-report.md), `O:\qg4snap` (qg4-review-m4.md), `O:\qg8snap` (qg8-review-m4.md), `O:\dgate` (DistGate-report.md). The unbuilt paged LogQL verifier in `O:\readback` is copied as `go-final/readback/` source with a note that it was never built or run. No checkout is removed before this commit exists; `O:\vis0509` is the user's and is not touched.
- [x] **Step 4:** Check that the conformance reference did not move: sha256 of `conformance/query/source-lock.json`, `conformance/query/provenance.json` and every `conformance/query/oracles/*.Dockerfile`, and the `sha256:` image digests they pin, on `11f21e6` and on `go-reference`. Expected: identical sets. These upstream image digests are the language-semantics oracle.
- [x] **Step 5:** Build the three reference binaries on a VM with `go run ./build release` (plain) and the diag/faults tags. Record the sha256 and `go run ./build source-digest` in `docs/support/go-reference.md`.
- [x] **Step 6:** Push `go-reference` and the tag through the signed-commit push guard.

### Task 0.2: Cargo workspace and `xtask` crate

**Files:**
- Create: `Cargo.toml` (workspace, `resolver = "3"`, `members = ["xtask", "crates/*"]`, `[workspace.lints]` with `unsafe_code = "forbid"`, `clippy::all = "deny"`; `[profile.dev]` `debug = "line-tables-only"`, `[profile.dev.package."*"]` `opt-level = 1`), `Cargo.lock` (generated, dependency-free), `crates/sp-model/{Cargo.toml,src/lib.rs}`, `xtask/{Cargo.toml,src/main.rs}`, `.cargo/config.toml` (alias `xtask = "run -p xtask --"`)
- Modify: `.gitignore` (add `/target`)

**Interfaces:**
- Produces: the `sp-model` crate skeleton and an empty `xtask` binary; later tasks add modules. Crates allowed `unsafe` (Global Constraints) set `unsafe_code = "deny"` in their own `[lints]` instead of inheriting.
- Toolchain: the implementer installs the stable toolchain from the official standalone archives on the build VM at the version Task 0.3 will pin, and records version and sha256 in its report (Task 0.3 commits the pin).

- [ ] **Step 1:** Land the minimal workspace with `sp-model` and `xtask` but **without** `[workspace.lints]`; write `crates/sp-model/tests/workspace.rs::workspace_lints_forbid_unsafe`, which reads the root `Cargo.toml` with std only and asserts that `[workspace.lints.rust]` sets `unsafe_code = "forbid"`.
- [ ] **Step 2:** On a VM, run `cargo test -p sp-model --locked --offline`. Expected: FAIL naming the missing setting.
- [ ] **Step 3:** Add the lints table and profiles.
- [ ] **Step 4:** Run the same command and `cargo xtask` (prints usage). Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 0.3: Pinned toolchain, offline

**Files:**
- Create: `rust-toolchain.toml` (the exact stable version installed in Task 0.2, components `rustfmt` and `clippy`, targets `x86_64-unknown-linux-musl` and `x86_64-pc-windows-msvc`), `xtask/src/toolchain.rs`, `docs/support/rust-toolchain.md`

**Interfaces:**
- Produces: `cargo xtask toolchain verify`, which checks that `rustc --version` equals the pinned version and that the installed archive's sha256 matches `docs/support/rust-toolchain.md`. The doc also records: a separately pinned nightly used only for the Task 1.9 ThreadSanitizer run; the Debian `mold`/`clang` packages used only as the dev/test linker on `x86_64-unknown-linux-gnu` (never by `xtask release`); and the lab-only verification tools (Java runtime and TLA+ tools jar with sha256, `cargo-fuzz`, `cargo-mutants`, `cargo-deny`) with their install steps.

- [ ] **Step 1:** Test `xtask::toolchain::tests::refuses_a_different_rustc`, with a fake `rustc` script printing a different version. It asserts an error naming both versions.
- [ ] **Step 2:** Run it on a VM. Expected: FAIL (function missing).
- [ ] **Step 3:** Implement `pub fn verify(rustc: &Path, pinned: &str) -> Result<(), String>`. Record the standalone installer archives (Linux gnu host plus the musl and windows target std) with sha256, and the offline install steps.
- [ ] **Step 4:** Install on two lab VMs from the archives and run `cargo xtask toolchain verify`. Expected: `ok <version>`.
- [ ] **Step 5:** Commit.

### Task 0.4: Dependency ledger, vendoring and `cargo deny`

**Files:**
- Create: `docs/support/rust-dependencies.md`, `deny.toml` (allow MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib; deny GPL, AGPL, LGPL, unknown), `vendor/` (from `cargo vendor`), `.cargo/config.toml` source replacement, `xtask/src/deps.rs`, `xtask/tests/fixtures/deps/{two-package.lock,one-row-ledger.md}`
- Modify: `THIRD_PARTY_NOTICES`

**Interfaces:**
- Produces: `cargo xtask deps check`: fails if any `Cargo.lock` package lacks a ledger row, if a row's license differs from the crate's metadata, or if the resolved non-test feature graph (`cargo tree -e features` for every product target and the exact release invocation) enables any `testing` feature, directly, by forwarding or by default; `xtask release` refuses `--all-features`. `cargo xtask notices` regenerates `THIRD_PARTY_NOTICES` from vendored license files.
- Audit (recorded, no code): the pinned `raft` crate's prost codec and its maximum entry size against the design §6 limits (4 MiB decompressed batch); the pinned `redb` `StorageBackend` signature.

- [ ] **Step 1:** Test `xtask::deps::tests::a_lockfile_package_without_a_ledger_row_fails` (fixtures above) asserting the error names the missing package; `a_testing_feature_reached_through_a_forwarded_or_default_feature_fails`; `a_testing_feature_on_a_dev_edge_passes`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `pub fn check(lock: &str, ledger: &str, edges: &[Edge]) -> Result<(), Vec<String>>`. The dependencies of xtask itself (lockfile/TOML parsing) are the first ledger rows. Record the YAML crate and the TLS provider choice as D111 with the license text checked. Vendor on a lab VM with egress (ask the controller if none has egress); verify offline on a VM without network.
- [ ] **Step 4:** On a VM with no network: `cargo deny check`, `cargo xtask deps check`, `cargo build --locked --offline`. Expected: all green.
- [ ] **Step 5:** Commit.

### Task 0.7: Obligation ledger

**Files:**
- Create: `docs/obligations/README.md` (format, ID rules, landed tasks, current phase = 0), `docs/obligations/{requirements,design,contracts,protocol,infrastructure}.md`, `docs/obligations/discrepancies.md`, `xtask/src/obligations.rs`
- Test: `xtask/tests/obligations.rs`

**Interfaces:**
- Produces: rows `| ID | source (file §/line, or owner decision) | testable statement | evidence kind (model / sim / process-kill / production test / qualification) | owning task | tests |`. IDs are stable (`R11-2`, `D7.1-4`, `C12-3`, `P-ingest-7`, `I-sim-3` for infrastructure). Tests cite IDs with `// obligation: <ID>` immediately above the test function; TLA+ invariants cite them in a comment on the invariant.
- `cargo xtask obligations check`: a row whose owning task has landed (listed in README) without a citing test, a citation of an unknown ID, a citation of a row whose owning task has not landed, a citation whose test kind does not match the row's evidence kind, a duplicate ID, a source reference that no longer resolves, or a discrepancy record without a ruling, spec text or existing regression test → fail.
- `cargo xtask obligations run --phase N`: runs every test cited by rows owned by Phase ≤ N (`cargo test` name filters on a lab VM; TLC via `xtask models check`), asserts that each cited test actually ran (a filter matching zero tests is a failure), records non-Rust evidence (TLC, drills) by runner and result file, writes `target/obligations-phase-N.json` (row, test, result, build digest), and fails on any failure or uncited row.
- Inventory rule: every source (requirements, design, contracts, protocol docs, owner decisions D1–D110) is inventoried at section granularity with an owning phase; rows owned by Phases 0–1 (design §6, §7.1, §7.3, §12 single-voter parts; C01, C03, C05, C12 single-voter parts; `docs/protocol/ingestion-v1.md` storage-visible rules; the Phase 0 infrastructure guarantees) are itemized now from the spec text only (Go code and tests are not sources); each later phase itemizes its rows in its phase plan before code.

- [ ] **Step 1:** Tests: `a_landed_row_without_a_citing_test_fails`, `a_test_citing_an_unknown_id_fails`, `a_wrong_evidence_kind_fails`, `a_duplicate_id_fails`, `a_row_of_an_unlanded_task_may_be_uncited`, `a_stale_source_reference_fails`.
- [ ] **Step 2:** Run them on a VM. Expected: FAIL.
- [ ] **Step 3:** Implement; write the inventory and the itemized Phase 0–1 rows, including infrastructure rows owned by Tasks 0.2–0.4, and add their `// obligation:` citations to the tests those tasks landed.
- [ ] **Step 4:** Run the tests and `cargo xtask obligations check`. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 0.8: `sp-sim` simulator core

**Files:**
- Create: `crates/sp-sim/{Cargo.toml,src/lib.rs,src/exec.rs,src/clock.rs,src/rng.rs,src/disk.rs,src/net.rs,src/seed.rs,src/trace.rs}`, `xtask/src/lint_seams.rs`
- Test: `crates/sp-sim/tests/{disk_model.rs,net_model.rs,determinism.rs}`

**Interfaces:**
- Produces:
  - `pub trait Clock { fn now_mono(&self) -> Mono; fn now_wall(&self) -> Wall; }` and `pub trait Rng { fn next_u64(&mut self) -> u64; }`.
  - `pub trait Disk`: synchronous file primitives used only by drivers and adapters, never by cores: `create`, `open`, `len`, `set_len`, `read_exact_at`, `write_all_at`, `sync_data`, `sync_dir`, `rename`, `remove`, `list`, plus `bytes_submitted()` (accounting for write-cost tests). `SimDisk` implements it in memory, so a synchronous call inside the executor never waits on another thread.
  - `SimDisk` fault model: data not covered by `sync_data` may at a crash be lost, kept, or kept per sector in any subset; a create/rename/remove not covered by `sync_dir` of its parent may be undone; a `sync_data` error leaves the covered data in any of those states and latches the file (later syncs fail); short writes; seeded read errors, bit flips and misdirected writes; whole-disk loss and replacement. Unwritten sectors of a preallocated file read as zeros.
  - `SimNet`: per-link drop, duplicate, reorder, delay, partition (including asymmetric).
  - `Completion { id: CompletionId { incarnation, group, generation, seq, op }, result }`; the executor delivers completions in a seeded order, possibly after a crash of their issuer (the core drops them by incarnation).
  - `sim::run(seed, suite)`: single-threaded executor with a virtual clock; a failure prints `SP_SIM_SEED=<seed> SP_SIM_SUITE=<suite>` and the build digest; the same seed replays the same trace byte for byte.
  - `cargo xtask lint-seams`: fails on `std::time`, `rand::thread_rng`, `std::fs`, `std::net` inside crates listed as cores (initially `sp-sim`'s simulated paths; each later core task adds its crate).
- [ ] **Step 1:** Tests: `unsynced_data_may_vanish_or_survive_per_sector_at_a_crash`, `synced_data_survives_every_crash_on_the_same_healthy_disk`, `a_rename_without_parent_dir_sync_may_be_undone`, `a_failed_sync_leaves_any_state_and_latches_the_file`, `a_misdirected_write_is_seen_at_the_wrong_offset`, `unwritten_preallocated_sectors_read_as_zero`, `a_completion_from_a_previous_incarnation_is_delivered_and_identifiable`, `the_same_seed_gives_the_same_trace`, `a_partition_drops_only_the_cut_links`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them, plus `determinism` over 1,000 seeds. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 0.9: History checker

**Files:**
- Create: `crates/sp-sim/src/history/{mod.rs,linearizable.rs,durable.rs}`
- Test: `crates/sp-sim/tests/history.rs`

**Interfaces:**
- Produces: a `History` that records per operation: no proposal, pending (ambiguous), durable terminal outcome (applied / applied-rejected), release, response sent, response observed; and reads/receipt lookups with their results. `check_linearizable<M: Model>(h, m) -> Result<(), Counterexample>`: a memoized bounded search (Wing–Gong style) in which a pending write may linearize or not; no key partitioning until a model declares independence and scale demands it. `check_durable(h)`: an observed ACK's rows and original receipt are present after every supported recovery; a write visible without commit evidence, an invented ACK, or a recomputed receipt is a violation; a committed write whose ACK was lost may be visible and found by receipt lookup; absence after an authorized deletion or expiry is not loss.
- Tiny-history domain (the gate): ≤ 4 operations on ≤ 3 keys with values from {1,2}, each operation pending or completed, ≤ 1 crash, all interleavings of invoke/return events.
- [ ] **Step 1:** Tests: `agrees_with_brute_force_on_the_whole_tiny_domain`, `a_pending_write_may_or_may_not_take_effect`, `a_committed_write_with_a_lost_ack_may_be_visible_and_found_by_lookup`, `a_visible_write_without_commit_evidence_is_reported`, `an_observed_ack_missing_after_recovery_is_reported`, `a_counterexample_is_reproducible_and_then_shrunk`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 0.10: TLA+ model of the single-voter write path

**Files:**
- Create: `models/wal/WalApplyAck.tla`, `models/wal/{correct,early_ack,apply_before_sync,tail_as_torn}.cfg`, `models/README.md`, `models/schedules/` (exported counterexample schedules), `xtask/src/models.rs`

**Interfaces:**
- Produces: a model of propose → write → `sync_data` and `sync_dir` → commit (single-voter authority) → durable apply cut → view publication → release (ACK), with crash at any point under the `SimDisk` loss rules, the WAL recovery rule of the Global Constraints, and the generation switch through `CURRENT`. Invariants, each citing its obligation ID in a comment: `NoReleaseBeforeSync`, `NoReleaseBeforeApplyCut`, `ReleasedIsDurable`, `RecoveryNeverDropsAProvenDurableFrame`, `ReceiptStable`, `OnlyCurrentGenerationServed`. Each mutant configuration enables one wrong transition. `cargo xtask models check` runs TLC on a lab VM with the pinned tools jar; each mutant must fail its named invariant, `correct` must fail none; bounds, distinct states and time are recorded in `models/README.md`.
- Schedule export: a counterexample becomes a versioned fixture `models/schedules/<name>.json` of exogenous events only (proposal IDs, disk write/sync completions and failures, crash, reopen) that `sp-sim` drives against the real core (Tasks 1.4 and 1.6).
- [ ] **Step 1:** Write the model and the mutant configurations; run `xtask models check` with only the mutants. Expected: each mutant fails its named invariant with a trace; export the `early_ack` and `tail_as_torn` schedules.
- [ ] **Step 2:** Run the `correct` configuration. Expected: no violation within the recorded bounds.
- [ ] **Step 3:** Commit.

### Task 0.5: `xtask source-digest` and `release`

**Files:**
- Create: `xtask/src/digest.rs`, `xtask/src/release.rs`, `xtask/tests/fixtures/d60/` (a scripted fixture repository: tracked, ignored, generated and excluded paths, built by the test with a controlled git index)
- Test: `xtask/tests/digest.rs`

**Interfaces:**
- Consumes: the source-digest definition of D60 and its documentation; the expected digest of the fixture is computed by hand from that definition and written in the test. The Go `build source-digest` from `go-reference` runs on the same fixture and the same commit only to detect differences; a difference gets a ruling against D60.
- Produces: `cargo xtask source-digest` and `cargo xtask release --version V --out DIR` (static musl binaries for every bin target, `BUILD.txt` with toolchain, digest and binary sha256). In Phase 0 the only bin target is `xtask` itself: the reproducibility check is a smoke test that becomes a gate when product binaries exist. `web/dist` embedding is wired in Phase 3.

- [ ] **Step 1:** Tests: `digest_of_the_d60_fixture_equals_the_documented_value`, `digest_is_independent_of_file_creation_order`, `digest_excludes_the_documented_paths`, `digest_changes_when_one_byte_of_a_tracked_file_changes`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `pub fn source_digest(root: &Path) -> io::Result<[u8; 32]>` and `release` (`--target x86_64-unknown-linux-musl`, `-C target-feature=+crt-static`, `--remap-path-prefix`).
- [ ] **Step 4:** Run the release twice on two VMs (smoke: identical sha256). Run the Go reference digest on the fixture and on the current commit; record equality or the ruling in `docs/obligations/discrepancies.md`.
- [ ] **Step 5:** Commit.

### Task 0.6: CI and the Phase 0 gate

**Files:**
- Create: `.github/workflows/rust.yml`
- Modify: existing Go workflows: keep them running on the `go-reference` branch only

**Interfaces:**
- Produces: jobs `fmt` (`cargo fmt --check`), `clippy` (`-D warnings`), `build` (`cargo build --workspace --locked --offline`), `test` (`cargo test --workspace --locked --offline`), `deny`, `deps`, `obligations` (`check`, landed-task scope), `lint-seams`, `digest`, and `sim-smoke` (each registered suite at its per-commit seed budget; empty in Phase 0, suites register as tasks add them), all on hosted Linux runners with pinned tool versions. TLC, fuzzing, mutation, `obligations run --phase N` and seed campaigns run on lab VMs by the direct `cargo xtask` commands named in each task (the `xtask gate` runner is Phase 7).

- [ ] **Step 1:** Push a branch with a deliberate clippy warning. Expected: the `clippy` job fails.
- [ ] **Step 2:** Remove the warning. Expected: all jobs green.
- [ ] **Step 3:** Run `cargo xtask obligations run --phase 0` on a lab VM (Phase 0 gate). Expected: PASS; set the current phase to 1 in `docs/obligations/README.md`.
- [ ] **Step 4:** Commit.

---

## Phase 1: model, scope seam and single-voter storage

Tests are derived from the Phase 1 obligation rows. The Go storage tests are a scenario inventory only: Task 1.9 mechanically lists their scenario families (deduplicated), maps each to the obligation that covers it, or states why it does not apply; their expected values are never copied. Every test below is shown red first and cites its obligation ID. Phase 1 proves single-voter behaviour only: the authority journal, cross-group barriers, restore and quota proofs, older or offline replicas and transfer/backup pins are carried by Phases 2, 5 and 8.

### Task 1.1: `sp-model` core types, fault and outcome model

**Files:**
- Create: `crates/sp-model/src/{id.rs,cursor.rs,fault.rs,outcome.rs,ctx.rs,json.rs}`
- Test: `crates/sp-model/tests/{fault.rs,json.rs,ctx.rs}`, `crates/sp-model/tests/fixtures/{fault-envelope.json,canonical/*.json}`

**Interfaces:**
- Produces:
  - `pub struct Id([u8; 16])` with lower-case 32-hex `Display`/`FromStr`, nonzero, and `Id::random(&mut dyn Rng) -> Id`.
  - `pub struct Cursor { pub group: Id, pub index: u64 }`.
  - `pub enum Code { Invalid, Unauthenticated, Forbidden, Conflict, TooLarge, Unsupported, Quota, Unavailable, Timeout, Cancelled, Stale, NotFound, Corrupt }`, serialised as the contract strings.
  - `pub struct Fault` (private fields: code, retryability, safe detail, latched flag), built only from typed causes: `Fault::from(Cause)` where `Cause` is a closed enum per producer (`NoLeader`, `QuorumLostOnReadFence`, `RetryableRefusal`, `Latched`, `Closing`, `FailedClosed`, `Invalid(..)`, `Conflict`, `Corrupt`, …) and retryability is derived exhaustively from the cause and the stage reached; there is no generic `transient(code)` constructor, and `Latched`, `Closing` and `FailedClosed` are never retryable.
  - `pub struct FaultEnvelope { fault: Fault, request_id: Id }` with the contract JSON envelope (`code`, `retryable`, `detail`, `request_id`); the request ID comes from the operation boundary, not the producer.
  - `pub enum Outcome<T> { NotCommitted(Fault), Ambiguous(Fault), Applied(T), AppliedRejected(Fault) }`.
  - `pub struct Ctx { deadline: Option<Mono>, cancel: CancelToken }` with `check(&self, clock: &dyn Clock) -> Result<(), Fault>` and `child(&self, clock: &dyn Clock, d: Duration) -> Ctx` (deadline = min(parent, now + d)).
  - `pub fn canonicalize(raw: &[u8]) -> Result<Vec<u8>, Fault>` (strict parse: invalid UTF-8, duplicate keys and integer overflow rejected; canonical output) and `pub fn hash_canonical(raw) -> Result<[u8; 32], Fault>`, under the rules of the contracts and the ingestion protocol ("Requests and exact values"); where they are silent, the rule is written into `docs/protocol/` first (owner ruling if it changes a documented byte).
- [ ] **Step 1:** Tests:
  - `fault_envelope_matches_the_contract`: expected bytes written by hand from the contracts' envelope definition.
  - `fail_is_never_retryable_and_transient_takes_only_transient_codes` (compile-fail doc-test for a transient `Corrupt`), `a_latched_fault_is_never_retryable`.
  - `ctx_child_deadline_is_min_of_parent_and_now_plus_d`, `ctx_reports_timeout_after_its_deadline_and_cancelled_after_cancel` (virtual clock).
  - `canonical_vectors_from_the_protocol_rules` (named vectors: key order, whitespace, UTF-8, numbers as the protocol encodes them) and `duplicate_keys_are_rejected_before_any_value_is_built`. Then run the vectors through the Go reference's `model.HashCanonical` on a VM; differences go to `docs/obligations/discrepancies.md` with a ruling.
- [ ] **Step 2:** Run `cargo test -p sp-model`. Expected: FAIL (types missing).
- [ ] **Step 3:** Implement as listed.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.2: Minimal `sp-auth` scope seam

**Files:**
- Create: `crates/sp-auth/{Cargo.toml,src/lib.rs,src/scope.rs,src/capability.rs,src/testing.rs}`
- Test: `crates/sp-auth/tests/scope.rs`, `crates/sp-auth/tests/ui/*.rs` (compile-fail)

**Interfaces:**
- Produces: `pub struct Scope` (org, principal, policy epoch, visibility fingerprint, granted projects/actions/named sources; private fields; no `Deserialize`; not constructible outside `sp-auth`), queried by `scope.allows(project, action)`; `pub struct EraseCapability` and `MaintenanceCapability` (private, issued only by `sp-auth`); `sp_auth::testing::{issue_scope, issue_erase}` behind the `testing` feature, used only by dev-dependencies (enforced by `xtask deps check`). The real issuance path (sessions, tokens, OIDC) is Phase 3; this task fixes the type and the trust boundary that storage consumes.
- [ ] **Step 1:** Tests: compile-fail `a_scope_cannot_be_built_outside_sp_auth` and `a_scope_cannot_be_deserialized`; `a_scope_without_the_project_grant_allows_nothing`; `a_scope_binds_its_policy_epoch_and_fingerprint`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them, and `cargo xtask deps check`. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.3: `sp-durablefs`, generation roots and the crash-point harness

**Files:**
- Create: `crates/sp-durablefs/{Cargo.toml,src/lib.rs,src/linux.rs,src/generation.rs,src/crashpoints.rs,src/bin/crashchild.rs}` (the child binary is test-only)
- Test: `crates/sp-durablefs/tests/{replace.rs,generation.rs}`

**Interfaces:**
- Produces:
  - `LinuxDisk: sp_sim::Disk` (`unsafe` allowed only for `fdatasync`/`fsync` via `rustix`, if needed), plus preallocation of zero-filled files.
  - `replace_atomically(disk, dir, name, bytes)` (temp, write, sync, rename, sync dir).
  - `GenerationRoot` per write domain: `stage(n) -> dir`; `commit(n, expected_current)`: compare-and-swap against the expected current generation (flush and erasure serialize through it), sync every staged file and every new directory entry (each parent), write and sync the checksummed root (Format baseline: digests of sealed files, identities of mutable files), replace `CURRENT` atomically, sync its directory; an uncertain publication fails closed until reopen decides it; `current()` validates the root and the sealed digests; a root that fails validation is `Corrupt`, never silently replaced by an older one.
  - `pub trait CrashPoints { fn hit(&self, point: &'static str); }` with `NoCrash` (production) and `HookCrash` (test: at the named point the child writes the point name to a pipe and blocks; the parent SIGKILLs it while blocked and reopens in a fresh process). Points used here: `replace`: `temp_written`, `temp_synced`, `renamed`, `dir_synced`; `generation`: `staged_files_synced`, `staged_dirs_synced`, `root_written`, `current_replaced`, `current_dir_synced`.
- [ ] **Step 1:** Tests: `replace_atomically_leaves_old_or_new_never_torn` and `a_generation_commit_is_all_or_nothing`, each under `SimDisk` at every operation boundary (fixed seed budget) and as process-kill tests at each named point (after an observed `dir_synced`/`current_dir_synced` only the new state is acceptable).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them on ext4 on a lab VM. Expected: PASS (process-kill tests skipped on non-Linux with a printed reason).
- [ ] **Step 5:** Commit.

### Task 1.4: Group WAL with the proven-boundary recovery rule

**Files:**
- Create: `crates/sp-storage/{Cargo.toml,src/lib.rs}`, `crates/sp-storage/src/wal/{frame.rs,segment.rs,recover.rs,core.rs,mod.rs}`
- Test: `crates/sp-storage/tests/wal.rs`

**Interfaces:**
- Consumes: `sp_sim::{Disk, Completion}`, `GenerationRoot`, `CrashPoints`.
- Produces:
  - Frame per the Format baseline (sector-aligned; header: magic, length, checksum, group, generation, segment, offset, index, term, kind). Kinds: `Entry`, `HardState`. Length is bounded before allocation. Frontier file: two alternating slots, each exactly one device atomic write unit (the logical block size probed at creation and recorded in the file header; creation refuses a device whose reported unit exceeds 4 KiB), each `{slot, seq, base index, base term, segment, offset, index, term, frame checksum, hard state, checksum}`; both slots are written and synced, with the file's directory entry, at creation; a new generation's frontier is seeded with its snapshot base (index and term of the cut) and an empty WAL. If a device tears a slot despite its reported unit, recovery fails closed (`Corrupt`), never rolls back; the Phase 8 power-cut drill qualifies the hardware.
  - `WalCore` (sans-IO): `append(frames) -> Actions`, `on_completion(Completion) -> Actions` (stale incarnation dropped), `certified_upto() -> Locator`; actions `Write`, `Sync`, `WriteFrontier`, `SyncFrontier`, `Rotate` (a new segment is created, synced and its directory entry synced before any frame in it is certified). A batch is certified only after `SyncFrontier` completes for a frontier covering it. Reads go through the driver by locator, off the owner loop.
  - Recovery: both frontier slots must validate (a failing slot is `Corrupt`, refuse service, never fall back); the slot with the higher sequence is the proven prefix; every frame inside it must validate (else `Corrupt`); frames beyond it are truncated; the result names the proven prefix and the truncated range.
- [ ] **Step 1:** Tests:
  - `every_certified_frame_survives_a_crash_at_any_operation` (sim, every boundary, fixed budget; replays `models/schedules/tail_as_torn.json`).
  - `sync_certify_then_damage_the_last_frame_then_reopen_is_corrupt_not_truncated` (no later operation; covers an entry frame and a hard-state frame).
  - `an_uncertified_tail_is_truncated_and_nothing_before_it_is_lost`.
  - `a_frontier_write_lost_at_a_crash_leaves_the_previous_slot_in_force` and `a_corrupt_frontier_slot_refuses_service_and_never_rolls_back`.
  - `a_valid_frame_at_another_offset_or_segment_is_rejected`.
  - `a_failed_sync_of_frames_or_frontier_latches_the_wal_and_nothing_is_certified`.
  - `a_late_completion_from_before_a_crash_certifies_nothing`.
  - `a_rotated_segment_is_not_certified_before_its_directory_entry_is_synced`.
  - Process kill at `frame_written`, `frames_synced`, `frontier_written`, `frontier_synced`, `rotated`, `rotation_dir_synced`: `every_frame_certified_before_the_kill_reads_back` (100 repetitions per point).
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS, 100/100 repetitions per point.
- [ ] **Step 5:** Commit.

### Task 1.5: Metadata store and write-set bound

**Files:**
- Create: `crates/sp-storage/src/meta/{store.rs,tables.rs,backend.rs}`, `docs/storage/format-v1.md` (rewritten; it states the frontier slot's atomic-write assumption explicitly, with the probe, the fail-closed consequence and the drills that check it)
- Test: `crates/sp-storage/tests/meta_bounds.rs`

**Interfaces:**
- Consumes: `redb` at the version audited in Task 0.4, opened with immediate durability (every commit synced before return), through `backend.rs`: a `redb::StorageBackend` over the synchronous `sp_sim::Disk` primitives; the database file is created, synced and its directory entry synced before first use. In production each write domain has one ordered logical metadata worker on a bounded shared metadata pool (capacity independent of WAL I/O and completion handling) that owns the database and executes `CommitMeta` actions; in simulation the executor runs them inline on `SimDisk`, so no cross-thread wait exists. After a latch the adapter refuses every further backend mutation, including on close.
- Produces:
  - `pub struct MetaStore` with typed tables `applied`, `receipts`, `tombstones`, `deny` (key and value encodings in `docs/storage/format-v1.md`). No payloads, index bodies or deletable strings in it. Generation roots stay in `GenerationRoot`.
  - `commit(f) -> Result<T, Fault>`, durable on return; a backend sync error latches the store.
- [ ] **Step 1:** Tests:
  - `metadata_bytes_per_commit_are_bounded_and_independent_of_history`: 1,000 versus 100,000 prior receipts; backend bytes submitted per receipt commit differ by less than 1.25×, with realistic batch keys and one pinned reader; the absolute figure is recorded (the whole append→ACK path is measured in Task 1.6).
  - `a_commit_is_durable_after_return` and `a_crash_between_any_two_backend_calls_reopens_all_old_or_all_new` (sim crash injected between backend calls, fresh reopen; process kill at `meta_committed`).
  - `a_backend_sync_error_latches_the_store_and_a_fresh_reopen_sees_all_old_or_all_new`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.6: Single-voter group: commit, apply, view, release

**Files:**
- Create: `crates/sp-storage/src/{group.rs,apply.rs,view.rs,window.rs,segment.rs,cut.rs,receipt.rs,engine.rs,sim_suite.rs}`
- Test: `crates/sp-storage/tests/{group_sim.rs,append.rs,cut_cost.rs}`

**Interfaces:**
- Consumes: `WalCore`, `MetaStore`, `GenerationRoot`, `sp_auth::Scope`, `sp-model::{Outcome, Fault, Ctx}`; adds `NormalizedBatch` and `Receipt` to `sp-model` from the contracts and the ingestion protocol.
- Produces:
  - `GroupCore` (sans-IO) with the milestones as events: `Proposed` → `LocalPersisted{upto}` (WAL certified) → `CommitAdvanced{term, cursor}` (single-voter authority derives it from certified persistence; Phase 2 replaces the source) → `ApplyCommitted{cut}` (the metadata transaction holding applied cut, terminal outcome, receipt with original deadlines, and references has completed) → `ViewPublished{cut}` → `Released{op}`; actions `WriteWal`, `SyncWal`, `CommitMeta(cut)`, `PublishView(cut)`, `Reply(Outcome<Receipt>)`. The release check (scope and published deny epoch) is performed in the same owner step that emits `Reply`, so the check and the handoff are one event in the owner's order; a deny is reported committed only after its epoch is published to that owner and to readers. A success or ordered result is replied only after `ViewPublished` covers it; a fault before proposal or a latch replies at once with `NotCommitted` or `Ambiguous`. `Engine::open` replays committed-but-unapplied entries from the certified prefix and is not ready until the applied cut reaches the certified commit point. A receipt lookup authenticates the full C03 identity tuple and content hash and returns the original cursor and deadlines without entering the write path. Changed content with the same identity is `AppliedRejected(Conflict)` (the HTTP 409 mapping is Phase 3).
  - `pub struct Engine` (production driver): `open(cfg) -> Result<Arc<Engine>, Fault>`, `append(&self, ctx, scope: &Scope, b) -> Outcome<Receipt>`, `lookup_receipt(&self, ctx, scope, r) -> Result<Receipt, Fault>`, `read_at_least(&self, ctx, scope, min: Cursor) -> Result<ViewHandle, Fault>` (minimal read for read-your-ACK), `flush`, `close`. 64 route slots as fixed groups (`RouteSlot: u16 < 64`), one logical owner each on a bounded set of event loops; metadata and WAL I/O on bounded worker pools; queues bounded by bytes and count.
  - Windows reference WAL frames by locator; sealing writes segments in a new generation and moves readers atomically; cut cost proportional to new commands; cuts of different slots staggered.
- [ ] **Step 1:** Tests:
  - `group_sim`: seeded suite with crash/restart at every operation boundary and `SimDisk` faults; histories checked by `check_durable` and `check_linearizable` against the spec model (append/ACK, receipt lookup, `read_at_least`); replays `models/schedules/early_ack.json` against the real core and asserts no premature release; registers its per-commit budget with `sim-smoke`.
  - `every_trace_orders_persist_commit_apply_publish_release` (milestone-order assertion on every trace).
  - `a_receipt_replay_returns_the_identical_cursor_after_restart`.
  - `changed_content_with_the_same_identity_is_applied_rejected_conflict`.
  - `bytes_per_ack_are_bounded_and_independent_of_history` (whole append→ACK path, WAL plus frontier plus metadata from `bytes_submitted()`, 1,000 versus 100,000 prior receipts, within 1.25×, with exact read-back after reopen) and `bytes_written_per_cut_are_proportional_to_new_commands_not_window_size` (cut after 100 and after 4,000 commands; 10 new commands; within 1.25×).
  - `sealing_a_window_reads_at_most_the_commands_since_the_last_cut`.
  - `cuts_of_different_slots_are_staggered`.
  - Process kill at `wal_synced`, `meta_committed`, `view_published`, `reply_sent` with a parent-side witness of the reply: `an_observed_ack_reads_back_with_its_original_receipt_after_restart` and `no_reply_is_observed_before_wal_sync_and_meta_commit`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.7: Scans, subscriptions and the deny fence on immutable views

**Files:**
- Create: `crates/sp-storage/src/{scan.rs,scan_build.rs,live.rs,slots.rs,deny.rs}`
- Test: `crates/sp-storage/tests/{scan_concurrency.rs,scan_toctou.rs,live_walk.rs}`

**Interfaces:**
- Produces:
  - `deny(&self, ctx, cap: &EraseCapability, preds: &[DeletePredicate]) -> Outcome<DenyCursor>`: commits a deny fence through the group and publishes its epoch (an atomically swapped immutable deny set) before reporting success; every page handoff, export and live delivery checks the published epoch at the moment of handoff, after the page is built, and drops rows the epoch denies.
  - `scan(&self, ctx, scope, req: ScanRequest) -> Result<Scan, Fault>` with `Scan::next_page(&mut self, ctx: &Ctx) -> Result<Option<Page<'_>>, Fault>` (a page borrows from the pinned view) and `watermarks()` restricted to the scope; `subscribe(&self, ctx, scope, req) -> Result<Feed, Fault>` whose items distinguish rows, explicit gaps, freshness faults and revocation from end of stream.
  - Readers hold an `Arc` of an immutable view (plus a bounded-age redb read transaction where they need metadata) and never a lock guard. Scan slots and live slots are separate FIFO pools (2,048 and 32, D105); a slot is taken before any engine state is touched and released once on drop. Pins carry an age and byte budget; when exceeded, the next `next_page` returns a typed fault and drops the pin; reclamation waits for file handles to close.
  - Spec wording: C05's reader mutex and the ingestion protocol's shared ordering lock are restated as their observable guarantees (atomic immutable view publication with authorization and applied-watermark checks; ordered validation at apply) in an amendment note referencing D110 (controller ruling; the owner may veto).
- [ ] **Step 1:** Tests:
  - `a_scan_blocked_in_decode_does_not_block_an_append_or_another_scan` (decode hook blocks one scan for 2 s; the append and the second scan complete in < 200 ms).
  - `a_deny_committed_before_a_page_release_hides_its_rows` (three orderings: before scan start, between pages, during a live walk).
  - `a_live_walk_delivers_every_kept_row_once_after_rechunking_and_reports_gaps`.
  - `an_admitted_query_mix_is_never_answered_too_large`.
  - `a_scan_waiting_for_a_slot_honours_its_deadline`.
  - `thirty_two_live_subscriptions_do_not_starve_scans`.
  - `a_scope_without_the_project_grant_sees_no_row_count_or_watermark`.
  - `an_expired_pin_ends_the_read_with_a_typed_fault`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.8: Erasure by generations

**Files:**
- Create: `crates/sp-storage/src/{erase.rs,erase_guard.rs,snapshot.rs,residual.rs}`
- Test: `crates/sp-storage/tests/{erase.rs,erase_sim.rs}`

**Interfaces:**
- Produces:
  - `erase(&self, ctx, cap: &EraseCapability, guard: &dyn EraseGuard) -> Result<EraseReport, Fault>` (single voter): with a committed deny fence in place, stop admission, wait for every in-flight WAL, frontier and metadata I/O to complete (or fail closed), choose the committed and applied command cut that covers every payload-bearing entry, carry the hard state and frontier into the new generation explicitly, seal a filtered snapshot at that cut (tombstones, receipt outcomes and deadlines, retained rows), build new segment/metadata files and an empty WAL in a staged generation, verify sealed digests, commit the generation root by compare-and-swap, resume admission, then reclaim superseded files once their file handles are closed (file handles are held only by cancellable bounded leases, separate from decoded memory). Replicated entries are never rewritten in place. Multi-voter suffix handling is a Phase 2 model obligation.
  - `erase_expired(&self, ctx, now: Wall, cap, guard)` (wall time injected by the caller's `Clock`); `residual(&self) -> ResidualReport`: every file the store owns, by generation, with held reasons (leases, guard veto), from the store's own inventory.
- [ ] **Step 1:** Tests:
  - `erased_bytes_are_absent_after_cleanup`: seed a canary in a payload and prove it present in each payload-bearing encoding the run exercised (WAL frame, segment page, snapshot) and absent from metadata by construction; after cleanup completes with no held files, scan every file under the data directory raw and through the format-aware decoders (including index and locator structures). Expected: absent everywhere. Also `a_historical_receipt_survives_erasure_without_its_rows` (C03).
  - `erase_after_a_terminal_hard_state_and_no_further_proposals_keeps_the_hard_state` and `a_rejected_payload_before_the_cut_is_erased_too`.
  - `a_crash_at_every_erase_step_converges_on_rerun_and_never_serves_an_old_generation` (sim, plus process kill at `snapshot_sealed`, `generation_staged`, `root_committed`, `reclaimed`).
  - `a_pinned_reader_delays_reclamation_and_is_reported_held`.
  - `the_guard_veto_keeps_bytes_and_reports_held`.
  - `a_mixed_batch_keeps_its_unerased_rows_after_erasure`.
  - `admission_resumes_after_erasure_and_new_writes_outside_the_predicate_succeed`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.9: Phase 1 exit

- [ ] **Step 1:** Mechanically inventory the Go storage test scenario families (test names and subtests, deduplicated) into `.superpowers/sdd/rust/phase1-report.md`; map each family to the obligation that covers it, or state why it does not apply; review unique schedules by hand. No expected value is copied.
- [ ] **Step 2:** Measure simulator throughput per suite; set and record each suite's campaign budget; run the campaigns on a lab VM. Expected: 0 failures.
- [ ] **Step 3:** `cargo test -p sp-storage --release` 3× and under ThreadSanitizer (the separately pinned nightly, this check only). Expected: all green, 0 reports.
- [ ] **Step 4:** `cargo-mutants` on the WAL, recovery, group milestone and erasure modules, plus hand-written ordering mutants (release before sync, release before apply commit, wrong cursor, skipped deny revalidation, tail treated as torn without proof): every surviving viable mutant killed by a new test or explained; timeouts and unviable mutants reported separately. `cargo-fuzz` on the frame, segment, snapshot and generation-root decoders and on recovery for a recorded time budget; minimized crashes become regression tests.
- [ ] **Step 5:** Single-host power-loss drill: append load, `echo b > /proc/sysrq-trigger` on a disposable VM, 10 cycles, FULL read-back; plus 10 cycles of a hypervisor hard stop of the VM (through the platform, with the owner's permission; if not granted, recorded as not run). After every cycle the frontier file opens with both slots valid; a slot that fails its check counts as a failed cycle, never as a rollback. Expected: 0 missing ACKed records, 0 failed slots. A torn slot on this hardware stops Phase 2 until the frontier format is revised.
- [ ] **Step 5b:** Measure append→ACK latency (p50/p95/p99 at the design §13 single-host load) on the same VM's real disk with the frontier sync and, as a measurement-only build flag, without it; record both and the fsync count per ACK in the report. The format is not changed on this measurement alone: a cost above the design §13 budget goes to the owner with the alternatives before Phase 2.
- [ ] **Step 6:** `cargo xtask obligations run --phase 1` on a lab VM. Expected: PASS; set the current phase to 2.
- [ ] **Step 7:** Write the Phase 2 detailed plan in this format, as `docs/superpowers/plans/2026-11-29-rust-rewrite-phase2.md`; review by `m1` and `m2` before execution.

---

## Later phases: obligations their detailed plans must carry

These are inputs to the phase plans, not tasks yet. Each phase plan itemizes its obligation rows before code.

**Phase 2 (replication, control):**
- First task: audit raft-rs at the pinned version (`Ready`, `LightReady`, `advance*`, `on_persist_ready`, `Storage`, ReadIndex, membership, snapshot) and make election timeouts deterministic through an audited seam (a recorded vendored patch if needed). If tick and peer processing cannot stay safe while persistence runs elsewhere under its contract, revisit the library before production code.
- TLA+: 3-voter commit → durable apply → ACK with lost responses and conflicting suffix replacement; snapshot install/rejoin; membership/layout guard; a composed two-slot + control model with cancel versus committed-but-unapplied append.
- Erasure across voters: a coordinated cut at which every voter's retained WAL suffix is proven free of the erased predicate (ordered validation and pinned identity) or the generation switch waits; old or offline voters and in-flight snapshot transfers cannot reintroduce erased bytes; modelled in TLA+ before code.
- The ready driver persists, then sends, applies and advances per the audited contract; tick and peer processing never wait on fsync, decode, apply or disk-backed reads. Test: with 200 proposers spread and skewed over all 65 groups, the 99th-percentile tick lag stays below 20% of the election timeout, measured over a stated period.
- The largest legal normalized command (a full design §6 batch plus reservation overhead) passes end to end through the codec, WAL frame and peer transport without splitting the one-slot atomic admission.
- Per-group WALs, group commit within each group; control has its own WAL and apply lane with reserved capacity. Measure sync pressure before considering any shared data WAL.
- Leader calls are idempotent. A transport failure before send maps to no-leader (retryable). After send, the outcome is ambiguous unless the call is idempotent. Test: drop the connection after the leader applies, retry, assert no double count.
- Per-record ledger tables only. Bytes per control commit do not depend on total state, for admission, settlement, issue planning and rule commits.
- Linearizable validation (ReadIndex before validate). A deposed leader never commits an ACKed write. A member that cannot read the layout is refused.
- 3-node qualification on independent storage: kill -9 rejoin, disk loss after ACK, snapshot install, membership change.

**Phase 3 (auth, ingest, HTTP):**
- A per-operation status/fault/action table authored from the contracts and protocol docs, including rulings where `docs/protocol/replay-v1.md` documents Go behaviour that conflicts with C03 (for example a retryable `corrupt`/`cancelled` 503).
- `sp-diffref` corpus: every route of `internal/httpapi`, recorded against the Go reference and replayed against both builds, normalised only for opaque IDs, times and timing fields; every difference ruled.
- Fault mapping tests: a leader gap is 503 retryable with Retry-After 1–3 s; a failed-closed engine is 503 non-retryable; a ReadIndex quorum loss is 503 retryable; a revision `stale` keeps 400/409.
- The membership socket path stays under the platform limit. Tests use short directories.

**Phase 4 (languages):**
- Oracle: the pinned upstream images in `conformance/query`. Primitives (`sp-goregex`, `sp-gotemplate`, `sp-gofmt`, `sp-gojson`) are differentially fuzzed against those images and against a fresh build of the exact upstream Go standard-library release each profile pins (BSD-3-Clause, notice kept), 10⁶ cases each with 0 differences; never against Soundpost's Go code.
- Query and rule cores are sans-IO (scheduler, admission, slot pools, deadlines) and run in `sp-sim`. Admission defaults 16/8/4 (D106), a typed page decode, an index-block cache bounded and dropped on erasure, and shared range scans equal to per-step evaluation.
- Rules: an own loop with bounded project concurrency, holding 100 evaluations/min under 100 rec/s ingest (design §13).

**Phase 5 (workflow, artifacts):**
- TLA+: quota reservation with ambiguous outcome; the C12 deletion barrier saga; outbox fenced claim including a provider result accepted but never observed.
- Outbox: each durable intent delivered with fenced attempts under a crash at every step; a repeat after provider acceptance is possible and visible (design §7.2, §11); retries capped at 12 attempts or 24 h, with jittered delays from 1 s to 15 min that honour provider Retry-After (contracts line 162).
- The symbolication sandbox gets escape tests (filesystem, network, process limits).
- Retention and backup restore authority: old users and tokens stay inactive after a restore.

**Phase 6 (native):**
- perf ring parsing is authored independently, with no `tools/perf` code. The seccomp allowlist includes `rseq`. The hostPID recipe stays unprivileged (D98). The privacy canary test runs on real kernels 6.1 and 6.6.

**Phase 7 (tools):**
- Each Rust validator in `sp-tools-qualify` derives its verdict from the obligations it cites; on the same stored result directories (G12 and the drill evidence) differences from the Go validator are discrepancy records, each ruled before the Go one is retired.

**Phase 8 (qualification and cutover):**
- The gates use the design §13 definitions: single-host p95, distributed `healthy_strict_p95_ms` over at least two runs with FULL read-back, and queries pooled p95 with 100 rule evaluations/min.
- Power-cut drill with FULL read-back, a real hypervisor stop, kill -9 rejoin within 30 s; erasure cleanup within 24 h with a canary scan on every replica.
- Console e2e in Chromium, Firefox and WebKit, including headed runs of investigation-journeys, accessibility and replay-profile.
- The Go code is removed in one commit. README, `docs/support` and the release notes are rewritten, and the release notes state the fresh format and that 0.1.0-preview.1 installs must be reinstalled.

## Risks

| Risk | Effect | Mitigation |
|---|---|---|
| Simulator fidelity (a fault model weaker than real disks/kernels) | green sims, real loss | fault model from the fsync/rename/directory semantics Linux documents; every sim claim paired with a real-process or real-node test; Phase 8 power-cut drills |
| raft-rs contract or randomness blocks determinism or safe progress | Phase 2 rework | audit first in Phase 2; vendored patch recorded; library replaceable behind the adapter |
| Obligation ledger decays or is itemized too coarsely | untested spec sentences | `xtask obligations check` in CI; each phase itemizes its rows before code; reviewers check rows against the spec text |
| RE2/template/number-format parity | conformance mismatches late in Phase 4 | differential fuzz against the pinned images and stdlib release from day one of Phase 4 |
| Verification cost (TLC, fuzz, mutation, seed campaigns) | slower phases | small models; campaigns on lab VMs, not per commit; budgets set from measured throughput |
| Lab removed 2026-12-06 | Phase 2/8 blocked | extension MR pending a human merge (new remove-by 2027-01-31) |
| Scale (~199k product lines, ~104k harness lines, ~314k test lines in Go) | estimate overrun | phase gates, parallel lanes after Phase 3, stop rules per phase |
