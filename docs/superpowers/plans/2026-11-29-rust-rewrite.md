# Soundpost Rust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** APPROVED by the owner on 2026-11-29 (decision D109). Execution method: subagent-driven. Model routing set by the owner: `m3` (Sonnet 5.5, high) for scouting and bug review; `m5` (Opus 5.5, high) for backend work, hard bugs and duplicate review; `m6` (GPT-6.2 Astra, high) only for the hardest tasks, sparingly; `m5` for design and UI. Phase 0 and Phase 1 are approved in detail. Each later phase plan is a draft until its predecessor passes its exit gate.

**Goal:** Replace every line of Go in this repository with Rust and ship the same product: the same external contracts, every promised language semantic and every durable-ACK guarantee, proven again by the same gates.

**Architecture:** One Cargo workspace. Synchronous, thread-based cores (storage, replication stage, control apply, query execution) take an explicit `Ctx` (deadline plus cancel token), and a tokio network shell (HTTP API, peer transport, provider clients) calls them through `spawn_blocking`. The frozen Go build is the behavioural oracle: every surface that both builds expose is tested differentially, request for request.

**Tech Stack:** Rust stable, pinned in `rust-toolchain.toml` and installed offline; `x86_64-unknown-linux-musl` static release binaries; tokio, hyper/axum, rustls; raft-rs; redb; serde; vendored crates (`cargo vendor`, `--locked --offline`). The TS/Python SDKs and the React console are unchanged.

**Spec:** [design](../specs/2026-11-03-soundpost-design.md), [contracts](../specs/2026-11-03-soundpost-contracts.md), [requirements](../specs/2026-11-03-soundpost-requirements.md), decisions D1–D109 (`.superpowers/sdd/approved-product/decisions-2026-11-13.md`). Where the design says "Go", D109 overrides it. Every other obligation stands.

## Owner decisions this plan implements (D109, 2026-11-29)

| Question | Decision |
|---|---|
| The Go implementation | Frozen as the reference and test oracle. No Go 0.1.0 release. |
| Scope | All Go code: `internal/`, `cmd/`, `tools/`, `fixtures/` (Go parts), `build/`, `third_party/` Go ports. The SDKs (`packages/`, `sdk/`) and the console (`web/`) stay. |
| Data compatibility | None. Fresh on-disk and peer format version 1. 0.1.0-preview.1 installs are reinstalled. No import tool and no mixed Go/Rust cluster. |

## Global Constraints

- License: first-party code is Apache-2.0, including SSO, isolation, replay and profiling. Every crate keeps its own notice in `THIRD_PARTY_NOTICES`. No AGPL or GPL code or test corpora; LogQL implementation and tests are authored independently.
- External contracts stay byte-compatible with the frozen Go build: HTTP API paths, status codes, fault JSON (`code`, `retryable`, `detail`, `request_id`), the ingestion/artifact/replay protocol v1 (`docs/protocol/*.md`), CLI names and flags of `soundpost`, `soundpost-agent`, `soundpost-perf-acquire`, `soundpost-querycheck`, `soundpost-symbolicate`, the configuration file, and the documented behaviour in `docs/`.
- Full PromQL and LogQL semantics, matched against the locked oracle images (`conformance/query`), with 0 mismatches on the release matrix. Go RE2 behaviour (three locked editions), Go `text/template` behaviour for `line_format`/`label_format`, and Go number formatting are reproduced exactly.
- Durability: an ACK only after quorum fsync and apply. Persist comes before send and before ACK. No deferred fsync. Linearizable control reads keep their ReadIndex.
- Fault classification: a fault is retryable only when its producer knows it is transient: no leader, a lost quorum on a read fence, or an explicitly retryable refusal. Failed-closed engines, fail-stopped groups, closing nodes and untyped errors answer `retryable:false` without `Retry-After`. `Retry-After` is a random 1–3 s unless the route sets its own.
- Release binaries are static (`x86_64-unknown-linux-musl`) and reproducible from `xtask release`. Evidence is bound to the source digest of the release commit (D60). The agent also builds for Windows (`x86_64-pc-windows-msvc`) where the Go agent did.
- `#![forbid(unsafe_code)]` in every crate except the listed FFI/syscall modules: `sp-durablefs`, `sp-native` perf ring and seccomp, and the `sp-native` Windows collector. Each unsafe block carries a `// SAFETY:` comment and a test.
- Dependencies: no crate enters `Cargo.lock` without a row in `docs/support/rust-dependencies.md` (name, version, license, purpose, approver). `cargo deny check` gates CI.
- Owner rules for lab and repo: no builds or tests on the owner's Windows PC; builds and tests run on lab VMs. Commits are by `aryn@sek.su`, SSH-signed. No lab names, IPs or credentials in committed files. LF only. Red first. Flakes are defects. Never weaken a test, budget or gate row.

## Review Focus

These are the five failure classes most likely to bite a user. Each was a real defect in the Go build, and each has a test pinned to an owning task below.

1. **Power loss mid-write leaves live records unreadable.** The Go payload sweep ignored index-run references and zeroed live records after an unsynced reboot. Pinned in Task 1.3 (crash harness) and the Phase 8 power-cut drill.
2. **Raft ticks starve behind persist/apply under load, so leaders change spuriously.** Go D103. Pinned in Phase 2: persist/apply run outside the group lock from day one, and a tick-lag test runs with 200 proposers.
3. **Per-commit cost grows with total state**: whole-state rewrites for control records, rule books, snapshot windows and issue planning. Pinned in Task 1.4 (write-set bound) and in the Phase 2/5 bytes-per-commit tests, which must not grow with state size.
4. **A permanent failure answered as retryable, or a transient one as final.** Go 3178b07 / 11f21e6. Pinned in Task 1.1 (fault model) and in the Phase 3 HTTP mapping tests.
5. **Reads hold a global lock across decode or authority reads, so one slow query blocks appends and other queries.** Pinned in Task 1.6: a concurrent scan and append must not block each other.
6. **A lost proposal starves a writer under saturating intake.** Go: `Begin` and the policy write were refused or stalled when proposals from any voter were dropped under a full intake (`TestAPolicyWriteIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake`, still flaky 2/11 under -race on the frozen tree). Pinned in Phase 2: a required test where a control write completes while every voter's intake is saturated and proposals are dropped.
7. **Send or ACK before the local fsync.** Pinned in Phase 2: a required ordering test where a crash injected between persist and send/ACK never yields an ACKed entry that is absent after restart, and no message leaves before its entries are durable.

## Workspace layout and crate map

The Go tree stays in place on the rewrite branch until Phase 8, because it is the oracle. Rust lives in `crates/` and `xtask/`. The Go code is removed in one commit at the Phase 8 cutover. The branch `go-reference` keeps it forever.

| Crate (path `crates/<name>`) | Replaces Go | Owns |
|---|---|---|
| `sp-model` | `internal/model`, `link`, `privacl`, `third_party/timezone` | IDs, cursors, faults, `Ctx`, telemetry DTOs, canonical JSON and hashes, the locked timezone data |
| `sp-durablefs` | `internal/durablefs` | fsync of file and dir, atomic replace, crash-injection points |
| `sp-gofmt` | `third_party/format`, `portablemath` | Go `strconv`/`fmt` number formatting and parsing, Go `math` exp2/log |
| `sp-goregex` | `third_party/regex` (go123/124/126), `internal/query/regexcompat` | Go RE2 semantics per locked edition, Unicode tables, literal sets |
| `sp-gotemplate` | Go `text/template` behaviour, `third_party/templateprimitives` | template parse/execute with the LogQL function set |
| `sp-gojson` | `third_party/jsonparser` | byte-level JSON field extraction with LogQL `json` parser parity |
| `sp-storage` | `internal/storage` | WAL, segments, windows, indexes, payload log, scans, subscriptions, deletion/erasure, receipts, blobs, pressure |
| `sp-replica` | `internal/replica` | raft-rs groups, ready stage, mTLS transport, snapshots/cuts, membership, leader calls, ReadIndex |
| `sp-control` | `internal/control` | control state machine on per-record ledger tables, admission/settlement, authority, rules ledger, outbox records |
| `sp-auth` | `internal/auth`, `egress`, `config` | sessions, OIDC, tokens, scopes, argon2, egress policy, config file |
| `sp-ingest` | `internal/ingest`, `policy`, `sources`, `adapters` | admission path, normalisation, source fences, input adapters |
| `sp-query` | `internal/query/**`, `third_party/promhistbounds` | syntax, PromQL, LogQL, scan/value, profiles, live, scheduler, caches, native histogram bounds |
| `sp-rules` | `internal/rules`, `conditions` | rule scheduler (RuleTick), recording output, conditions |
| `sp-workflow` | `incidents`, `issues`, `jobs`, `notify`(+providers), `gitlab`, `releases`, `releaseevidence`, `retention`, `backup`, `exports`, `health` | lifecycle and notification workflow |
| `sp-artifacts` | `artifacts`, `sourcemap`, `symbolicate`, `replays`, `profiles`, `traces` | artifact bytes, sandboxed symbolication, replay chain, profile reads |
| `sp-native` | `nativeperf`, `host`, `agent` | perf acquisition, ring parsing, seccomp, host collectors (Linux, Windows) |
| `sp-httpapi` | `internal/httpapi`, `uibundle` | every HTTP route, console bundle embedding |
| `sp-app` | `internal/appcore`, `diagstat`, `smokecluster` | wiring, workers, diag page |
| `sp-conformance` | `internal/conformance` | query conformance harness and comparators |
| `soundpost`, `soundpost-agent`, `soundpost-perf-acquire`, `soundpost-querycheck`, `soundpost-symbolicate` | `cmd/*` | binaries with identical CLIs |
| `xtask` | `build/` | `source-digest`, `release`, `gate`, notices, SBOM |
| `sp-tools-smoke`, `sp-tools-qualify`, `sp-tools-pcut`, `sp-tools-drills`, `sp-tools-adoption`, `sp-tools-browserevidence`, `sp-fixtures` | `tools/*`, `fixtures/**/*.go` | harnesses, validators, gate runners, overhead and native fixtures |
| `sp-diffref` (new) | — | differential runner: the same request stream against the Go reference and the Rust build |

## Dependency candidates (approved or replaced in Task 0.4)

| Need | Candidate | License | Note |
|---|---|---|---|
| Raft | `raft` (tikv/raft-rs) with prost codec | Apache-2.0 | port of etcd raft, so same model as the Go build; production use in TiKV |
| Embedded B-tree store | `redb` | MIT OR Apache-2.0 | replaces bbolt; the payload stays in the owned append-only log |
| Async runtime / HTTP | `tokio`, `hyper`, `axum`, `tower` | MIT | network shell only |
| TLS | `rustls` + `rustls-pemfile`, crypto provider `ring` or `aws-lc-rs` | Apache/MIT/ISC (check the provider's exact terms at approval) | mTLS peer transport, HTTPS |
| Serialisation | `serde`, `serde_json`, `prost` | MIT OR Apache-2.0 | canonical JSON is owned code in `sp-model` |
| YAML config | maintained YAML crate chosen at approval, or an owned parser for the config subset | — | `serde_yaml` is archived; do not use it |
| Password hashing / crypto | `argon2`, `sha2`, `hmac`, `rand` (RustCrypto) | MIT OR Apache-2.0 | parameters copied from `internal/auth` |
| OIDC | `openidconnect` or owned code on `jsonwebtoken` | MIT | discovery, JWKS, ID-token checks as `internal/auth` does |
| SMTP / HTTP client | `lettre`, `hyper-util` client | MIT | providers |
| Syscalls / seccomp | `rustix`, `libc`, `seccompiler` | Apache-2.0 / MIT | perf_event_open, ring mmap, filters |
| CLI | `clap` (derive) | MIT OR Apache-2.0 | flags reproduced exactly |
| Tests | `proptest`, `tempfile` | MIT OR Apache-2.0 | dev only |

## Format baseline (fresh version 1)

There are no installed Rust nodes, so version 1 starts from the final designs the Go build arrived at. The upgrade machinery itself stays for later versions: declared protocol per member, expand/contract, refusing members that cannot read the layout.

- Payload in an owned append-only log (D89), with index-run references counted by the orphan sweep.
- Control state in per-record ledger tables from the start (D84, D85, D108). There is no whole-state blob form. Compact admission ops (`rsv`, `fin`), record deltas (`rec`), settlement (`stl`) and the rule ledger are the only forms.
- Scoped preconditions for login and instance scope (D102). Writer turns for whole-record writers (D107) only if a whole-record writer still exists; first try per-record preconditions.
- Snapshot cut cost proportional to the new commands (D103 follow-up), cuts pinned and staggered.
- `docs/storage/format-v1.md` is rewritten for the Rust format in Phase 1. The Go document moves to the `go-reference` branch.

## Phases and exit gates

Durations are estimates, not measurements: nothing was timed, and no Rust code exists yet. Phase 0 and Phase 1 are detailed below. Each later phase gets its own detailed plan, in this format, written when the previous phase passes its exit gate. The exit gate is the only way into the next phase.

| Phase | Builds | Exit gate | Estimate |
|---|---|---|---|
| 0 | Freeze, workspace, toolchain, vendoring, dependency ledger, `xtask`, CI | `cargo build/test/clippy/deny` green in CI and on a lab VM; `xtask source-digest` matches the documented rules | 1 week |
| 1 | `sp-model`, `sp-durablefs`, `sp-storage` single node | the ported storage behaviour tests pass, plus the crash harness at every write step, write-set and cut-cost bounds, and concurrent scan/append | 4–6 weeks |
| 2 | `sp-replica`, `sp-control` | 3-voter tests: tick-lag with 200 proposers, kill -9 rejoin, snapshot install, membership, leader calls idempotent under a dropped connection; per-commit bytes independent of state | 4–6 weeks |
| 3 | `sp-auth`, `sp-ingest`, `sp-httpapi`, `sp-app`, `soundpost` serve | `sp-diffref` shows identical responses to the Go reference for the recorded API corpus; the SDK test suites pass against the Rust server; the console e2e passes in Chromium | 4 weeks |
| 4 | `sp-gofmt`, `sp-goregex`, `sp-gotemplate`, `sp-gojson`, `sp-query`, `sp-rules`, `sp-conformance`, `soundpost-querycheck` | conformance campaign: 8/8 matrix rows, 0 mismatches; rules 100 evaluations/min under ingest | 6–8 weeks |
| 5 | `sp-workflow`, `sp-artifacts`, `soundpost-symbolicate` | differential workflow corpus identical; outbox exactly-once under crash; sandbox escape tests | 4–6 weeks |
| 6 | `sp-native`, `soundpost-agent`, `soundpost-perf-acquire` | real-kernel 6.1/6.6 runs, privacy canary, seccomp allowlist, mutation battery as for 04.02 | 3–4 weeks |
| 7 | `xtask` release/gate, all `sp-tools-*`, `sp-fixtures` | each Rust harness reproduces the Go harness verdict on the same recorded run before the Go harness is retired | 3–4 weeks |
| 8 | Qualification and cutover | single-host, distributed (1 h, kill -9, FULL read-back), queries (24 h) gates; power-cut and qm-stop drills; e2e in three browsers including headed; evidence envelopes; release notes; Go code removed | 3–4 weeks plus gate wall time |

Phases 4–6 depend only on Phase 1 (scan API) and Phase 3 (wiring), so they can run as parallel lanes. Phase 2 can run beside Phase 3 once `sp-storage` exposes its scan and append traits.

**Lab:** the current lab VMs are removed on 2026-12-06. Phases 0–1 run on any Linux VM. A 3-node lab is needed from the Phase 2 exit, and the full gate lab (3 nodes on distinct hypervisors, query host, generators, a power-cut VM) from Phase 8. Request both through the platform contact with the owner's permission, through the platform's MR process.

**Lab decision required before Phase 2:** the owner decides whether to ask for an extension of the current lab or a new lab. The request goes through the platform MR process. Phase 2 does not start on borrowed or unlisted hardware.

**Go gates never met (context for Phase 8):** the Go build never passed the distributed gate (the 1 h run with kill -9 and FULL read-back was never run; the 20 min serial run at 5k gave a p95 of 449 ms with 2 of 20 minutes ≥ 500 ms, an earlier run 614 ms; the LogQL read-back answered 504 and found 16–18% of logs, unexplained) or the queries gate (24 h never run; rules reached 103 evaluations/min against the 98 required). Phase 8 gates are first-time passes, not regressions against a passing Go baseline.

---

## Phase 0: freeze, workspace and toolchain

### Task 0.1: Freeze the Go reference

**Files:**
- Create: branch `go-reference` from the integration tree; tag `go-reference-2026-11-29`
- Create: `docs/support/go-reference.md`

**Interfaces:**
- Produces: the reference commit SHA, plus the reference binaries `soundpost` (plain and `soundpost_diag`, `soundpost_faults` builds) with their sha256, stored at a lab path named in `docs/support/go-reference.md` (no host names).

- [ ] **Step 1:** Diff `O:\integ` against its frozen copy `O:\integsnap` and list any partial edits left by the stopped IntegFix lane; keep or drop each, with the reason in the commit message. `O:\integ` is `11f21e6` plus the uncommitted admission, BeginFix, CutFix, AdmitFlakes, ctllane (rounds 1–5), qg4 (rounds 4–9) and rules lanes: 260 files (140 new, 120 modified), carrying decisions D104–D108.
- [ ] **Step 2:** Copy the integration tree over a branch made from `11f21e6`. Commit it signed, with a message that lists what is unverified: the two open flakes (`TestAPolicyWriteIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake` under -race, 2/11; `TestMixedBinaryPreviousReleaseVoterOnAFreshInstallation` 503 once, then 3/3), the unmeasured distributed and queries gates, the LogQL read-back 504 question, and the protocol-5 declaration after a rolling upgrade from 1.0.0.
- [ ] **Step 3:** Archive every stopped lane's reports in the ledger repo under `.superpowers/sdd/approved-product/go-final/<lane>/`, and commit them there signed. Sources (each under `<checkout>\.superpowers\sdd\approved-product\`): `O:\integ` (integ-report.md, integ-changed.txt), `O:\admit` (admit-report.md, admit-merge-report.md, admit-final-report.md, latgrow-report.md), `O:\admfin` (roundclimb-report.md), `O:\admbegin` (beginfix-report.md), `O:\admbegsnap` (turn-review-m4.md), `O:\admcut` (cutfix-report.md), `O:\admsnap` (admit-pcut-report.md, admit-delta-review-m4.md), `O:\admitrev` (admit-review-m4.md), `O:\ctllane` (ctllane-report.md), `O:\rules` (rules-report.md), `O:\rulessnap` (rules-review-m4.md), `O:\qg4` (qg4-report.md), `O:\qg4snap` (qg4-review-m4.md), `O:\qg8snap` (qg8-review-m4.md), `O:\dgate` (DistGate-report.md). The unbuilt paged LogQL verifier in `O:\readback` is copied as `go-final/readback/` source with a note that it was never built or run. No checkout is removed before this commit exists; `O:\vis0509` is the user's and is not touched.
- [ ] **Step 4:** Check that the conformance reference did not move: compute the sha256 of `conformance/query/source-lock.json`, `conformance/query/provenance.json` and every `conformance/query/oracles/*.Dockerfile`, and list the `sha256:` image digests they pin, on `11f21e6` and on `go-reference`. Expected: identical sets. These digests are the Rust conformance reference.
- [ ] **Step 5:** Build the three reference binaries on a VM with `go run ./build release` (plain) and the diag/faults tags. Record the sha256 and `go run ./build source-digest` in `docs/support/go-reference.md`.
- [ ] **Step 6:** Push `go-reference` and the tag through the signed-commit push guard.

### Task 0.2: Cargo workspace

**Files:**
- Create: `Cargo.toml` (workspace, `resolver = "3"`, `[workspace.lints]` with `unsafe_code = "forbid"`, `clippy::all = "deny"`), `crates/sp-model/Cargo.toml`, `crates/sp-model/src/lib.rs`, `.cargo/config.toml`
- Modify: `.gitignore` (add `/target`)

**Interfaces:**
- Produces: the `sp-model` crate skeleton; later tasks add modules.

- [ ] **Step 1: Write the failing test** `crates/sp-model/tests/workspace.rs::workspace_lints_forbid_unsafe`. It parses the root `Cargo.toml` and asserts that `workspace.lints.rust.unsafe_code == "forbid"`.
- [ ] **Step 2:** On a VM, run `cargo test -p sp-model --locked --offline`. Expected: FAIL with "no `workspace.lints` table".
- [ ] **Step 3:** Write the workspace manifest and the skeleton crate.
- [ ] **Step 4:** Run the same command. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 0.3: Pinned toolchain, offline

**Files:**
- Create: `rust-toolchain.toml` (exact stable version chosen on the day from the Rust release metadata, with components `rustfmt` and `clippy` and targets `x86_64-unknown-linux-musl` and `x86_64-pc-windows-msvc`), `xtask/src/toolchain.rs`, `docs/support/rust-toolchain.md` (also records one dated nightly, with `rust-src`, used only for the ThreadSanitizer run in Task 1.8 and never for release builds)

**Interfaces:**
- Produces: `xtask toolchain verify`, which checks that `rustc --version` equals the pinned version and that the installed archive's sha256 matches `docs/support/rust-toolchain.md`.

- [ ] **Step 1:** Test `xtask::toolchain::tests::refuses_a_different_rustc`, with a fake `rustc` printing a different version. It asserts an error naming both versions.
- [ ] **Step 2:** Run it. Expected: FAIL (function missing).
- [ ] **Step 3:** Implement `pub fn verify(rustc: &Path, pinned: &str) -> Result<(), String>`. Record the standalone installer archives (Linux gnu host plus the musl and windows target std) with sha256, and the offline install steps for the lab VMs (there is no internet on some of them).
- [ ] **Step 4:** Install on two lab VMs from the archives and run `cargo xtask toolchain verify`. Expected: `ok <version>`.
- [ ] **Step 5:** Commit.

### Task 0.4: Dependency ledger, vendoring and `cargo deny`

**Files:**
- Create: `docs/support/rust-dependencies.md`, `deny.toml` (allow MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib; deny GPL, AGPL, LGPL, unknown), `vendor/` (from `cargo vendor`), `.cargo/config.toml` source replacement, `xtask/src/deps.rs`
- Modify: `THIRD_PARTY_NOTICES`

**Interfaces:**
- Produces: `xtask deps check`, which fails if any package in `Cargo.lock` lacks a ledger row or the row's license differs from the crate's metadata. `xtask notices` regenerates `THIRD_PARTY_NOTICES` from vendored license files.

- [ ] **Step 1:** Write test `xtask::deps::tests::a_lockfile_package_without_a_ledger_row_fails`, with a two-package lock and a one-row ledger. It asserts that the error names the missing package.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement `pub fn check(lock: &str, ledger: &str) -> Result<(), Vec<String>>`. Choose each candidate from the table above; record the decision for the YAML crate and the TLS crypto provider as D110 in the decisions ledger, with the license text checked.
- [ ] **Step 4:** Run `cargo vendor`, `cargo deny check`, `cargo xtask deps check` and `cargo build --locked --offline` on a VM with no network. Expected: all green.
- [ ] **Step 5:** Commit.

### Task 0.5: `xtask source-digest` and `release`

**Files:**
- Create: `xtask/src/digest.rs`, `xtask/src/release.rs`
- Test: `xtask/tests/digest.rs`

**Interfaces:**
- Consumes: the Go `build/` source-digest rules (exclusions and ordering), read from the `go-reference` branch.
- Produces: `xtask source-digest` (prints a hex sha256 over the tracked tree under the same rules), and `xtask release --version V --out DIR`, which builds static musl binaries, embeds `web/dist`, and writes `BUILD.txt` with toolchain, digest and binary sha256.

- [ ] **Step 1:** Tests: `digest_is_independent_of_file_creation_order`; `digest_excludes_the_documented_paths` (`.superpowers`, `vendor` excluded or included exactly as the rule documents); `digest_changes_when_one_byte_of_a_tracked_file_changes`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement `pub fn source_digest(root: &Path) -> io::Result<[u8; 32]>`, and `release` with `--target x86_64-unknown-linux-musl`, `-C target-feature=+crt-static`, `--remap-path-prefix` for reproducibility.
- [ ] **Step 4:** Run the release twice on two VMs. Expected: identical binary sha256.
- [ ] **Step 5:** Commit.

### Task 0.6: CI

**Files:**
- Create: `.github/workflows/rust.yml`
- Modify: existing Go workflows: keep them running on the `go-reference` branch only

**Interfaces:**
- Produces: jobs `fmt` (`cargo fmt --check`), `clippy` (`-D warnings`), `test` (`cargo test --workspace --locked --offline`), `deny`, `deps`, `digest`, all on hosted Linux runners.

- [ ] **Step 1:** Push a branch with a deliberate clippy warning. Expected: the `clippy` job fails.
- [ ] **Step 2:** Remove the warning. Expected: all jobs green.
- [ ] **Step 3:** Commit.

---

## Phase 1: model and single-node storage

The behaviour tests of `internal/storage` (32,862 test lines in Go) are the specification. Port them by behaviour, not by wording; tests that pinned Go internals are dropped and listed in the task report. Every test named below must be shown red first.

### Task 1.1: `sp-model` core types and the fault model

**Files:**
- Create: `crates/sp-model/src/{id.rs,cursor.rs,fault.rs,ctx.rs,json.rs}`
- Test: `crates/sp-model/tests/{fault.rs,json.rs,ctx.rs}`

**Interfaces:**
- Produces:
  - `pub struct Id([u8; 16])` with lower-case 32-hex `Display`/`FromStr`, and `Id::new() -> Id` (random).
  - `pub struct Cursor { pub group: Id, pub index: u64 }`.
  - `pub enum Code { Invalid, Unauthenticated, Forbidden, Conflict, TooLarge, Unsupported, Quota, Unavailable, Timeout, Cancelled, Stale, NotFound, Corrupt }`, serialised as the Go strings (`"invalid"` … `"corrupt"`).
  - `pub struct Fault { pub code: Code, pub retryable: bool, pub detail: String, pub request_id: Id }`, with `Fault::fail(code)` (`retryable = false`) and `Fault::transient(code)` (`retryable = true`). `transient` accepts only `Unavailable`, `Stale`, `Timeout` and `Quota`, and panics in debug builds otherwise.
  - `pub struct Ctx { deadline: Option<Instant>, cancel: CancelToken }`, with `check(&self) -> Result<(), Fault>` (`Cancelled` or `Timeout`) and `child(&self, d: Duration) -> Ctx`.
  - `pub fn canonical_json(v: &serde_json::Value) -> Vec<u8>` and `pub fn hash_canonical(v) -> [u8; 32]`.

- [ ] **Step 1:** Tests:
  - `fault_json_matches_the_go_reference`: serialises `Fault { code: Unavailable, retryable: true, detail: "unavailable", request_id }` and compares it with the bytes the Go reference produced for the same values, stored as a fixture in `crates/sp-model/tests/fixtures/fault.json`.
  - `fail_is_never_retryable`.
  - `ctx_reports_timeout_after_its_deadline_and_cancelled_after_cancel`.
  - `canonical_json_is_key_sorted_and_whitespace_free_and_equals_the_go_hash` (fixtures from `go-reference` `model.HashCanonical`).
- [ ] **Step 2:** Run `cargo test -p sp-model`. Expected: FAIL (types missing).
- [ ] **Step 3:** Implement as listed.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.2: `sp-durablefs`

**Files:**
- Create: `crates/sp-durablefs/src/lib.rs` (`unsafe` allowed only for `fdatasync`/`fsync` via `rustix`, if needed)
- Test: `crates/sp-durablefs/tests/crash.rs`

**Interfaces:**
- Produces:
  - `pub fn sync_file(f: &File) -> io::Result<()>`, `pub fn sync_dir(p: &Path) -> io::Result<()>`.
  - `pub fn replace_atomically(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()>` (temp, write, fsync, rename, fsync dir).
  - `pub trait CrashPoints { fn hit(&self, point: &'static str) -> io::Result<()>; }` with `NoCrash` and `CrashAt(&'static str)` (aborts the child process at the point).

- [ ] **Step 1:** Test `replace_atomically_leaves_old_or_new_never_torn`. It runs a child process that crashes at each of `temp_written`, `temp_synced`, `renamed` and `dir_synced`, then reopens and asserts that the file equals the old or the new bytes.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run it. Expected: PASS on ext4 on a lab VM (the test is skipped on non-Linux with a printed reason).
- [ ] **Step 5:** Commit.

### Task 1.3: Payload log with crash-safe orphan sweep

**Files:**
- Create: `crates/sp-storage/src/payload/{log.rs,sweep.rs,record.rs}`
- Test: `crates/sp-storage/tests/payload_crash.rs`

**Interfaces:**
- Consumes: `sp-durablefs::{sync_file, CrashPoints}`.
- Produces:
  - `pub struct PayloadLog`, with `open(dir, &dyn CrashPoints) -> Result<Self, Fault>`, `append(&mut self, rec: &[u8]) -> Result<PayloadRef, Fault>`, `read(&self, r: PayloadRef) -> Result<Vec<u8>, Fault>` and `sync(&mut self) -> Result<(), Fault>`.
  - `pub struct PayloadRef { pub file: u32, pub offset: u64, pub len: u32, pub crc: u32 }`.
  - `pub fn sweep(log: &mut PayloadLog, live: &dyn Fn(PayloadRef) -> bool) -> Result<SweepReport, Fault>`.

- [ ] **Step 1:** Tests:
  - `a_record_referenced_only_by_an_index_run_survives_the_sweep`. This is the Go defect fixed in 6c8e3ad: the `live` closure must see index-run references; assert that the record reads back byte-equal after the sweep.
  - `power_loss_at_every_append_step_keeps_every_synced_record`: a child process crashes at each point; reopen and assert that every record synced before the crash reads back and no unsynced record reads back torn.
  - `a_crc_mismatch_is_corrupt_not_empty`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The record layout is `len:u32le | crc32c:u32le | bytes`. Recovery truncates at the first bad tail after the last synced offset.
- [ ] **Step 4:** Run them, plus 100 repetitions of the crash test. Expected: PASS 100/100.
- [ ] **Step 5:** Commit.

### Task 1.4: Metadata store and write-set bound

**Files:**
- Create: `crates/sp-storage/src/meta/{store.rs,tables.rs}`
- Test: `crates/sp-storage/tests/meta_bounds.rs`

**Interfaces:**
- Consumes: `redb`.
- Produces:
  - `pub struct MetaStore` over `redb::Database`, with typed tables `receipts`, `index_runs`, `windows`, `manifest`, `erasure` (the key and value encodings are listed in `docs/storage/format-v1.md`, rewritten in this task).
  - `pub fn commit<F: FnOnce(&mut WriteTxn) -> Result<T, Fault>>(&self, f: F) -> Result<T, Fault>` with durable commit.

- [ ] **Step 1:** Tests:
  - `bytes_written_per_ack_are_bounded_and_independent_of_history`: 1,000 versus 100,000 prior receipts; assert that the bytes written per append differ by less than 1.25×. This carries over the Go D83 bound and the `TestWrittenBytesPerAckAreBounded…` intent.
  - `a_commit_is_durable_after_return`: a child crashes right after `commit` returns, and the value is present on reopen.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. Measure written bytes through `/proc/self/io` `write_bytes` around the commit.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.5: Append, WAL, segments and windows with bounded cut cost

**Files:**
- Create: `crates/sp-storage/src/{engine.rs,append.rs,wal.rs,segment.rs,window.rs,cut.rs}`
- Test: `crates/sp-storage/tests/{append.rs,cut_cost.rs}`

**Interfaces:**
- Consumes: `PayloadLog`, `MetaStore`, `sp-model::{NormalizedBatch, Receipt, Ctx, Fault}`.
- Produces:
  - `pub struct Engine`, with `open(cfg: EngineConfig) -> Result<Arc<Engine>, Fault>`.
  - `append(&self, ctx: &Ctx, scope: &Scope, b: NormalizedBatch) -> Result<Receipt, Fault>`.
  - `lookup_receipt(&self, ctx, scope, r: ReceiptRequest) -> Result<Receipt, Fault>`.
  - `flush(&self, ctx) -> Result<(), Fault>`.
  - `close(&self) -> Result<(), Fault>`.
  - The 64 route slots exist as in the Go build (`RouteSlot: u16 < 64`).

- [ ] **Step 1:** Tests:
  - `an_acked_batch_reads_back_after_a_crash_at_every_append_step` (the crash-points harness).
  - `bytes_written_per_cut_are_proportional_to_new_commands_not_window_size`: cut after 100 and after 4,000 commands in an open window; the bytes per cut for 10 new commands are within 1.25×. This is the Go LatGrow/CutFix finding.
  - `sealing_a_window_derives_it_from_the_open_window_cache`: count the commands read at the seal ≤ the commands since the last cut.
  - `cuts_of_different_slots_are_staggered`: no two of the 64 slots cut at the same command count.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.6: Scans and subscriptions without a global lock across decode

**Files:**
- Create: `crates/sp-storage/src/{scan.rs,scan_build.rs,live.rs,slots.rs}`
- Test: `crates/sp-storage/tests/{scan_concurrency.rs,scan_toctou.rs,live_walk.rs}`

**Interfaces:**
- Produces:
  - `pub fn scan(&self, ctx: &Ctx, scope: &Scope, req: ScanRequest) -> Result<RowIterator, Fault>`.
  - `pub fn subscribe(&self, ctx, scope, req: SubscribeRequest) -> Result<ChangeIterator, Fault>`.
  - `RowIterator: Iterator<Item = Result<Row, Fault>>`, with `watermarks(&self) -> Vec<Cursor>`.
  - Scan slots and live slots are separate FIFO pools (2,048 and 32, D105). A slot is taken before any engine lock and released once on drop.

- [ ] **Step 1:** Tests:
  - `a_scan_blocked_in_decode_does_not_block_an_append_or_another_scan` (a decode hook blocks one scan for 2 s; the append and the second scan complete in < 200 ms).
  - `a_deletion_committed_before_the_release_barrier_hides_its_rows` (the three Go TOCTOU cases).
  - `a_live_walk_delivers_every_kept_row_once_after_rechunking`.
  - `an_admitted_query_mix_is_never_answered_too_large`.
  - `a_scan_waiting_for_a_slot_honours_its_deadline`.
  - `thirty_two_live_subscriptions_do_not_starve_scans`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement. The chunk build reads from a `redb` read transaction plus a copied iterator state, and never holds the engine mutex across decode or authority reads.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.7: Deletion, erasure and receipts

**Files:**
- Create: `crates/sp-storage/src/{tombstone.rs,erase.rs,erase_guard.rs,receipt.rs}`
- Test: `crates/sp-storage/tests/{erase.rs,erase_crash.rs}`

**Interfaces:**
- Produces:
  - `erase_deleted(&self, ctx, preds: &[DeletePredicate], guard: &dyn EraseGuard) -> Result<EraseReport, Fault>`.
  - `erase_expired(&self, ctx, now: UnixNano, guard) -> Result<EraseReport, Fault>`.
  - `residual_stores(&self) -> Vec<String>`.
  - Erasure zeroes payload bytes in place through `PayloadLog`, rewrites affected index runs to new files, and never edits a file in place that another name links to.

- [ ] **Step 1:** Tests:
  - `erased_bytes_are_absent_from_payload_log_index_runs_and_snapshots` (a byte scan of every file for a canary).
  - `a_crash_at_every_erase_step_converges_on_rerun`.
  - `the_guard_veto_keeps_bytes_and_reports_held`.
  - `an_erasure_after_a_hard_link_leaves_no_erased_bytes_in_the_snapshot_copy`.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run them. Expected: PASS.
- [ ] **Step 5:** Commit.

### Task 1.8: Phase 1 exit

- [ ] **Step 1:** Port every remaining behaviour test of `internal/storage` that applies to a single node. List the dropped ones, each with its reason, in `.superpowers/sdd/rust/phase1-report.md`.
- [ ] **Step 2:** Run `cargo test -p sp-storage --release` 3× and `cargo test -p sp-storage` under ThreadSanitizer (`RUSTFLAGS=-Zsanitizer=thread` on a nightly pinned separately for this check only) on a lab VM. Expected: all green, 0 reports.
- [ ] **Step 3:** Run the single-host durability drill: append load, `echo b > /proc/sysrq-trigger` on a disposable VM, 10 cycles, FULL read-back. Expected: 0 missing ACKed records.
- [ ] **Step 4:** Write the Phase 2 detailed plan in this format, as `docs/superpowers/plans/2026-11-29-rust-rewrite-phase2.md`.

---

## Later phases: obligations their detailed plans must carry

These are inputs to the phase plans, not tasks yet. Each line is a test or rule that the phase plan must assign to a task.

**Phase 2 (replication, control):**
- The ready stage persists, installs, sends, applies, then calls Advance, outside the proposer lock. Test: tick lag stays far below the election timeout with 200 proposers.
- Leader calls are idempotent. A transport failure before send maps to no-leader (retryable). After send, the failure is retryable only for idempotent calls. Test: drop the connection after the leader applies, retry, and assert no double count.
- Per-record ledger tables only. Bytes per control commit must not depend on total state, for admission, settlement, issue planning and rule commits.
- Linearizable validation (ReadIndex before validate). A deposed leader never commits an ACKed write.
- Membership guard: a member that cannot read the layout is refused.

**Phase 3 (auth, ingest, HTTP):**
- `sp-diffref` corpus: every route of `internal/httpapi`, recorded from the Go reference, replayed against both builds, normalised for IDs, times and `QueueWaitNS`/`ElapsedNS`.
- Fault mapping tests: a leader gap is 503 retryable with Retry-After 1–3 s; a failed-closed engine is 503 non-retryable; a ReadIndex quorum loss is 503 retryable; a revision `stale` keeps 400/409.
- The membership socket path stays under the platform limit. Tests use short directories.

**Phase 4 (languages):**
- `sp-goregex` is ported from the vendored Go `regexp` sources (BSD-3-Clause, notice kept) for all three editions. A differential fuzz against the Go reference binary runs 10⁶ random patterns × inputs with 0 differences.
- `sp-gotemplate` reproduces Go `text/template` including whitespace trimming, `and`/`or` short-circuit, the error texts LogQL exposes, and the function whitelist. Differential fuzz against the Go reference, 0 differences.
- `sp-gofmt` number formatting is differentially fuzzed against Go `strconv.FormatFloat` for every format the query engines use.
- The query gate's lessons are in place from the start: slot pools, admission defaults 16/8/4 (D106), a typed page decode, an index-block cache bounded and dropped on erasure, and shared range scans equal to per-step evaluation.
- Rules: an own loop with bounded project concurrency, holding 100 evaluations/min under 100 rec/s ingest.

**Phase 5 (workflow, artifacts):**
- Outbox exactly-once delivery under a crash at every step. Retries are capped at 12 attempts or 24 h, with jittered delays from 1 s to 15 min that honour provider Retry-After (contracts line 162).
- The symbolication sandbox gets escape tests (filesystem, network, process limits).
- Retention and backup restore authority: old users and tokens stay inactive after a restore.

**Phase 6 (native):**
- perf ring parsing is authored independently, with no `tools/perf` code. The seccomp allowlist includes `rseq`. The hostPID recipe stays unprivileged (D98). The privacy canary test runs on real kernels 6.1 and 6.6.

**Phase 7 (tools):**
- Each Rust validator in `sp-tools-qualify` reproduces the Go validator's verdict and figures on the same stored result directories (G12 and the drill evidence) before the Go one is retired.

**Phase 8 (qualification and cutover):**
- The gates use the validator definitions: single-host p95, distributed `healthy_strict_p95_ms` over at least two runs with FULL read-back, and queries pooled p95 with ≥ 98 evaluations/min.
- Power-cut drill with FULL read-back, a real hypervisor stop, kill -9 rejoin within 30 s.
- Console e2e in Chromium, Firefox and WebKit, including headed runs of investigation-journeys, accessibility and replay-profile.
- The Go code is removed in one commit. README, `docs/support` and the release notes are rewritten, and the release notes state the fresh format and that 0.1.0-preview.1 installs must be reinstalled.

## Risks

| Risk | Effect | Mitigation |
|---|---|---|
| Go RE2/template/number-format parity | conformance mismatches late in Phase 4 | port from the vendored Go sources first, differential fuzz from day one of Phase 4 |
| raft-rs behaviour differs from etcd raft in corner cases (PreVote, CheckQuorum, ReadIndex, learners) | election or read anomalies | Phase 2 starts with a raft-rs conformance test set derived from the Go replica tests |
| musl static builds with a C crypto provider | build friction | choose the provider in Task 0.4 with a musl build proven on a VM |
| Lab removed 2026-12-06 | Phase 2/8 blocked | owner decides on an extension or a new lab now (see "Lab decision required before Phase 2"); request through the platform MR process |
| Scale (~199k product lines, ~104k harness lines, ~314k test lines in Go) | estimate overrun | phase gates, parallel lanes after Phase 3, stop rules per phase as in the Go gate work |
