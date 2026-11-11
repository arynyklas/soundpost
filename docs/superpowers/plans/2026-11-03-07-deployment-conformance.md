<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Deployment, Collection and Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** APPROVED for product implementation by Aryn Yklas on 2026-11-03 with m1 implementers and m2 reviewers. Commands below are acceptance instructions, not run results. Publication and customer infrastructure changes need separate authorization.

**Goal:** Ship operable single-host/distributed Soundpost, real host collection, reproducible full-language/runtime/privacy/failure evidence and verifiable Apache releases.

**Architecture:** Package the same owned engine/UI/agents for a non-HA host and three independent replicated servers. A generic synthetic application estate exercises real SDK/DB/dependency/replay/native paths. Full semantic oracles run only in isolated development/CI, never production.

**Tech Stack:** Go 1.27.3; Node 22/24 and Bun 1.3.14 qualification; CPython 3.12–3.14; Linux amd64/arm64; Compose/systemd/Kubernetes; pinned browser drivers, isolated Prometheus/Loki binaries, S3-compatible backup fixture where explicitly configured.

**Spec:** [design](../specs/2026-11-03-soundpost-design.md), [C01–C12 contracts](../specs/2026-11-03-soundpost-contracts.md). Depends on real implementations from plans01–06, not mocks.

## Global Constraints

- Entire R01–R24 product scope remains release-gated; vertical success is not complete-product success.
- All first-party functionality including SSO/replay/native profiler is Apache-2.0. Generic dependencies retain their notices; no copied AGPL LogQL implementation/corpora.
- Full language profiles are Prometheus3.1.0/3.13.5 and Loki3.5.2. No upstream HTTP/API/Sentry/OTLP product compatibility requirement or production engine fallback.
- Durable ACK survives one distributed ingest/storage node failure; minority/failed fsync cannot acknowledge; tests alone are insufficient without real-process drills.
- No private customer addresses, inventory, credentials or production changes in fixtures or default manifests. External deadman remains independent.
- Native Linux CPU/off-CPU qualification is kernel6.1/6.6 amd64/arm64 with explicit permissions and honest frame/loss/async limits.

## Review Focus

1. Shared disk/failure domain accidentally masquerades as three nodes: placement validator and actual disk-disappearance drill (Tasks2,7).
2. Missing host/source support appears as zero telemetry: capability/freshness and unknown-source rejection (Tasks3,4).
3. A green oracle suite silently skipped a flag/type or lost input: inventory coverage and exact input/result reconciliation (Task5).
4. Restore resurrects acknowledged deletion or activates old senders: current authority/fence and disabled activation (Tasks2,7).
5. Release binary/container omits paid-looking features or ships unsafe dependency/native permissions: smoke/BOM/build provenance and installation authorization checks (Tasks1,8).

---

### Task1: Reproducible distribution with real functional readiness

**Files:** Create `build/{toolchains.json,release.go}`, `deploy/{Dockerfile,compose.single.yaml}`, `deploy/systemd/{soundpost.service,soundpost-agent.service}`, `cmd/soundpost/{version,ready}.go`, `internal/health/{status,readiness}.go`, `internal/health/readiness_test.go`, `docs/operations/install-single.md`, `.github/workflows/verify.yml`.

**Interfaces:** `health.Ready(ctx,LocalState) (Readiness,error)` reports quorum/apply/disk/policy freshness/migrations, not merely listening TCP. CLI `soundpost version --json`, `soundpost ready --json`, `soundpost serve --mode=single --data-dir --listen`; embed actual UI assets from plan05. Production server targets Linux amd64/arm64. macOS/Windows SDK support does not imply server disk durability certification there.

- [ ] Write `TestReadinessRejectsNoQuorumFailedSyncAndOldSchema`: each state is unready with a safe reason; a healthy ready state exposes applied cursor/version and no credentials. Include an actual authenticated ingest/query in the distribution integration case, not a static health echo.
- [ ] Run `go test ./internal/health -run TestReadiness -count=1`; verify red behavior before implementation.
- [ ] Implement pinned compiler/archive hashes, locked module/npm/Python inputs, Linux static server+agent builds, nonroot server containers, explicit 0700 data/0600 secrets and TLS/bootstrap docs. Local Compose has persistent disk, no default password or hardcoded customer labels. Native acquisition privileges are opt-in, not server-wide root.
- [ ] Run tests and `go run ./tools/smoke install-single --artifact-dir <temp>` against the produced binary/container: bootstrap, ingest every implemented signal, query/investigate/restart, use UI assets. Expected same real data/receipt after restart and unready before storage recovery. Commit `build: Package a functional single-host distribution`.

### Task2: Real three-node deployment and deletion-safe backup configuration

**Files:** Create `deploy/compose.distributed.yaml`, `deploy/helm/soundpost/{Chart.yaml,values.yaml,templates/statefulset.yaml,templates/service.yaml,templates/secrets.yaml,templates/networkpolicy.yaml,templates/pdb.yaml}`, `internal/config/{validate,placement,backup}.go`, `internal/config/validate_test.go`, `docs/operations/{distributed,upgrade,backup-authority}.md`.

`docs/operations/distributed.md` already belongs to plan01 Task6: modify its real deployment instructions, never recreate or overwrite that earlier implementation evidence.

Task2 wires plan04's optional helper/seccomp profile into Compose/Helm rather than granting server privileges. Add `TestNativeRecipeSeparatesHelperAndServerPermissions`: server/exporter cannot perf-open; helper requires explicit PERFMON plus audited seccomp/LSM/tracefs/target visibility, no privileged/unconfined/SYS_ADMIN fallback. Verify actual runtime behavior in install-distributed/qualification, not manifest text alone. Systemd helper and Kubernetes Localhost seccomp/host-path/PID exceptions need documented operator setup; denied deployment leaves capability denied, not zero/off-CPU-complete. Record host kernel because container tags cannot supply6.1/6.6 kernels.

**Interfaces:** `config.Validate(InstallConfig) error` requires distinct durable member identities/volumes, RF3, mTLS trust, C12 restore authority capabilities when off-host backup is enabled. `InstallConfig` typed YAML has mode, nodes/failure domains, disks, listen/public origins, source policies, quotas, retention, backup/authority and optional collector grants. Safe logs redact secret references and credentials.

- [ ] Write `TestDistributedRejectsSharedIdentityOrMissingVoter` and `TestOffhostBackupRequiresAuthorityCASAndFreshHead`: invalid placement/missing authority/conditional-update failure cannot become ready. Local recovery copy must not be labeled deletion-safe disaster backup.
- [ ] Run `go test ./internal/config -run 'TestDistributed|TestOffhostBackup' -count=1`; verify red.
- [ ] Implement typed validation and three-node persistent deployment, anti-affinity/PDB/network policy, mTLS rotation, explicit failure-domain caveats and safe rolling-upgrade order. Independent volumes in local Compose are process/disk simulations, not three physical failure domains; document this distinction.
- [ ] Run tests and `go run ./tools/smoke install-distributed --artifact-dir <temp>` on actual three-process/container cluster, then an authorized isolated Kubernetes cluster. Verify RF3, read fence, readiness/leader change, backup authority conditional HEAD and tombstone-safe restore. Commit `build: Package quorum-safe distributed operation`.

### Task3: Product-owned host/system collection outside Kubernetes

Task3 additionally creates `internal/sources/scrape.go`/`scrape_test.go`: `FetchScrape(ctx context.Context,grant policy.SourceGrant,target ScrapeTarget)(ScrapeResult,error)` acquires configured OpenMetrics endpoints and feeds plan02 decoders/C03. Targets are locally approved aliases with explicit secret references/interval/deadline/size/TLS/egress policy, not telemetry-supplied URLs. `TestScrapeTimeoutStalenessAndEndpointPolicy` uses a real changing HTTP exporter, timeout/reset and refused target; assert exact admitted samples/stale markers per declared adapter policy, unknown coverage when unavailable and zero request to forbidden destination. Plan02 owns decoders; this task owns actual acquisition/scheduling and source health.

**Files:** Create `cmd/soundpost-agent/main.go`, `internal/host/{collector,linux,windows,darwin,capability}.go`, `internal/sources/{journal,syslog,file,templates,checkpoint}.go`, `internal/host/collector_test.go`, `internal/sources/privacy_test.go`, `tools/fixtures/host/`, `docs/collection/{host,system-logs,source-policies}.md`.

**Interfaces:** `host.Collect(ctx,HostPolicy) (HostBatch,Capabilities,error)` obtains safe CPU/memory/filesystem/process-count/cgroup metrics from OS primitives without commandlines/env/paths with identities. `sources.Read(ctx,SourcePolicy,Checkpoint)([]model.LogRecord,Checkpoint,error)` advances durable source checkpoint only after corresponding Admit receipt. Source adapters use plans01/C03 and plan02 normalization; do not become a second ingestion engine. Native acquisition from plan04 is separately authorized.

- [ ] Write `TestHostCapabilityMissingIsUnknown`, `TestJournalUnknownMessageNotRaw`, `TestSourceCheckpointAfterACK`, `TestRotatedFileAndDuplicateTail`: no unknown message body copied into export queue/logs; registered message templates emit typed approved fields; lost ACK/restart neither skips source records nor duplicates logical admissions. File/journal rotation and permission denial expose gaps/reasons.
- [ ] Run `go test ./internal/host ./internal/sources -run 'TestHost|TestJournal|TestSource|TestRotated' -count=1`; verify red.
- [ ] Implement native host metric acquisition per OS capability matrix and journal/syslog/file collection with structured template default and explicit restricted raw source policies. Source acquisition buffers may transiently contain source bytes; sanitize before export/spool and never persist rejected raw contents. Do not scrape commandlines/environment or assume Kubernetes metadata is required.
- [ ] Run tests and `go run ./tools/smoke host-collection --artifact-dir <temp>` on Linux VM/bare host/container, plus Windows/macOS core-agent matrix. Generate actual CPU load/filesystem change and controlled registered journal/file events; assert observed deltas/templates and denied-source capability, not non-empty arrays. Commit `feat(agent): Collect policy-bound host metrics and system logs`.

### Task4: End-to-end generic reference journeys

**Files:** Create `examples/reference/{README.md,compose.yaml}`, `examples/reference/gateway/` Bun gateway, `examples/reference/web/` maintained frontend, `examples/reference/api/` Python API, `examples/reference/jobs/` scheduler/worker, `examples/reference/dependency/` real deterministic HTTP model/dependency fixture, `tools/smoke/journeys.go`, `docs/acceptance/reference-journeys.md`.

**Interfaces:** CLI `go run ./tools/smoke journeys --artifact-dir <temp>` provisions isolated product + SDK apps + real PostgreSQL dependency; records expected event/trace/build/job IDs and captures actual admitted output. Fixtures are functioning applications with deliberate failure modes, not mock telemetry injectors. Dependency receives actual HTTP requests; absent thirdparty internals stay absent.

- [ ] Define `TestReferenceJourneyAssertions` around fixture behavior: gateway parent has real dependency child; frontend request→API→DB causes source-mapped error at expected source location/build; job run attempt1 fails, attempt2 succeeds and failed attempt remains; same trace ID in wrong org is denied. Expectations use known behavior, not source-text snapshots.
- [ ] Run `go test ./tools/smoke -run TestReferenceJourneyAssertions -count=1`; verify it fails until real trace/artifact/job integration is present.
- [ ] Implement fixture applications using custom SDKs and public source-policy setup. Browser bodies/prompts/DB SQL values include canaries that must not appear in captured payload/storage; DB span captures safe operation/dependency only. Provide exact build/source-map artifact upload and deterministic run IDs.
- [ ] Run the actual `journeys` smoke and browser actions through real frontend; inspect trace critical path, readable mapped frame, release, failed/retry history, replay masked interaction and runtime/native profile linkage with capability truth. Record all actual images/runtimes/versions. Commit `test(acceptance): Exercise real reference application journeys`.

### Task5: Release-matrix orchestration of the complete language gate

**Files:** Create `qualification/query-matrix.yaml`, `tools/qualify/query_conformance.go`, `tools/qualify/query_conformance_test.go`, `.github/workflows/conformance.yml`, `docs/compatibility/language-profiles.md`. Plan02 owns `internal/conformance/query`, `conformance/query`, `profiles/query` and `cmd/soundpost-querycheck`; reuse them, no second comparator/loader/coverage inventory.

**Interfaces:** `RunQueryConformance(ctx context.Context,matrix QueryMatrix,artifactDir string)(CampaignReport,error)` executes plan02's locked `soundpost-querycheck release/smoke` interfaces for all three profiles, registered FeatureSets, seeds and single/distributed persisted layouts. CampaignReport maps required matrix rows to verified actual reports/digests. It does not reimplement semantic comparison or convert upstream HTTP into a product contract.

- [ ] Write `TestMatrixRequiresEveryProfileFeatureSetAndArtifact`: omit a required profile/config/layout row or supply a mismatched oracle/report digest; release orchestration fails with the exact missing evidence. Existing plan02 tests own stale/histogram/duplicate/tolerance/comparator correctness; do not duplicate their same-path tests here.
- [ ] Run `go test ./tools/qualify -run TestMatrixRequires -count=1`; verify red.
- [ ] Implement complete matrix/CI orchestration over plan02 exact profile manifests/provenance/reference hashes and authored corpora. Never inherit suite-default upstream versions, skip inconvenient feature rows or author a second normalization policy.
- [ ] Run `go run ./cmd/soundpost-querycheck release --policy conformance/query/release-policy.json --all-profiles --all-feature-sets --require-locked --require-zero-unbound --require-zero-skips --require-zero-mismatches`, then actual single/distributed ingest→flush→compact→restart smoke. Aggregate all required reports; finite-corpus limits/tolerances remain explicit. Commit `test(conformance): Orchestrate complete language release evidence`.

### Task6: Runtime/privacy/overhead qualification matrix

**Files:** Create `qualification/{matrix.yaml,workloads.yaml}`, `tools/qualify/{main,runtime,browser,native,privacy,overhead}.go`, `.github/workflows/qualification.yml`, `docs/support/{runtimes,browsers,native-linux,budgets}.md`.

**Interfaces:** `tools/qualify --suite runtime|privacy|overhead --matrix <file> --report <dir>` runs actual pinned SDK/framework/browser/kernel builds. Matrix covers Python3.12/3.13/3.14 GIL builds, Node22/24, Bun1.3.14, browser core/replay and feature-detected sample capabilities, Linux6.1/6.6 amd64/arm64 native collector. Each result carries exercised/not-exercised/unsupported/denied separately.

- [ ] Write `TestQualificationCannotPromoteUnsupportedToZero` and `TestPrivacyCanaryFindsPrebufferLeak`: a Firefox/Safari unavailable sampler cannot show zero CPU; a secret materialized in the recorder/export queue fails even if network is scrubbed. Native no-stack-byte config and actual stored/exported records must both be inspected.
- [ ] Run `go test ./tools/qualify -run 'TestQualification|TestPrivacyCanary' -count=1`; verify red.
- [ ] Implement real runtime hooks/concurrency/fatal/worker/coexistence cases, canary instrumentation and measured with/without budgets from design section13. Exercise Linux CPU loops, blocked sleeps/I/O, runqueue contention, PID reuse/namespace/CPU hotplug and permission failures. Do not benchmark timers as samplers or extrapolate one architecture's pass to another.
- [ ] Required native rows reject staged `acquisition_pending` or empty-success sampler implementations; runtime-only/timer evidence cannot substitute for real native CPU/off-CPU capture. Preserve separate permission-denied/unsupported results rather than promote them to passing qualification.
- [ ] Run matrix and publish exact build IDs, raw safe measurement series, requested/observed intervals, loss/coverage and limits. A missed budget blocks the claim or needs explicit owner revision; no scope downgrade. Commit `test(qualification): Measure capture privacy coverage and overhead`.

### Task7: Pipeline outage, partitions, deletion/restore and external deadman drills

**Files:** Create `tools/drills/{main,node_loss,partition,pipeline,delete_restore,capacity}.go`, `drills/scenarios.yaml`, `docs/operations/drills.md`, `tools/fixtures/deadman/` independent observer recipe.

**Interfaces:** `go run ./tools/drills --scenario <name> --target isolated --report <dir>` requires explicit isolated target allowlist and outputs ACK ledgers/cursors/fences/policy/notification timelines. Production target execution is a separate owner action. External observer owns its own storage/runtime/destination and is not launched by the product under test.

- [ ] Write `TestDrillRefusesUnapprovedTarget`, `TestReceiptReconciliationDetectsOneMissingACK`, `TestOutageIsNotRecovery`: harness must fail on one lost acknowledged batch, unsafe target, false recovered state or overwritten failed attempt.
- [ ] Run `go test ./tools/drills -run 'TestDrill|TestReceiptReconciliation|TestOutage' -count=1`; verify red.
- [ ] Implement kill/power/disk-availability/partition/full-disk/failed-sync/slow-apply/failed-provider/outage scenarios, stale policy and all-shard delete barrier races, backup predating a completed deletion with independent authority HEAD, restore with authority unavailable (fail closed), explicit evidence-gap after retention expiry and canonical owner cutover/rollback. Verify external deadman still delivers with all Soundpost processes stopped.
- [ ] Run isolated scenarios and all three actual reference journeys after recovery. Collect every ACKed ID and compare exact retained semantic data; verify no stale worker sends/remaps source states, retries preserve ID/receipt, ACK still shows failure and material impact can notify. Commit `test(drills): Prove pipeline and single-node recovery guarantees`.

### Task8: Release gate, notices and installation verification

**Files:** Create `build/{sbom,attest,package}.go`, `.github/workflows/release.yml`, `docs/releases/{checklist,security,versioning}.md`, release notes, `THIRD_PARTY_NOTICES` once dependencies exist.

**Interfaces:** `build.Release(ctx,Commit,Reports)(ReleaseManifest,error)` requires complete plan-index coverage, language/runtime/privacy/node-loss/browser evidence, SBOM/licenses/checksums/signature metadata and no known unimplemented promised surfaces. Artifact activation/publishing requires owner release approval; public package handles are checked before publishing.

- [ ] Write `TestReleaseRejectsMissingNativeReplaySSOOrProfileEvidence` and `TestReleaseRejectsUnreviewedLicenseOrSkippedSemantics`: a working initial slice cannot pass whole-product gate; AGPL-derived source/corpus or license-unknown dependency blocks Apache distribution.
- [ ] Run `go test ./build -run 'TestReleaseRejects' -count=1`; verify red.
- [ ] Implement deterministic archives/images/wheels/npm packages, provenance/SBOM/notices, upgrade/rollback schema compatibility and safety docs. All selected functionality is in the OSS artifacts, no feature license gate. Report tested platforms/deviations precisely and no unsupported certification claims.
- [ ] Run every release artifact through fresh install-single/distributed and real UI/SDK/native/reference smoke; verify cryptographic checksums/signatures and archive contents against manifest. Publish only with explicit authorization and record resulting URLs/digests. Commit `build(release): Gate complete verifiable Apache distribution`.

## Completion evidence

Archive sanitized real command output and reports for all three journeys, every language profile, runtime/browser/kernel rows, org/project denials, node/pipeline/deletion/restore/outbox drills and full release installation. Proposed future commands are not present capabilities. Customer acceptance and production rollout remain plan08 with separate authorization.
