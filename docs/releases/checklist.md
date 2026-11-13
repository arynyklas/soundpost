<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release checklist

Every item must be ticked by evidence, never by assertion. `go run ./build gate` is the machine form of this
list and refuses to proceed while any item is open; `build/promised_surfaces.json` is the machine-readable twin
of the surface list below (the gate fails when an id here and there disagree, or a surface's tasks are not
`complete` in the plan ledger, or an `implemented_*` task is not explicitly accepted with `--accept-task`).

Nothing in this repository publishes anything. GitHub releases, npm/PyPI/Go-module publication, signing with
the real release key and the approval decision are owner actions (Aryn Yklas).

## Promised surfaces (task ids in parentheses)

- [ ] `identity-sso` Local identity, MFA/recovery, OIDC SSO, revocable sessions, audited elevation (01.01, 05.01)
- [ ] `durable-ingest` Typed admission/privacy contract; fsync-backed records with original receipts; owned segments and complete scans; org isolation (01.02, 01.03, 01.04, 01.05)
- [ ] `replicated-storage` Three-voter replicated data and control groups; durable ACK survives one node failure; snapshot repair (01.06, 01.07, 07.07)
- [ ] `retention-backup` Retention, deletion, holds, disk-pressure admission; encrypted backup/export and isolated restore (01.08, 01.09, 07.02)
- [ ] `promql` Full version-pinned PromQL (3.1.0/3.13.5) language semantics, owned engine (02.01, 02.02, 02.03, 02.04)
- [ ] `logql` Full version-pinned LogQL (3.5.2) language semantics, owned engine (02.05, 02.06, 02.07)
- [ ] `query-services` Input translators, owned execution services, live stream, fenced rule evaluation, persisted-path conformance gate (02.08, 02.09, 02.10, 02.11, 02.12)
- [ ] `sdk-capture` Policy-first Python/Node/Bun/browser capture with bounded durable delivery (03.01, 03.02, 03.03, 03.04, 03.05)
- [ ] `releases-sourcemaps` Releases, real source maps, protected artifact upload, sandboxed symbolication, artifact retention (03.06, 09.01, 09.02, 09.03, 09.04)
- [ ] `replay` Masked replay recorder, chain integrity, protected storage and inert rendering (03.07, 03.08, 05.08, 09.05)
- [ ] `runtime-profiling` Runtime supplements, capability truth, measured whole-SDK overhead and the runtime/privacy qualification matrix (03.09, 07.06)
- [ ] `native-profiler` Linux native CPU/off-CPU profiler with kernel 6.1/6.6 amd64/arm64 qualification (04.01, 04.02, 04.03, 04.04, 04.05, 04.06, 04.07, 04.08, 04.09)
- [ ] `investigation-ui` Scoped investigation, queue and incident workspace, errors/releases, metrics/logs/traces exploration, jobs, accessible end-to-end investigation (05.02, 05.03, 05.04, 05.05, 05.06, 05.07, 05.09)
- [ ] `issues-jobs-conditions` Stable grouping, issue evidence and regression, job history/health, ordered conditions (06.01, 06.02, 06.03, 06.04)
- [ ] `incidents-notifications` Incident actions, canonical urgency policy, durable fenced outbox, canonical-owner cutover (06.05, 06.06, 06.07, 06.08, 06.09). **Open: real-provider delivery is not accepted.** Provider code exists (SMTP, Telegram, webhook). A webhook was exercised once between two real VMs by the infrastructure agent: accepted, idempotent on retry, 401 on a wrong secret, egress to a forbidden destination refused. SMTP and Telegram have never been run against a real server or account (only loopback protocol fixtures). `soundpost serve` does not wire a notification `Sender`: that waits on the owner's worker-identity decision, so no delivery happens from a served node. Tick only when all three channels are delivered from a served node with evidence.
- [ ] `host-collection` Product-owned host/journal/syslog/file/scrape collection outside Kubernetes (07.03)
- [ ] `distribution` Reproducible static distribution with functional readiness; single-host and three-node installs (07.01, 07.02)
- [ ] `reference-journeys` End-to-end generic reference journeys over real SDK/DB/dependency/replay/native paths (07.04)
- [ ] `language-campaign` Release-matrix orchestration of the complete PromQL/LogQL language gate (07.05)
- [ ] `failure-drills` Pipeline outage, partitions, deletion/restore and external deadman drills with real processes (07.07)
- [ ] `cross-module-evidence` Cross-module evidence and actual-browser acceptance (09.06)
- [ ] `release-gate` Release gate, SBOM, notices, signature metadata and installation verification (07.08)

## Gate checks

- [ ] `plan_coverage`: every task in the ledger is `complete`, or an `implemented_reviewed`/`implemented_verified` task the owner accepted by id. Plan 08 (customer adoption) tasks are in the ledger and block until delivered under their own authorization.
- [ ] `promised_surfaces`: all surfaces above delivered.
- [ ] `evidence_language`, `evidence_runtime`, `evidence_privacy`, `evidence_node_loss`, `evidence_browser`: reports in the `soundpost-release-evidence/1` envelope (see `security.md`, "Exporters", for the producer and exporter of each), every expected row `passed`, for exactly the release commit.
- [ ] `dependency_inventory`: `build/dependencies/node-licenses.json` pins the current `pnpm-lock.yaml`. Stale pins are reported, never silently refreshed; refreshing is a reviewed change.
- [ ] `licenses`: every in-scope component carries a committed license in the approved set (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, BlueOak-1.0.0, CC-BY-4.0, Python-2.0, Unlicense, MIT-0, PSF-2.0, MPL-2.0, LGPL-3.0-only). NOASSERTION blocks. PSF-2.0 (typing-extensions), MPL-2.0 (certifi) and LGPL-3.0-only (psycopg, psycopg-binary) were added by owner decision: they are Python test/optional-integration dependencies that users install from PyPI and are never vendored or redistributed in Soundpost artifacts; MPL-2.0 is file-level copyleft and LGPL-3.0 applies to the unmodified library used at runtime.
- [ ] `notices`: `THIRD_PARTY_NOTICES` equals `go run ./build notices` output and every in-scope component carries license/notice text.
- [ ] `sbom`: CycloneDX 1.5 and SPDX 2.3 generated twice with identical sha256.
- [ ] `checksums`: `SHA256SUMS` matches every artifact and `release.json` (reproducible, `--reproduce`).
- [ ] `signature`: detached Ed25519 signature over the `release.json` digest verifies against the published public key (`not_signed` blocks).
- [ ] `handle_check`: npm/PyPI/Go handles checked unclaimed (`not_run` blocks).
- [ ] `owner_approval`: signed owner approval for this exact version, commit and manifest digest.
- [ ] Fresh install-single and install-distributed smokes plus UI/SDK/native/reference smokes run against the produced artifacts.
