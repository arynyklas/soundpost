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
- [ ] `incidents-notifications` Incident actions, canonical urgency policy, durable fenced outbox, canonical-owner cutover (06.05, 06.06, 06.07, 06.08, 06.09). **Open: real-provider delivery is not accepted.** Provider code exists (SMTP, Telegram, webhook). A webhook was exercised once between two real VMs by the infrastructure agent: accepted, idempotent on retry, 401 on a wrong secret, egress to a forbidden destination refused. SMTP and Telegram have never been run against a real server or account (only loopback protocol fixtures). `soundpost serve` now starts the runner under the in-process system principal (owner decision D1, task 11.01) and wires the notification `Sender` (webhook, Telegram, SMTP behind the destination registry), so a served node attempts deliveries; the alert-rule stage stays off because no rule catalogue is wired (`docs/operations/background-workers.md`). What stays unproven is real delivery: SMTP and Telegram were never run against a real server or account from a served node, and no served-node delivery evidence exists for any channel. Tick only when all three channels are delivered from a served node with evidence.
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
- [ ] `evidence_language`, `evidence_runtime`, `evidence_privacy`, `evidence_node_loss`, `evidence_browser`: reports in the `soundpost-release-evidence/1` envelope (see `security.md`, "Exporters", for the producer and exporter of each), every expected row `passed`, for exactly the release commit. The only exceptions are rows out of release scope (D10) and the declared failed server SDK overhead rows whose claim the release withdraws (D65); both are reported, never passed (see the two paragraphs at the end of this file).
- [ ] `dependency_inventory`: `build/dependencies/node-licenses.json` pins the current `pnpm-lock.yaml`. Stale pins are reported, never silently refreshed; refreshing is a reviewed change.
- [ ] `licenses`: every in-scope component carries a committed license in the approved set (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, BlueOak-1.0.0, CC-BY-4.0, Python-2.0, Unlicense, MIT-0, PSF-2.0, MPL-2.0, LGPL-3.0-only). NOASSERTION blocks. PSF-2.0 (typing-extensions), MPL-2.0 (certifi) and LGPL-3.0-only (psycopg, psycopg-binary) were added by owner decision: they are Python test/optional-integration dependencies that users install from PyPI and are never vendored or redistributed in Soundpost artifacts; MPL-2.0 is file-level copyleft and LGPL-3.0 applies to the unmodified library used at runtime.
- [ ] `notices`: `THIRD_PARTY_NOTICES` equals `go run ./build notices` output and every in-scope component carries license/notice text.
- [ ] `sbom`: CycloneDX 1.5 and SPDX 2.3 generated twice with identical sha256. Both documents carry one explicit creation time, never the clock: the gate and `build sbom` need `--created YYYY-MM-DDThh:mm:ssZ` (UTC, whole seconds, the form SPDX 2.3 requires). Derive it from the release commit so every run of the same commit writes the same bytes: `TZ=UTC git show -s --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd <commit>`. `build gate` refuses a missing `--version`, `--commit` or `--created`, or a malformed `--created`, before it prints any result.
- [ ] `checksums`: `SHA256SUMS` matches every artifact and `release.json` (reproducible, `--reproduce`).
- [ ] `artifacts` (CI step `Deterministic wheel, npm packages and container image` in release.yml; not a `build gate` check): wheel, npm tarballs and image from `go run ./build artifacts --reproduce` are byte-identical across two builds (`SHA256SUMS.artifacts` and `artifacts.json` compare equal); `artifacts.json` records the `release.json` and SBOM digests it was built next to.
- [ ] `signature`: detached Ed25519 signature over the `release.json` digest verifies against the published public key (`not_signed` blocks).
- [ ] `handle_check`: npm/PyPI/Go handles checked unclaimed (`not_run` blocks). A handle this project has already published is listed in `build/owned-handles.json` with its evidence and may exist; any other existing handle blocks.
- [ ] `owner_approval`: signed owner approval for this exact version, commit and manifest digest.
- [ ] Fresh install-single and install-distributed smokes plus UI/SDK/native/reference smokes run against the produced artifacts.

The documented invocation of the machine form (`docs/releases/security.md` lists every flag):

```sh
COMMIT=$(git rev-parse HEAD)
CREATED=$(TZ=UTC git show -s --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd "$COMMIT")
go run ./build gate --version "$VERSION" --commit "$COMMIT" --created "$CREATED" --ledger tasks.json --artifacts dist/release \
  --evidence language=language.json --evidence runtime=runtime.json --evidence privacy=privacy.json \
  --evidence node_loss=node_loss.json --evidence browser=browser.json
```

Source stamp: every producer (qualify suites, query campaign, drills, the journeys and evidence smokes, and the Playwright run through `web/playwright.config.ts`) stamps its own report with `source_sha256`, the digest `go run ./build source-digest` prints for the tree it ran against. Each exporter refuses input reports whose stamps are missing or differ, and writes the shared stamp into the envelope. The gate compares that stamp with the source component of `release.json` `build_id` (`sha256:<digest>+ui:...`), and its `source` check recomputes the digest from `--root` and refuses unless it equals that component: a tree edited after `go run ./build release` blocks even when `release.json` and every envelope stamp still agree with each other. Run the gate with `--root` at the tree the release was built from. A producer run on an edited tree therefore needs a rebuilt release (`go run ./build release`), and a release built from an edited tree needs fresh producer runs.

Release commit: `go run ./build release` takes no typed commit. In a git work tree it records `HEAD`, refuses an explicit `--commit` that differs from `HEAD`, and refuses a tree with a modified or untracked file under the digested set (`cmd/`, `internal/`, `profiles/` without tests or the staged UI, plus `go.mod` and `go.sum`), because the digest would then describe bytes that `HEAD` does not contain; commit or discard first. Without a git work tree (a VM copy) it records the commit as `unknown` and refuses any typed `--commit`; such a manifest cannot match a gate run with the real `--commit`, so a publishable release is built in a git checkout. `release.yml` asserts `git rev-parse HEAD` equals the triggering SHA instead of passing it.

`release.yml` runs only the packages it names, never `./...`. Tests that self-skip on a runner without the toolchain they need (notably `cmd/soundpost` `TestServeJobDurableRetryJourney`, which skips on Windows or without `python3`) are therefore not covered by CI: run `go test ./...` on a Linux host with `python3` and record that run, with its output, in the release evidence.

PyPI license overrides (`build/dependencies/license-overrides.json`, `pypi_license`) are bound to the metadata they reviewed: every entry carries an explicit `declared` value (`NOASSERTION` when the metadata names no license) and every upstream `sources[]` entry says `wheel_text` `identical` (its sha256 must equal the committed `license_text_sha256`; the generator and `go test ./build` refuse a mismatch) or `differs` (the evidence describes how).

Release platform scope (owner decision D10, 2026-11-15): the release contains only linux/amd64, so `go run ./build release` builds `releaseevidence.ReleasePlatforms` only. Qualification rows for other platforms (linux/arm64, Windows and macOS hosts, Safari on macOS, Edge/Firefox on Windows) are reported as `out_of_release_scope` with D10 as the reason, never as passed; they never run, are listed separately from unqualified rows, and do not change the suite exit code. The gate accepts such a required row only when its detail cites D10 and its platform is not a release platform; every other non-`passed` required row still blocks, except the declared withdrawn claims below. A later release that adds a platform lists it in `release_platforms` of `qualification/matrix.yaml` and `ReleasePlatforms`, and its rows run unchanged.

Withdrawn claims (owner decision D65, 2026-11-18): the owner kept the design's 5 % budget for server SDK capture (<=5 % p95 latency/CPU increase, core capture) unchanged and the release does not claim it; the measured rows stay FAILED. `evidence_runtime` therefore accepts exactly the rows named in the closed list `releaseevidence.ClaimWithdrawals` (`soundpost-claim-withdrawals/1`): the linux/amd64 `overhead.sdk.<runtime>.linux-amd64.http-3hash` and `http-100hash` rows of Node 22, Node 24, Python 3.12, 3.13, 3.14 and Bun 1.3.14, which is every row of the matrix with runner `overhead_sdk_server` or `overhead_sdk_runtime_server` on linux/amd64 (a test pins the list to the matrix). A listed row is accepted only when it is `failed` and its structured `failure_class` is `budget_miss`. The class is a closed enum (`budget_miss`, `harness`, `dropped_records`, `assertion`, `not_run`, `unsupported`, `denied`, `out_of_scope`) that the exporter sets from the structure of the producer's result, never from the wording of the row's detail: `qualify evidence` writes `budget_miss` only for an exercised, failed row that carries no failure text and at least one measured budget that was not met, `dropped_records` when the delivered mode dropped records (also when a budget was missed as well), and `harness` for every other failed server row (the harness died, no p95 series, the measurement protocol was not followed, an unmeasurable ratio). The gate decodes the envelope strictly (an unknown or non-string `failure_class` is a malformed report) and refuses a row whose class does not fit its status (a passed row carries none, every other row carries exactly one that fits). Such a row is never `passed`: the check detail says `claim withdrawn (D65)` and names the rows, `go run ./build gate` prints one `CLAIM WITHDRAWN (D65)` line per row and lists them in the manifest `claims_withdrawn`, and the release notes MUST repeat those lines. A row that is not on the list still blocks. A listed row that is `not_run`, `not_exercised`, `unsupported`, `denied`, missing, or `failed` with any other class (harness, dropped records, assertion) still blocks however its detail reads, because the measurement must exist. The list lives in code: no report, row detail or flag can add to it, and a release that restores the claim removes the entries.
