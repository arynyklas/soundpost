<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release security model

## What the build tool does and does not do

`go run ./build` verifies, builds, summarizes and gates. It never signs, publishes, tags, uploads or contacts a
network service, except the explicit `handles` subcommand, which asks public registries whether a name is
unclaimed (it has not been run in this repository's tests). Signing keys are generated and held by the owner;
the tool contains verification code only and never reads a private key.

## Commands

- `go run ./build release --out DIR --version V --commit C --reproduce` builds static binaries, `SHA256SUMS`, `release.json`.
- `go run ./build sbom --version V --created RFC3339 --out DIR` writes `soundpost.cdx.json` (CycloneDX 1.5) and `soundpost.spdx.json` (SPDX 2.3). Output is a pure function of tracked files and `--created`; running it twice yields identical sha256. A component without a committed license record carries `NOASSERTION` and the reason; no license is ever guessed.
- `go run ./build notices [--check]` regenerates or checks `THIRD_PARTY_NOTICES`.
- `go run ./build verify-signature --manifest release.json --signature release.json.sig --public-key key.pub`.
- `go run ./build handles --out handles.json` (network; owner/CI only).
- `go run ./build gate --version V --commit C --ledger tasks.json --artifacts DIR --evidence language=... --evidence runtime=... --evidence privacy=... --evidence node_loss=... --evidence browser=... --created T [--public-key F --signature F --approval F --handle-report F] [--accept-task ID] [--json]` exits nonzero and prints every blocking item unless the release is fully verified and owner-approved.

## Signature and approval envelopes

Both are JSON, strict (unknown fields rejected), bound to the sha256 of the exact `release.json` bytes, and verified with a base64 Ed25519 PUBLIC key. The signed message is `soundpost-release/1\n<purpose>\n<payload>` with purpose `manifest` (payload: the digest) or `approval` (payload: owner, decision, version, commit, digest). The purpose prefix stops one being replayed as the other.

`soundpost-release-signature/1`: `schema, algorithm("ed25519"), key_id(sha256 hex of the public key), manifest_sha256, signature(base64)`.
`soundpost-release-approval/1`: `schema, owner, decision("approve"), version, commit, manifest_sha256, key_id, signature`.

Without a signature the gate reports `signature: not_signed`; without an approval, `owner_approval: missing`; both block.

## Evidence report envelope (`soundpost-release-evidence/1`)

Producers (07.05 language campaign, 07.06 runtime/privacy qualification, 07.07 drills, browser acceptance) write
`{"schema","kind"(language|runtime|privacy|node_loss|browser),"commit","expected_rows":[ids],"rows":[{"id","status","detail"}]}`.
Only `status: "passed"` passes. The gate recomputes the verdict from the rows (no producer-side "passed" flag exists to trust), requires every expected row to have a result, requires the commit to equal the release commit, and rejects a report that declares no expected rows. A missing file is reported by name.

### Exporters

Each producer keeps writing its own result files; a thin exporter converts them into the envelope through `internal/releaseevidence` (the same types the gate reads). An exporter never runs a producer, never decides a verdict and never changes a row's status: a row is `passed` only when the producer's own row says so, every other producer state is exported under one non-passing name with its reason, and a failing row stays failing. `expected_rows` come from a source that is independent of the exported rows (the producer's matrix, policy or manifest, or a fixed list pinned to the producer's source by a test), so a producer that drops a row also leaves it visible as `expected row X has no result`. `--commit` must be the full 40-hex release commit; the exporters cannot prove the producer ran at that commit, the operator who runs both against one checkout states it. An exporter exits 0 when the envelope was written whatever the rows say; the gate is the verdict.

| Kind | Producer | Exporter | Expected rows | Exported rows |
| --- | --- | --- | --- | --- |
| `language` | 07.05 `go run ./tools/qualify/cmd/query-campaign --artifact-dir D` | `query-campaign evidence --matrix qualification/query-matrix.yaml --campaign-report D/campaign-report.json --commit C --out F` | one per release profile of `conformance/query/release-policy.json` and matrix seed (`release/<profile>/seed/<seed>`), one per required layout (`smoke/single`, `smoke/distributed`) and `campaign/matrix` | each campaign row (`passed` iff `verified`), matched by profile/seed/layout; `campaign/matrix` is `passed` only when the report lists no missing item and no failure (policy, profile pins, FeatureSets, duplicate or unknown rows, execution errors) |
| `runtime` | 07.06 `qualify --suite runtime` and `--suite overhead` | `qualify evidence --kind runtime --matrix qualification/matrix.yaml --commit C --out F --report runtime-report.json --report overhead-report.json` | required rows of the matrix in the runtime and overhead suites | every required row, plus every exercised row that failed (the producer's own verdict counts those); `exercised`+`passed` is `passed`, `exercised`+`failed` is `failed`, `not_exercised`, `unsupported` and `denied` keep their names. Reports must come from the same matrix bytes (sha256 checked) |
| `privacy` | 07.06 `qualify --suite privacy` | `qualify evidence --kind privacy ... --report privacy-report.json` | required rows of the matrix in the privacy suite | as above |
| `node_loss` | 07.07 `drills --scenario all` (per-scenario JSON in the report directory) | `drills evidence --scenarios drills/scenarios.yaml --reports D --commit C --out F` | the scenarios `drills/scenarios.yaml` tags `evidence: node_loss` (the three-member cluster group: node kill, minority and majority pause, partition, power loss, fsync failure, disk disappearance) | `passed`, `failed`, `not_run` as the drill reported them; a `passed` report with a failed check is exported as `failed`; a drill that lists not-run parts stays `passed` with the parts named in the detail |
| `browser` | `playwright test --project=chromium --reporter=json` in real Chrome, `tools/smoke journeys` (`observed.json`) and `tools/smoke evidence` (`evidence-summary.json`) | `go run ./tools/browserevidence/cmd/browser-evidence --commit C --out F --playwright-list L --playwright-results R --journeys observed.json --evidence evidence-summary.json` | every test of `playwright test --list --reporter=json` for the project, the Playwright run row, the 14 journey rows and the 15 evidence-smoke rows (lists pinned to the smokes' source by `tools/smoke/browser_evidence_rows_test.go`) | tests: `passed` only when expected to pass, ended as expected and the last result passed (`failed`, `skipped`, `flaky`, `expected_failure`, `not_run` otherwise); smoke rows: required rows, `passed` iff `satisfied`. A result file that does not exist leaves its rows without a result |

### Browser e2e: provisioning and run

The Playwright suite in `web/e2e` reads accounts and an OIDC provider that a fresh server does not have. `web/e2e-provision/provision.spec.ts` (run through `web/playwright.provision.config.ts`, deliberately outside the suite's `testDir`) creates them through the real admin commands and writes them as `export NAME='value'` lines (mode 0600) to `PROVISION_OUT`. Per fresh server: start `soundpost serve` over trusted HTTPS with the symbolicate sandbox ready and the OIDC fixture (`web/fixtures/oidc`) trusted, bootstrap the instance owner, then

```
SOUNDPOST_TEST_ORIGIN=https://localhost:PORT SOUNDPOST_OIDC_ISSUER=https://localhost:OIDCPORT \
SOUNDPOST_SCOPE_EMAIL=<owner> SOUNDPOST_SCOPE_PASSWORD=<password> PROVISION_OUT=F \
  playwright test -c playwright.provision.config.ts --project=chromium
. F && playwright test --project=chromium --reporter=json   # the producer of the `browser` evidence rows
```

`playwright test --list` also needs those variables (the auth and elevation specs throw at load without them), so list after provisioning. The suite registers its own releases through `POST /api/v1/releases/register`, uploads a real source map through `POST /api/v1/artifacts` and ingests real error occurrences; it uses no seed route.

## Known limits

Public handle availability is only a point-in-time registry observation; it does not establish trademark clearance. The Go module path is `github.com/arynyklas/soundpost`; the handle check derives the Go handle from the `module` line of `go.mod` and asks the module proxy whether it is claimed.
