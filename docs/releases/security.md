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
Only `status: "passed"` passes. The gate recomputes the verdict from the rows (no producer-side "passed" flag exists to trust), requires every expected row to have a result, requires the commit to equal the release commit, and rejects a report that declares no expected rows. A missing file is reported by name. The existing 07.05 campaign report is not in this envelope; a thin exporter belongs to its owner.

## Known limits

Public handle availability is only a point-in-time registry observation; it does not establish trademark clearance. The Go module path is `soundpost`, which is not a fetchable public module path, so the handle check marks it `invalid` until the owner chooses a published path.
