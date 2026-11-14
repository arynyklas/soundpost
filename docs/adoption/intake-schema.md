<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Generic intake schema

Run `go run ./tools/adoption intake --targets <private-targets.json> --authorization <private-grant.json> --private-output <external-directory> --public-summary <new-summary-file>` only with environment authorization. On Windows add `--private-directory-acl-confirmed` only after the operator has restricted and verified the external directory ACL. The private filename is `intake.json` and must not already exist. Public summary also uses exclusive creation.

JSON names match the exported Go field names. Unknown fields are rejected on targets, grants and live evidence. Targets is `{ "Targets": [...] }`. Each target has `ID`, `Repository`, `ExpectedRef`, `EvidenceURL`, and optional `SecretReferences` containing only `external:` references. Repository must be an existing local Git checkout; endpoint must be an authorized HTTP(S) URL without user info, query or fragment. No arbitrary commands or request headers are accepted.

Authorization fields and semantics are specified in [authorization](authorization.md). The complete nested live DTO is `LiveEvidence` in `tools/adoption/intake.go`; HTTP endpoint returns precisely that JSON object. It must be backed by current read-only observations, not a document stating that instrumentation exists. Coverage is an explicit list of observed producers; source ordering must be explicitly inventoried. The tool records these facts but cannot prove producer truthfulness.

A private intake consists of `CollectedAt`, `GrantID`, `MaxEvidenceAgeSeconds` and `Targets`. Each collected target retains `ID`, `Repository`, `ExpectedRef`, `ObservedRef`, `EvidenceURL`, structured `Evidence`, `SecretReferences` and a discrepancy list. Secret contents have no field in this protocol. Raw bodies and credentials are never included in public output. See [evidence format](evidence-format.md) for completeness and acceptance boundaries.
