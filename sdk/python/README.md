# Policy-first capture

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This package implements local policy admission and bounded safe capture, not delivery, spans, integrations, jobs, replay or profiling. These later APIs are deliberately not exported. No record is acknowledged merely by entering this queue. `buffered_records()` / `bufferedRecords()` returns immutable serialized safe snapshots for the delivery layer, not raw exception objects. `close()` destroys pending records and records their loss.

## Installation trust and policy protocol

The installation supplies trusted Ed25519 public keys by key ID. Policy envelope fields are `version: 1`, `algorithm: "Ed25519"`, `key_id`, `payload`, `signature`. The last two are unpadded canonical base64url. Signature verification covers decoded exact payload UTF-8 bytes and happens before parsing policy fields. The decoded payload must equal canonical JSON: sorted object keys, compact separators, UTF-8, no duplicates, no floating/nonfinite numbers. Policy fields are `version`, `org`, `project`, `source`, `revision`, `expires_ns`, `errors`, `logs`, `replay`, `bodies`; revisions and nanoseconds are decimal strings. Bindings must match Config. Unknown keys and algorithms reject initialization. Expiration disables capture at admission, not only initialization. Trust is installation-owned, never downloaded from the signed envelope itself.

The deployment allowlist intersects policy booleans. Raw bodies are never an available capture input, even when both policy permissions allow them. Replay permission is only a decision value, not a recorder. Templates and safe identity aliases are deployment registrations; signed policy alone cannot register arbitrary content. Approved field values are exact finite primitive enums, not arbitrary strings. Unknown fields are discarded without reading their values. Template revisions must increase; buffered lines and template revisions never change.

Every template registration explicitly supplies severity from `trace | debug | info | warn | error | fatal`; it is immutable per revision and preserved in the record. Text bounds count strict UTF-8 bytes in both SDKs: identity 128, template line 4096, approved string field 256. Unpaired Unicode surrogates reject rather than silently replacing text.

## Record mirror

The SDK-local safe JSON record has `kind` (`error` or `log`), `id` (32 lowercase hex), `observed_at_ns` (exact decimal string), `policy_revision` (decimal string), and `payload`. Error payload: `occurrence_id`, `exception_class`, `code`, `build_id`, `handled`, `fatal`, `frames` (currently empty: sanitized stack extraction belongs to the next task). Non-native/hostile errors use constant `UnknownError`, never message/string conversion. Log payload: `template_id`, `template_revision`, `fields`, `line`, `severity`, `stream_labels`, `structured_metadata`, `source_class`. Every field is normalized before JSON serialization; there is no generic object serializer at the capture boundary. Queue caps are at most 1024 records and 2 MiB UTF-8, single record at most 256 KiB, exporter age 5 minutes. Diagnostics contain only fixed reason codes and counts.

## Verification (parent-run)

Python: `python -m pip install -e "sdk/python[test]"`; `python -m pytest sdk/python/tests/test_policy.py -q`; `python sdk/python/tests/smoke_policy.py`.
TypeScript: `pnpm install --frozen-lockfile`; `pnpm typecheck`; `bun test packages/core/test/policy.test.ts`; `bun packages/core/test/smoke-policy.ts`.
Qualification rows remain `not_run` until the exact target actually executes. Package availability is not support evidence.

## Dependency notice

Policy signature verification uses cryptography 50.0.0 under Apache-2.0 OR BSD-3-Clause; its third-party notices remain applicable. Exact distribution hashes and primary metadata are recorded in fixtures/sdk/qualification.json and the parent-generated requirements-dev.lock. The observed PyPI release response has an empty vulnerabilities array; that is not a claim of universal security or completed runtime qualification.
