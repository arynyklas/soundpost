# Policy-first capture

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This package implements local policy admission and bounded safe capture, not delivery, spans, integrations, jobs, replay or profiling. These later APIs are deliberately not exported. No record is acknowledged merely by entering this queue. `buffered_records()` / `bufferedRecords()` returns immutable serialized safe snapshots for the delivery layer, not raw exception objects. `close()` destroys pending records and records their loss.

## Installation trust and policy protocol

The installation supplies trusted Ed25519 public keys by key ID. Policy envelope fields are `version: 1`, `algorithm: "Ed25519"`, `key_id`, `payload`, `signature`. The last two are unpadded canonical base64url. Signature verification covers decoded exact payload UTF-8 bytes and happens before parsing policy fields. The decoded payload must equal canonical JSON: sorted object keys, compact separators, UTF-8, no duplicates, no floating/nonfinite numbers. Policy fields are `version`, `org`, `project`, `source`, `revision`, `expires_ns`, `errors`, `logs`, `replay`, `bodies`; revisions and nanoseconds are decimal strings. Bindings must match Config. Unknown keys and algorithms reject initialization. Expiration disables capture at admission, not only initialization. Trust is installation-owned, never downloaded from the signed envelope itself.

The deployment allowlist intersects policy booleans. Raw bodies are never an available capture input, even when both policy permissions allow them. Replay permission is only a decision value, not a recorder. Templates and safe identity aliases are deployment registrations; signed policy alone cannot register arbitrary content. Approved field values are exact finite primitive enums, not arbitrary strings. Unknown fields are discarded without reading their values. Template revisions must increase; buffered lines and template revisions never change.

Every template registration explicitly supplies severity from `trace | debug | info | warn | error | fatal`; it is immutable per revision and preserved in the record. Text bounds count strict UTF-8 bytes in both SDKs: identity 128, template line 4096, approved string field 256. Unpaired Unicode surrogates reject rather than silently replacing text. Runtime package type exports use the owned `@soundpost/core/types` boundary.

## Record mirror

The SDK-local safe JSON record has `kind` (`error` or `log`), `id` (32 lowercase hex), `observed_at_ns` (exact decimal string), `policy_revision` (decimal string), and `payload`. Error payload: `occurrence_id`, `exception_class`, `code`, `build_id`, `handled`, `fatal`, `mechanism`, root `frames`, and `exception_graph` (`nodes`, `edges`, `reasons`). Nodes carry bounded class symbols, their safe frames and context suppression; edges preserve cause/group references including cycles and shared children. Limits are 16 nodes and 128 frames per occurrence, with explicit overflow reasons. No message, arguments, values, locals or source content are admitted. Log payload: `template_id`, `template_revision`, `fields`, `line`, `severity`, `stream_labels`, `structured_metadata`, `source_class`. Queue caps remain 1024 records/2 MiB UTF-8, 256 KiB per record, five-minute pending age. No transport or durable receipt is implemented yet.

Runtime entrypoints supply a safe native-error brand. Node/Bun use `node:util.types.isNativeError`; the browser uses intrinsic `Error.isError` only where present, otherwise reports `native_brand_unavailable` and `UnknownError`. Unknown throws/proxies are not inspected. Cause/group accessors are never invoked. JS frames currently carry `safe_original_stack_unavailable`: even a V8 own stack descriptor can trigger lazy custom formatting. Caller-stack APIs are not substituted for original error frames. Foreign/custom prototypes are reported conservatively; browser group containers without a safe proxy boundary report `safe_group_boundary_unavailable`.

## Explicit handling episodes and hook ownership

`client.beginHandlingEpisode()` returns a caller-owned token. `episode.captureException(error, options?)` captures one logical occurrence and thereafter returns its stable occurrence ID; `episode.close()` is idempotent and prevents further use. The token retains only its client and safe ID, never a raw error/stack/object ID. A token is **one logical handling episode**, not a general error identity cache: use a new token for every new occurrence, even if the application reuses the same exception instance.

`installHooks(client)` is exported by runtime packages, not installed implicitly by init. Each client permits at most eight open leases. Node/browser `lease.useEpisode(episode, error, mechanism)` arms one exact weakly referenced object identity for `uncaught_exception` or `unhandled_rejection` on that lease's native source. Primitive throws cannot be weakly identified and reject association with `weak_error_identity_required`; they still capture independently. Unrelated sources or error objects capture their own occurrences and do not consume another arm. Up to eight pending arms are permitted; `lease.clearEpisode(episode)` explicitly cancels an arm, and close clears all arms. No raw errors/object IDs are retained or user errors mutated. First-observation handled/fatal/mechanism metadata stays immutable on ID reuse. Python's explicit nonweak-source context contract is documented in sdk/python/README.md; Bun's unavailable monitor rejects arming.

### Shared C04 exception vocabulary

Both SDKs use one closed mechanism enum: `manual | uncaught_exception | unhandled_rejection | thread_exception | asyncio_exception`; graph edge kinds are `cause | context | group`. JavaScript does not invent Python context edges. Python `None` and JavaScript absent/null/undefined causes mean no cause edge/node. A present non-nullish JS non-Error cause remains a constant `UnknownError` node with `unknown_throw`, never its primitive/object value. These are the local C04 error-field spellings for the later batch/ingest mapping, not runtime-specific aliases.

`fatal` describes observation of the process-level default-fatal path, not a prediction or confirmed process exit: true for Python sys.excepthook and Node uncaughtExceptionMonitor, even if an application's prior handler/capture callback chooses to continue; false for browser reporting, Python threading and asyncio task/loop failures. A thread/task may end, but the SDK does not infer process fate from that event.

Leases preserve prior hook order/default handling, remove only owned callbacks, and are idempotent. Application-owned fatal/rejection behavior remains authoritative. Actual runtime qualification and full original/source-mapped JS exception frames remain separate unmet gates, not implied by local class capture.

## Verification (parent-run)

Python: `python -m pip install -e "sdk/python[test]"`; `python -m pytest sdk/python/tests/test_policy.py -q`; `python sdk/python/tests/smoke_policy.py`.
TypeScript: `pnpm install --frozen-lockfile`; `pnpm typecheck`; `bun test packages/core/test/policy.test.ts`; `bun packages/core/test/smoke-policy.ts`.
Qualification rows remain `not_run` until the exact target actually executes. Package availability is not support evidence.
