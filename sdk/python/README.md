# Policy-first capture

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This package implements local policy admission and bounded safe capture, not delivery, spans, integrations, jobs, replay or profiling. These later APIs are deliberately not exported. No record is acknowledged merely by entering this queue. `buffered_records()` / `bufferedRecords()` returns immutable serialized safe snapshots for the delivery layer, not raw exception objects. `close()` destroys pending records and records their loss.

## Installation trust and policy protocol

The installation supplies trusted Ed25519 public keys by key ID. Policy envelope fields are `version: 1`, `algorithm: "Ed25519"`, `key_id`, `payload`, `signature`. The last two are unpadded canonical base64url. Signature verification covers decoded exact payload UTF-8 bytes and happens before parsing policy fields. The decoded payload must equal canonical JSON: sorted object keys, compact separators, UTF-8, no duplicates, no floating/nonfinite numbers. Policy fields are `version`, `org`, `project`, `source`, `revision`, `expires_ns`, `errors`, `logs`, `replay`, `bodies`; revisions and nanoseconds are decimal strings. Bindings must match Config. Unknown keys and algorithms reject initialization. Expiration disables capture at admission, not only initialization. Trust is installation-owned, never downloaded from the signed envelope itself.

The deployment allowlist intersects policy booleans. Raw bodies are never an available capture input, even when both policy permissions allow them. Replay permission is only a decision value, not a recorder. Templates and safe identity aliases are deployment registrations; signed policy alone cannot register arbitrary content. Approved field values are exact finite primitive enums, not arbitrary strings. Unknown fields are discarded without reading their values. Template revisions must increase; buffered lines and template revisions never change.

Every template registration explicitly supplies severity from `trace | debug | info | warn | error | fatal`; it is immutable per revision and preserved in the record. Text bounds count strict UTF-8 bytes in both SDKs: identity 128, template line 4096, approved string field 256. Unpaired Unicode surrogates reject rather than silently replacing text.

## Record mirror

The SDK-local safe JSON record has `kind` (`error` or `log`), `id` (32 lowercase hex), `observed_at_ns` (exact decimal string), `policy_revision` (decimal string), and `payload`. Error payload: `occurrence_id`, `exception_class`, `code`, `build_id`, `handled`, `fatal`, `mechanism`, root `frames`, and `exception_graph` (`nodes`, `edges`, `reasons`). Intrinsic BaseException descriptors preserve explicit cause, unsuppressed context, suppression flags, group ordinals, shared children and cycles without invoking exception getters/str/repr. The graph is bounded to 16 nodes and 128 inspected traceback frames; overflow/filtering reasons are explicit. No messages, arguments, values, locals or source contents enter records. Log fields and queue limits remain unchanged: 1024 records/2 MiB UTF-8, 256 KiB per record, five-minute pending age.

## Safe frames, episodes and hooks

Set `Config(project_root=<absolute trusted application root>, ...)` to enable Python project-relative traceback identities. Only intrinsic traceback/frame/code fields are read; no source files, locals or globals are accessed. Frames include relative artifact/module ID, bounded function symbol, positive line, unknown column (`None`), in-app and async flags. Paths outside the lexical project root or unsafe identity syntax are omitted with `frame_not_project_safe`; no configured root reports `project_root_unconfigured`. No absolute home path is buffered.

`client.begin_handling_episode()` creates an explicit single-logical-occurrence token. `episode.capture_exception(error, code=...)` returns the same ID within that episode; `episode.close()` is idempotent and prevents further use. Create a new episode for every new logical error, even when the application reuses an exception instance. Python BaseException is not generally weakrefable: tokens retain neither raw errors nor object IDs, do not mutate user exceptions, and never infer identity from reused IDs. Temporary traversal references are explicitly cleared before extraction returns, including recursive-closure storage.

`from soundpost.hooks import install_hooks`; `lease = install_hooks(client, loop=optional_live_loop)` installs sys/threading handlers and an explicitly supplied or current running asyncio loop handler. A client owns at most eight open leases; close releases its own leases. Prior handlers are called unchanged after capture; default asyncio handling is delegated when no prior handler exists. Hooks are restored only if still owned, so subsequent application replacements survive. Overlapping leases become inert when closed; they never resume capture if a later lease restores their wrapper.

`lease.use_episode(episode, error=error, mechanism="uncaught_exception")` binds a weakrefable exception to the exact current Thread object and mechanism. Nonweak BaseException instances reject association unless the adapter explicitly supplies `explicit_rethrow=True`, acknowledging a same-thread/source immediate logical rethrow rather than claiming proven exception identity. Never use that opt-in for unrelated same-source callbacks; new logical handling needs a new token. `mechanism="thread_exception"` targets that thread's threading path. `mechanism="asyncio_exception", task=task` additionally requires this lease's exact loop and native asyncio Task and binds both weakly; missing/dead/mismatched tasks do not match. Unrelated threads/mechanisms/loops/tasks/errors capture independently and do not consume an arm. Up to eight arms are allowed; ambiguous nonweak same-source context arms reject. `lease.clear_episode(episode)` cancels pending associations; close clears them. No raw exceptions, numeric IDs or error mutations are retained. First-observation handled/fatal/mechanism stays immutable on reuse. Message-only/None-exception asyncio diagnostics increment `asyncio_missing_exception` without creating error occurrences; original prior/default handling still runs.

Shared C04 mechanisms are `manual | uncaught_exception | unhandled_rejection | thread_exception | asyncio_exception`; edge kinds are `cause | context | group` in both SDK schemas. Python None/JS nullish causes mean no edge. `fatal=True` means a process-level default-fatal observation (Python sys hook/Node monitor), not confirmed exit; prior application handlers remain authoritative. Python threading/asyncio and browser events use fatal=False because thread/task/browser reporting does not establish process termination.

## Verification (parent-run)

Python: `python -m pip install -e "sdk/python[test]"`; `python -m pytest sdk/python/tests/test_policy.py -q`; `python sdk/python/tests/smoke_policy.py`.
TypeScript: `pnpm install --frozen-lockfile`; `pnpm typecheck`; `bun test packages/core/test/policy.test.ts`; `bun packages/core/test/smoke-policy.ts`.
Qualification rows remain `not_run` until the exact target actually executes. Package availability is not support evidence.

## Dependency notice

Policy signature verification uses cryptography 50.0.0 under Apache-2.0 OR BSD-3-Clause; its third-party notices remain applicable. Exact distribution hashes and primary metadata are recorded in fixtures/sdk/qualification.json and the parent-generated requirements-dev.lock. The observed PyPI release response has an empty vulnerabilities array; that is not a claim of universal security or completed runtime qualification.
