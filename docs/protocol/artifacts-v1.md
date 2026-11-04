# Soundpost protected artifacts v1

Copyright 2026 Aryn Yklas. Apache-2.0.

Artifacts are inert build evidence, not a public telemetry kind or a general attachment/heap upload channel. The current implementation accepts owned source-map v3 documents and uses the existing single-voter ordered storage engine. It does not fetch runtime URLs, remote section maps, symbols, or sources. Native symbol-file decoding is not supplied by this protocol.

## Authentication and scope

The canonical endpoint is `POST /api/v1/artifacts` over HTTPS. A private server token needs the explicit `artifacts.write` or `artifacts.read` project permission and its principal's effective project grant. A browser user instead uses the existing session cookie, same-origin check and CSRF header. Source-ingest bearer credentials are write-only in their own source-ingest channel and are **not** user/server artifact credentials. Credentials never appear in query parameters.

An organization administrator has no implicit artifact or private-source read permission. Reads check exact organization/project/source/build identity and current policy, project existence, source closing/revocation state, retention and authorization epoch. The same checks precede every stream release, including bytes buffered from an earlier fragment. Hash equality does not confer authorization. The metadata key includes organization, project and immutable artifact ID; there is no unscoped hash cache.

## Upload arm

Use `multipart/form-data` with exactly two ordered parts:

1. `manifest`: strict JSON, at most 16 KiB.
2. `file`: exactly `manifest.size` source-map bytes. Its filename is ignored and never becomes a filesystem path.

Unknown or additional parts are rejected before durable admission. The total transport ceiling is 32 MiB plus bounded multipart overhead. No JSON upload arm exists.

The closed manifest is:

```json
{
  "version": 1,
  "org": "<model.ID>",
  "project": "<model.ID>",
  "source": "<model.ID>",
  "build": "<registered model.ID>",
  "debug_id": "immutable-build-debug-id",
  "generated_sha256": "<SHA-256 hex>",
  "map_sha256": "<original input SHA-256 hex>",
  "path": "dist/application.js",
  "source_content": false,
  "size": "1234",
  "retain_until_ns": "<Unix nanoseconds>"
}
```

IDs/hashes use the existing model encodings. Debug and project-relative path identities are bounded inert text; absolute paths, URL syntax, traversal, separators in debug IDs and control characters are rejected. The build must be registered in the source's current policy. A previously reserved build/debug/path binding cannot change its generated/map hash or owning source. Release display names are not artifact selectors.

The original byte count and map hash are verified in a bounded temporary upload before reservation/admission. The owned v3 decoder validates map structure, paths, indexed-map offsets, mapping budgets and local nested sections. Limits are 32 MiB expanded retained bundle, 1024 files and nesting depth 8. Unknown extensions are not retained. There is no compression/archive expansion arm.

`sourcesContent` is removed by default, including from nested sections. An explicit `source_content: true` additionally requires `raw.read` and the named source-reader grant; that data is stored as a **separate private source blob**. Ordinary map bytes never contain source content. Granting artifact map access does not grant private source/context access. Source-content policy cannot be used as a public telemetry admission kind.

A successful response is the durable reference intent: exact manifest/ID, sanitized map receipt, optional separate source receipt, fragment SHA-256/size/cursors, owning-group final cursor, and the control store's actual `control_revision` plus immutable `command_id`. No control-group Raft cursor is invented. Input `map_sha256` is the original uploaded hash; the map receipt hash is the transformed sanitized map's actual hash and may differ. Retention is explicit and never silently shortened to a credential's expiry.

## Read arm

Use `Content-Type: application/json` with the closed DTO:

```json
{
  "operation": "read",
  "org": "<model.ID>",
  "project": "<model.ID>",
  "id": "<exact immutable artifact model.ID>"
}
```

`operation` is only `read` or `sources`. Unknown fields/operations and JSON uploads are rejected. `read` returns only the sanitized map. `sources` is a separate, explicit private-content operation and additionally enforces current `raw.read` plus the named source-reader grant. No additional URL or implicit investigate kind exists.

Successful downloads are bounded JSON bytes with `Cache-Control: no-store`, `nosniff`, exact content length and a receipt-hash ETag. Content-Disposition is generated from the immutable ID, not the uploaded path. If an already-started stream loses authorization or reference authority, the connection is aborted rather than appending a successful empty result or an error-shaped JSON document. A missing retained byte is unavailable, never empty successful symbolication.

## Durable ordering, retries, and orphan cleanup

Each root has one immutable owner slot derived from organization/project/root. Sanitized map and private source blobs use that same root slot. Each private `artifact_fragment` WAL entry carries at most 256 KiB, its exact reservation/manifest/hash, ordinal and owner-group cursor. It uses the existing ordered append/write/fsync/apply/receipt path and applied cursor; it is not a second blob filesystem/database. Its source-policy epoch is checked against the existing slot barrier. Per-org/project/source charges share the existing durable quota state. An ambiguous write remains charged.

The control reference intent is committed **after** all complete byte receipts have been verified in their owner group. This is a recoverable ordered cut, not a cross-group atomic transaction. Until that control write commits, fragments are unpublished orphans and are not readable through the artifact endpoint. Retrying the exact manifest/input resumes the existing reservation and fragment cursors, then publishes the reference. A different immutable identity/hash cannot reuse a reservation.

`CancelArtifact` creates a terminal control cancellation under the same serialized authority as reference publication, only when no reference to the root exists. Its proof binds actual control revision, command ID, reservation and exact manifest. `GCUnreferencedBlob` requires that current authoritative proof and commits a private `artifact_gc` entry in the same owner slot before deleting orphan fragments. A permanent no-use fence makes replay/repeated GC idempotent. Cancellation prevents future publication/reuse. Charges are **not refunded** without a later exact cleanup-release certificate; TTL is not proof.

On reopen, private initialized markers, bucket presence, durable root/fragment/GC counts, hashes and all published references are validated. Missing retained authority fails closed instead of silently recreating it from WAL. The full authoritative bytes remain in the owning apply database and WAL. There is no automatic orphan deletion, artifact expiry deletion, artifact WAL truncation or manifest-only snapshot shortcut.

## Acceptance boundary and smoke entry

Three-voter Raft, distributed snapshots/transfers, backup reconciliation and retention release certificates remain their owning plan dependencies. This implementation does not claim distributed completeness or snapshot/replacement qualification. Future snapshot/retention integration must include every retained byte and private GC fence, preserve pending intents and referenced bytes, and must not truncate WAL based on metadata-only coverage.

The integration owner runs:

```text
node fixtures/artifacts/upload-fixture.mjs --artifact-dir <private-fixture-output>
go test ./internal/artifacts -run TestArtifact -count=1
go test ./internal/storage -run TestArtifact -count=1
go run ./tools/smoke artifact-upload --fixture-config <private-config.json> --artifact-dir <sanitized-output>
```

The public fixture entry writes a deterministic generated module, matching TypeScript source, inert v3 map and hash identity fragment outside the repository. Its sanitized mappings span multiple 256-KiB fragments; the parent adds real organization/project/source/build IDs and retention to the private manifest rather than checking credentials into a fixture.

The private config is outside the repository and contains `state_dir`, `manifest_file`, `map_file`, `uploader_token_file`, `reader_token_file`, `denied_token_file`. It references real preprovisioned project/source/build authority and an unused immutable artifact identity. Tokens are separate files, not command arguments. Use an actual source bearer as the denied credential. The smoke launches an owned child, waits for real durable fragment receipts before reference publication, kills that child, reopens the real app, proves orphan reads are denied, resumes through the canonical HTTPS endpoint, compares exact byte cursors/hashes and tests protected/denied reads. Its public report contains only hashes/cursors/statuses and the explicit single-voter boundary. Source-content fixtures additionally exercise the separate sources read with real extra grants.
