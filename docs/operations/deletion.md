<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Beginning a deletion

`POST /api/v1/admin/deletions` is the one way an operator begins a C11/C12 deletion (`retention.Service.Delete`) through the product. It is implemented in `internal/httpapi/deletion.go` and mounted by `RegisterDeletionRoutes(mux, authority, deleter)`; the polling route already existed and is not duplicated.

## Who may call it

* An organization admin of the requested `org_id`, with a **session** (cookie plus `X-CSRF-Token` and a same-origin `Origin`).
* The session must have been **freshly reauthenticated** (the same 5-minute rule `POST /api/v1/admin/commands`, server-token issue and source onboarding apply). A stale session gets `403`; reauthenticate and retry.
* Server tokens (`Authorization: Bearer`) are authenticated by the shared helper but are never fresh, so they always get `403`: a deletion cannot be begun by a machine credential.
* Scope comes from the caller's own credential for the requested organization. A non-admin member, another organization's admin and an organization that does not exist are the same `404`. Nothing is committed on any refusal.

## Request

Closed JSON (unknown fields, trailing data, bodies over 64 KiB are `400`). Revision and nanosecond fields are canonical decimal **strings**.

```json
{
  "command_id": "<32-hex id, the idempotency key and the operation id>",
  "expected_revision": "<control revision you read, decimal string>",
  "mode": "retire_org | retire_project | historical_range | entity",
  "org_id": "<id>",
  "project_ids": ["<id>"],
  "signals": ["metric"],
  "start_ns": "<decimal string>", "end_ns": "<decimal string>",
  "entity_ids": ["<id>"],
  "reason": "<required, 1-512 bytes, stored in the operation and its audit entry>"
}
```

Mode shapes are the control-store rules (`retire_project` needs projects and nothing else; `historical_range` needs projects, at least one signal and `start_ns < end_ns`; and so on). At most 128 projects, 128 entities and 16 signals.

## Response

| Status | Body | Meaning |
|---|---|---|
| `202` | `DeletionReceipt` (`phase: fencing`) | Begun. Reads of the covered data are denied **now**; the erasure is not complete. |
| `200` | `DeletionReceipt` (`phase: complete`) | Only a retry of a command that has since completed. |
| `409` | `{code:"conflict", detail:"deletion_held", receipt}` | A legal hold blocks the begin. Reads are untouched. The retry of the same `command_id` returns this same receipt. Placing/releasing holds and `Resume` have no HTTP route today (service calls only), so releasing a hold and resuming a held deletion is not possible through the product yet. |
| `409` | `{code:"conflict", detail:"deletion_failed", receipt}` | The saga ended failed (retry of an old command); `receipt.safe_reason` says why. |
| `409` | fault `conflict` | `expected_revision` is stale for a **new** command. |
| `501` | `{state:"not_available", reason:"deletion_authority_not_wired"}` | The process was built without a deletion authority. Nothing changed. |
| `400/401/403/404` | typed fault | No request text is echoed; no stack text. |

`DeletionReceipt` carries `operation_id`, `mode`, `phase`, `generation`, `revision`, `progress`, `physical`, `physical_deadline_ns`, `backup_deadline_ns`, optional `holds`, `safe_reason`, `residual_stores`. The reason text is never in a response.

A retry with the same `command_id` returns the original receipt even though the control revision has moved on. (The control store records a no-op replicated entry for the replay, so the revision still advances by one; no second saga or audit entry is created.)

## Polling

`GET /api/v1/lifecycle/operations/{operation_id}?org=<org_id>` (existing route, org-admin) reports the same operation through `PollDelete`. `202` is not erasure: completion needs every all-group fence and, when off-host backup is configured, the independent deletion-authority checkpoint (see [backup-restore.md](backup-restore.md)).

## Wiring

`internal/appcore/app.go` registers it beside the action routes:

```go
httpapi.RegisterDeletionRoutes(mux, a.Auth, a.Retention)
```
