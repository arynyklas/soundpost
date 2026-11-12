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

`GET /api/v1/operations/{operation_id}?org=<org_id>` (org-admin) is the C11 polling route and reports the same operation through `PollDelete` as a `LifecycleOperation`. `GET /api/v1/lifecycle/operations/{operation_id}?org=<org_id>` is the older spelling of the identical answer and stays. The same `/api/v1/operations/{id}` route also answers source-policy operations (`POST /api/v1/sources/policy`), in their own, different shape (the source fence, not `LifecycleOperation`), with or without `org`. A deletion id needs `org`: nothing maps a deletion id to its organization without a scope, so without `org` it is a plain 404. A foreign, missing or wrongly scoped id of either kind is the same 404; which store holds an id is not observable. `202` is not erasure: completion needs every all-group fence and, when off-host backup is configured, the independent deletion-authority checkpoint (see [backup-restore.md](backup-restore.md)).

## Wiring

`internal/appcore/app.go` registers it beside the action routes:

```go
httpapi.RegisterDeletionRoutes(mux, a.Auth, a.Retention)
```

## Evidence: erasure on three real members (`deletion-cluster`)

Physical erasure is per voter: every member holds its own `apply.db`, segments, Raft journals and snapshots, and erases only its own copy. The receipt keeps naming `data_apply_db` in `residual_stores` until the answering member has erased and **every** member of the committed configuration has replicated an acknowledgement (see [retention.md](../privacy/retention.md)). The storage tests prove that by driving each voter's worker steps in one process. The `deletion-cluster` smoke proves it with three real `soundpost serve --mode=distributed` processes on loopback (the produced static binary, one data directory each, node files generated by `internal/config`, the seed exported from a stopped single installation, exactly as `install-distributed` provisions them):

```sh
go run ./tools/smoke deletion-cluster --artifact-dir smoke-out --binary dist/linux-amd64/soundpost --release dist
# optional: --wait 6m (bound of every deletion wait; the retention worker passes once a minute) --hold-window 20s
```

Steps, each bounded (a timeout is a typed failure naming the stage, for example `stage=dc_wait_complete_node_3_down code=timeout_operation_complete_node_1`):

1. Onboard a source and ingest six batches whose metric name is a canary string into one project through node 1. Every node must serve the canary, and a scan of every node's data directory must find it (the positive control: a later zero means something).
2. Kill node 3. With a freshly reauthenticated organization-owner session, `POST /api/v1/admin/deletions` (`retire_project`) through node 1: `202` fencing, and the project's reads are already denied (`404 not_found`).
3. Poll `GET /api/v1/lifecycle/operations/{id}` on nodes 1 and 2 until `phase: complete` and `physical: done`. While node 3 is down every sample of both receipts over the hold window must still name `data_apply_db`.
4. Restart node 3 and wait until the receipt on all three nodes is clean (no residual store). At the moment each node's receipt first reads clean, its whole data directory is scanned live: zero hits.
5. Stop every node (`SIGTERM`) and scan **every regular file** of its data directory, whole, for the canary (raw and through up to five levels of nested base64, the form journals and snapshots carry it in): zero hits on every node.
6. Restart all three: the receipt is still clean on each, a project read answers `404 not_found` and a source ingest `403 forbidden` through each node, and a second scan after another stop is still zero.

`deletion-cluster.json` lists every assertion (name, stage, result, detail, time), every stage duration and the named milestone timings, the per-node scan results (files, bytes, hits by store) and the residual-store trail each receipt showed. It is written on failure too, and never carries the canary, a credential or a session token.

Measured (Linux 6.6.87.2 WSL2, i9-14900KF; the binary produced by `go run ./build release` for commit `1fd9bc1`; three passing runs, exit code 0 each, 49 assertions in each of the last two): scenario wall clock 231 s, 236 s and 180 s. The operation reached `complete` with node 3 down 131 s, 128 s and 78 s after it was begun (the retention worker passes once a minute). The receipts on nodes 1 and 2 named `data_apply_db` in all 10 of 10 samples each in the last two runs. After node 3 came back and was ready, the receipts on all three nodes were clean within 35 s, 41 s and 41 s. In every run, at the end of the 20 s hold window (the operation already `complete`, `physical: done`), one surviving voter still held the canary in its own `apply.db` and Raft journal (30 and 6 hits) and the receipt answered by that voter was naming `data_apply_db`; `physical: done` alone is therefore not a statement about every copy, the residual list is. After the stop there were zero hits in all 390 files of every node, before and after the final restart.

Not covered: independent physical hosts, disks, power or network paths (this is three directories on one host); a sibling project in the same cluster (over-erasure is covered by the in-process `delete-restore-pressure` smoke); the off-host backup authority (backup mode `none`); a container host. A node that is killed and replaced by a fresh identity while a deletion is pending is not exercised.
