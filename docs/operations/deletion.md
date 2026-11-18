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
| `409` | `{code:"conflict", detail:"deletion_held", receipt}` | A legal hold blocks the begin (or a resume while the hold is still active). Reads are untouched. The retry of the same `command_id` returns this same receipt. Release the hold and resume the deletion with the routes in [Holds and resume](#holds-and-resume). |
| `409` | `{code:"conflict", detail:"deletion_failed", receipt}` | The saga ended failed (retry of an old command); `receipt.safe_reason` says why. |
| `409` | fault `conflict` | `expected_revision` is stale for a **new** command. |
| `501` | `{state:"not_available", reason:"deletion_authority_not_wired"}` | The process was built without a deletion authority. Nothing changed. |
| `400/401/403/404` | typed fault | No request text is echoed; no stack text. |

`DeletionReceipt` carries `operation_id`, `mode`, `phase`, `generation`, `revision`, `progress`, `physical`, `physical_deadline_ns`, `backup_deadline_ns`, optional `holds`, `safe_reason`, `over_erased`, `residual_stores`. `over_erased` is a list of `{"book": "incident"|"condition"|"job", "count": "<n>"}`: how many opaque control states the erasure dropped without being able to show that they intersect a range deletion's window (a state that records no evidence time is erased fail-closed; see [retention.md](../privacy/retention.md), "Control state"). It is omitted when the erasure was exact, and always for a retirement or an entity deletion. The reason text is never in a response.

A retry with the same `command_id` returns the original receipt even though the control revision has moved on. (The control store records a no-op replicated entry for the replay, so the revision still advances by one; no second saga or audit entry is created.)

## Holds and resume

Decision proposed by lane 1 wave 7, recommendation: accept. The three routes below are served by the same `RegisterDeletionRoutes` call and the same `*retention.Service` (it is a `httpapi.HoldManager`), so `internal/appcore/app.go` needed no change. A process whose deleter is not a `HoldManager` answers all three `501 {state:"not_available", reason:"deletion_authority_not_wired"}`.

Admission is identical to the begin route and in the same order: credential (session with CSRF and same-origin `Origin`, or server credential), fresh reauthentication (`403`; server tokens are never fresh), availability (`501`), closed JSON body of at most 64 KiB (`400`), and only then the organization-admin authority for `org_id` (`404` for a member, another organization's admin and an organization that does not exist alike). Nothing is committed on a refusal and no request text is echoed.

| Route | Body | Success |
|---|---|---|
| `POST /api/v1/admin/holds` | `{command_id, expected_revision, org_id, project_ids?, signals?, start_ns?, end_ns?, entity_ids?, reason}` (the hold id is `command_id`; the same shape limits as a deletion) | `201 {hold_id, org_id, state:"active"}` |
| `POST /api/v1/admin/holds/{hold}/release` | `{command_id, expected_revision, org_id, reason}` | `200 {hold_id, org_id, state:"released"}` (an unknown hold or one of another organization is `404`) |
| `POST /api/v1/admin/deletions/{operation}/resume` | `{org_id}` | the begin route's answers: `202` fencing once no active hold blocks it, `409 deletion_held` while one still does |

A release never starts a held deletion by itself: the operator resumes it explicitly.

**Resume is not caller-fenced or idempotent on the wire.** Decision D47, accepted as proposed, `Service.Resume` unchanged. `resume` reads the current control revision and proposes `begin_fence` under a fresh command id, so (a) a lost response followed by a retry commits a second `begin_fence`, which the control transition answers as a no-op for an operation that is already `fencing` or `complete` (it costs one control revision and a command-log entry until the log is expired, and changes no deletion state), and (b) an authority change that lands between the read and the proposal makes the proposal `conflict` on its revision, which the operator answers by repeating the resume. A deterministic command id (for example a digest of organization, operation and a fence generation) was considered and not adopted: the command log replays the recorded outcome of a command id, and the outcome of a resume that finds a hold still active is `deletion_held`, so an id that does not change when that hold is released would replay `deletion_held` forever and make the operation unresumable; an id that does change with the holds only helps the narrow case of a retry that sees an unchanged hold set, while the case that is actually harmless today (a retry that finds the operation already `fencing`) is already a no-op. The safe shape is a caller-supplied `command_id` and `expected_revision` in the resume body, like the begin and hold routes, which is a wire change and is not part of this fix. Nothing is erased twice or early by a repeated resume.

## Polling

`GET /api/v1/operations/{operation_id}` (org-admin) is the C11 polling route and reports the operation through `PollDelete` as a `LifecycleOperation`, with or without the `?org=<org_id>` selector. Without it the control store maps the id to its owning organization (`control.DeletionOrg`, the operation records are keyed by id and name their organization), that organization is authorized for the caller as organization administrator first, and only then is the operation read; the answer is byte for byte what the `?org=` form answers. `GET /api/v1/lifecycle/operations/{operation_id}?org=<org_id>` is the older spelling of the scoped answer and stays; it still needs `org`. The same `/api/v1/operations/{id}` route also answers source-policy operations (`POST /api/v1/sources/policy`), in their own, different shape (the source fence, not `LifecycleOperation`), with or without `org`. A foreign, missing, wrongly scoped or not-administered id of either kind is the same 404 with or without `org` (an authorization refusal of the owning organization is that 404 too, so the answer never says that an id exists in an organization the caller does not administer); which store holds an id is not observable. `202` is not erasure: completion needs every all-group fence and, when off-host backup is configured, the independent deletion-authority checkpoint (see [backup-restore.md](backup-restore.md)).

The `LifecycleOperation` body is the contract C11 shape `{id, kind, phase, generation, progress, safe_reason}`: `kind` is the deletion mode (`retire_org`, `retire_project`, `historical_range`, `entity`), `phase` is `fencing`, `complete`, `held` or `failed`, `generation` is a decimal string, `progress` is the engine's own `<recorded>/64` data-slot barrier count and `safe_reason` is the static failure reason (present only when `failed`). The body also keeps the fields the web client reads: `state`, `physical`, `pending_groups`, `applied_barriers`, `holds`, `safe_fault` (the same text as `safe_reason`), the physical and backup deadlines, `over_erased` and `residual_stores`.

## Wiring

`internal/appcore/app.go` registers it beside the action routes:

```go
httpapi.RegisterDeletionRoutes(mux, a.Auth, a.Retention)
```

## Evidence: erasure on three real members (`deletion-cluster`)

Physical erasure is per voter: every member holds its own `apply.db`, segments, Raft journals and snapshots, and erases only its own copy. The receipt keeps naming `data_apply_db` in `residual_stores` until the answering member has erased and **every** member of the committed configuration has replicated an acknowledgement (see [retention.md](../privacy/retention.md)). The storage tests prove that by driving each voter's worker steps in one process. The `deletion-cluster` smoke proves it with three real `soundpost serve --mode=distributed` processes on loopback (the produced static binary, one data directory each, node files generated by `internal/config`, the seed exported from a stopped single installation, exactly as `install-distributed` provisions them):

```sh
go run ./tools/smoke deletion-cluster --artifact-dir smoke-out --binary dist/linux-amd64/soundpost --release dist
# runs: --lag-nodes 3,2,1 (default; one fresh cluster per node, the lagging voter is restarted; node 1 is the initial leader)
#       --replace-nodes 3 (default; the dead voter is replaced by a fresh identity); "none" drops either kind
#       --replace-early-nodes 3 (default none; the fresh identity joins as a learner BEFORE the deletion and holds the canary)
# --authority=false drops the real restore authority and the backup/restore leg; --wait 6m --hold-window 20s
```

Each run is a fresh cluster with its own artifact (`deletion-cluster-lag-<N>.json`, `deletion-cluster-replace-<N>.json`, `deletion-cluster-replace-early-<N>.json`). Steps, each bounded (a timeout is a typed failure naming the stage):

1. Authority (default): `backup authority-keygen`/`authority-init` against the stopped bootstrap installation and `backup keygen`; every `serve` process gets `--authority-keys` and `--authority-dir` (a directory of this host outside every node's data directory).
2. Onboard a source and ingest six batches whose metric name is a canary string into one project through node 1, and a sibling project of the same organization (own source, reader grant, marker metric). Every node serves both; a scan of every node's data directory finds both (the positive control: a later zero means something).
3. Stop the lagging voter (`SIGTERM`; killed when there is no authority) and, with the other two holding the quorum, take an older backup through its directory (`backup create --mode distributed`). With a freshly reauthenticated organization-owner session, `POST /api/v1/admin/deletions` (`retire_project`) through a live node: `202` fencing, reads denied (`404 not_found`). Poll `GET /api/v1/lifecycle/operations/{id}` until `phase: complete`, `physical: done`; the authority, read with the restricted keys, holds the tombstone of exactly that project at a head past the backup's. The sibling keeps serving its data and control rows and accepts a new sample.
4. Restart runs: the receipts of the live voters keep naming `data_apply_db` over the hold window; both live voters erase, cut a verified snapshot of every group and truncate each Raft journal (proved from the journal files: the lagging voter never journaled past the cut); the voter is restarted and the receipt is sampled from process start (a clean answer while its directory holds the canary is a false clean) until it is clean on all three nodes; the voter's journals then start past every cut (an installed snapshot) and the replicated erase notice naming it is in every `apply.db`.
5. Replacement runs: right after the begin, while the deletion is pending, `membership add-learner` for node 4 (new raft id, node identity, address, certificate, failure domain), node 4 started on an empty directory, `membership replace --remove 3 --promote 4`. The receipt is sampled from before the learner exists; node 4's directory is scanned throughout; the receipt must end clean on nodes 1, 2 and 4. The retired voter's directory still holds the canary and is outside every receipt (the operator must destroy it, [distributed.md](distributed.md) step 5): the smoke asserts that, it does not hide it.
6. Stop every node (`SIGTERM`) and scan **every regular file** of its data directory, whole, for the canary (raw and through up to five levels of nested base64): zero hits on every member; the sibling marker is still there. Restart all members: receipts still clean, a project read answers `404 not_found` and a source ingest `403 forbidden` through each, the sibling is intact and accepts a write through the returned (or replacement) voter; a second scan after another stop is still zero.
7. Restore leg (default): the older backup (it holds the canary) is restored with `backup restore` into a clean root against the current authority (the head past the backup's sequence is verified and the tombstone carried), `backup activate`, and the root is served by a real process. The recovery administrator reinstates the reader's account, membership and sibling grant; the retired project's grant cannot be reinstated (`404`), its read answers `404 not_found` and its ingest `403`, the sibling is served as of the backup, and the canary leaves the restored root (zero hits after the process ran). Between `activate` and the first start the restored root still holds the canary bytes (36 hits in `apply.db` and one Raft snapshot, denied by the barriers); the restored installation's retention worker erased them within a second of the process being ready.

Each artifact lists every assertion (name, stage, result, detail, time), every stage duration, the milestone timings, the per-node scan results and the residual-store trail. It is written on failure too, and never carries the canary, a credential or a session token.

Measured (Linux VM, one shared host, release binary of this tree): `--lag-nodes 1 --replace-nodes none` with the authority: pass, 110 assertions, 210 s (run `l1w14s-auth4`); `--lag-nodes none --replace-nodes 3`: pass, 89 assertions, 82 s (`l1w14s-rep1`); `--lag-nodes 1` without the backup leg (earlier tree): pass, 92 assertions, 197 s. In the replacement run the replacement was promoted 2 s after the begin and the receipts of nodes 1, 2 and 4 read clean 58 to 59 s after the begin; the canary was never seen on node 4's directory in 25 scans, so that run shows the receipt waiting for the membership change, not a receipt that held back a replacement still holding the canary.

Early-learner replacement run (`--replace-nodes none --lag-nodes none --replace-early-nodes 3`, with the authority, release binary of this tree; sp-w1 `l1w24` run `early3`): pass, 90 assertions, 134 s. After the older backup and with node 3 stopped, node 4 is added as a learner and started on an empty directory **while the canary is live**; the run continues only once node 4's own directory holds it (assertion `replacement_learner_holds_the_canary_before_the_deletion`: 45 hits in one scan, first seen 6.2 s in). The deletion is then begun, node 4 replaces node 3, and the receipts of nodes 1, 2 and 4 are sampled throughout: the canary was last seen on node 4's directory at 65.0 s, the first clean receipt read at 123.3 s, and no sample was a false clean. A limit of this run, stated because a mutant showed it: the receipt of this scenario is gated by the control-plane stores (`control_raft_journal`, `control_state`) until about 122 s, long after the replacement erased its copy at about 65 s, so a receipt that ignored the data plane entirely (mutant: `Engine.ErasureResidual` always clean) still passed it (run `mutB`, trail `[control_raft_journal]`, no `data_apply_db`); the data-plane acknowledgement rule for a joined voter is pinned by the storage tests, not by this run.

Not covered: independent physical hosts, disks, power or network paths (these are directories of one host); an authority or backup destination on separate hardware or S3; a container host.
