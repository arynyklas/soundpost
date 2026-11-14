<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Off-host backup configuration and the restore-authority gate

`internal/config` decides what a configured backup may be **called**. The cryptography, the authority journal and the restore itself are `internal/backup` and are described in [backup-restore.md](backup-restore.md); this page is only the configuration contract in front of them. Nothing here changes the backup package.

## Three labels, one of which is earned

| Configured `backup.mode` | Label | Meaning |
| --- | --- | --- |
| `none` | `none` | No backup. |
| `local` | `local-recovery-copy` | A copy beside the installation. Restoring it can **resurrect data whose deletion was already acknowledged**; it is a recovery aid, never a disaster backup. No authority block changes that. |
| `offhost` | `deletion-safe-disaster-backup` | Only when every check below passes **now**. Otherwise a typed not-ready error and no label. |

A local recovery copy is never labelled deletion-safe, and an off-host backup whose authority cannot be proven is not labelled at all: it is reported not ready. That is the whole point of the page.

## What `backup.mode: offhost` requires

`config.Validate` rejects the installation unless all of this is declared (the error names the field and the rule, never the value):

* `backup.destination`: an `s3` store (HTTPS endpoint, no credentials in the URL, bucket, secret references for `access_key` and `secret_key`) or a `dir` store on a device attested (`device_id`) to be different from every node disk and not overlapping any node data path.
* `backup.authority.store`: a **second** store with the same rules that is **not** the backup destination (same bucket/prefix, same directory, or same device is refused) and, for `s3`, does **not share credentials** with the backup destination. The data node's backup credentials must not be able to rewrite the authority.
* `backup.authority.keys` (full keys, only on the signing node) and `backup.authority.restricted_keys` (read/verify only, for the restore operator): two different secret references. A backup key confers no authority.
* `backup.authority.signing_node`: the identity of exactly one member that checkpoints deletions.
* `backup.authority.capabilities`: `conditional_create`, `fresh_head` and `restricted_restore` all declared `true`. These are statements, not evidence: they are necessary and never sufficient.
* `backup.data_kek_id` and `backup.secret_kek_id`: two different identifiers; `backup.retention_days` between 1 and 30 (the manifest lifetime `internal/backup` enforces).

Secret values are never in this file. A `SecretRef` is `env:NAME`, `file:/absolute/path` or `k8s:secret/key`; a raw credential pasted where a reference belongs is rejected and is not echoed. S3 credentials come only from the environment variables `internal/backup`'s CLI reads (`SOUNDPOST_DEST_S3_*`, `SOUNDPOST_AUTHORITY_S3_*`).

## The runtime gate (`config.BackupChecker`)

`Check` returns the deletion-safe label only if, in this order:

1. the configuration validates (an invalid one never reaches the store);
2. **conditional create is proven**: `internal/backup.VerifyConditionalCreate` creates a probe object, a second create of the same name must be refused, and the first bytes must read back. A last-writer-wins store fails here (`conditional_create_failed`);
3. **a fresh head is read and fully verified** (`Authority.Current`: root signature, every record's signature, hash chain, sequence continuity, tombstone monotonicity). An uninitialised, truncated, tampered or foreign journal is `head_unavailable`, never "no deletions";
4. the head's read time is within `MaxHeadAge` (default one minute) of now and not in the future: a cached head is `head_stale`;
5. if `backup.authority.id` is configured the head names that authority (`foreign_authority`);
6. the head's sequence is not below the highest sequence this checker has already seen (`authority_rolled_back`).

Any failure is a `*config.NotReadyError` (matches `config.ErrNotReady`) carrying only a closed reason. The error text never contains the store's own message because that can name an endpoint. The consumer of `Check` must treat a not-ready result as "do not take, label or upload a backup as deletion-safe, and do not mark the installation ready for off-host backup".

`config.NewBackupProbe(dest, keys, now)` adapts the real `backup.Authority` to the narrow `config.AuthorityProbe` interface (`VerifyConditionalCreate`, `CurrentHead`). The restore operator can build it with the restricted keys.

## What is and is not verified

* Verified (unit tests and the `install-distributed` smoke): the configuration gate against the real authority on a local directory: uninitialised refused, proven store ready, last-writer-wins store refused, stale head refused, tampered journal refused and ready again after repair, local copy never labelled deletion-safe.
* **Not run:** the gate against a real S3-compatible service (conditional create on a given store is checked at runtime, not assumed); a tombstone-safe **restore through the three-member cluster** (the backup package restores into a single-voter root and seeding a three-voter cluster from a restored root is not implemented, see backup-restore.md "Not verified"); the wiring that makes the running server call `Check` before it takes a backup (the checker is a library call; the server does not construct the backup service yet).
* The single-node `go run ./tools/smoke backup-restore` smoke, which exercises the conditional HEAD advance and the tombstone-safe restore end to end, is separate evidence and is not a cluster result.
