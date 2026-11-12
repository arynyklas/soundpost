# Encrypted backup, independent deletion authority and isolated restore

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

This describes task 01.09 (`internal/backup`, `internal/auth/restore.go`, `cmd/soundpost/backup.go`, `tools/smoke/backup.go`). It builds on the C12 cuts of task 01.07 (`docs/operations/recovery.md`) and the deletion saga of task 01.08. It is local-process evidence on one non-HA node. It is not a power-loss, distinct-hardware or at-scale qualification, and nothing below claims a backup-based single-node RPO.

## What is and is not claimed

* **Disaster RPO is the last complete verified backup.** Everything ACKed after that backup's data cut is lost with the node. The numbers in "Measured RPO" describe one local drill; they are not a target, a cadence or a guarantee. The proposed cadence (30-minute snapshots, daily backup, weekly restore drill) is still unmeasured.
* Node-loss RPO of zero holds only inside the three-voter model (two durable copies), never from a backup of a single node.
* An off-host backup without the deletion authority below can be a local recovery copy; it is **not** deletion-safe disaster recovery, and `backup.New` refuses to be built without one.
* Uploading a backup never evicts, truncates or rewrites a local retained replica. `Destination` has no delete or overwrite primitive and no access to the local store.

## Moving parts

| Piece | Where | Role |
| --- | --- | --- |
| Backup service | `internal/backup/restore.go` (`Service.Run`, `Service.Backup`) | C/H capture, pinned post-H journal, sealed data cut D, encrypted export, authenticated manifest |
| Encryption | `internal/backup/encrypt.go` | AES-256-GCM chunked objects, per-object keys, wrapped per-bundle data keys |
| Manifest | `internal/backup/manifest.go` | hashes, sizes, cursors, retention/deletion bindings, gap attestations, key IDs |
| Destinations | `internal/backup/object.go` | local directory and S3-compatible bucket behind one `Destination` interface |
| Deletion authority | `internal/backup/authority.go` | independent, signed, hash-chained deletion ledger with a conditional monotonic HEAD |
| Restore | `internal/backup/restore.go` (`Restorer.Restore`, `Activate`) | verify, install into a clean root, quarantine, arm activation |
| Reconciliation | `internal/backup/reconcile.go` | quota certificate applied to control, gap re-verification |
| Restore auth | `internal/auth/restore.go` | quarantine of every pre-restore privilege, audited reconciliation, instance scope |
| CLI | `cmd/soundpost/backup.go` | `soundpost backup ...` |
| Drill | `tools/smoke/backup.go` | `backup-restore` smoke |

## Bundle format and encryption

A backup is a set of objects under one prefix in a `Destination`:

```
backups/<id>/key/<id>-data        wrapped data key (JSON; ciphertext only)
backups/<id>/key/<id>-keys        wrapped key-material key
backups/<id>/obj/bundle           storage.BackupBundle (C12 replay and quota certificates, cut C, 64 snapshot manifests)
backups/<id>/obj/control-state    control seed without its key files and without any restore quarantine stash
backups/<id>/obj/control-keys     the control envelope key files (class "keys")
backups/<id>/obj/slot-00..63      the 64 verified slot snapshot streams
backups/<id>/manifest.json        written last
```

The manifest is created only after every object was uploaded, read back from the destination and its ciphertext hash checked, so a backup exists exactly when its manifest does. Orphan objects of an interrupted backup have no manifest and are never restorable.

* **Cipher.** AES-256-GCM in 1 MiB chunks (STREAM construction). Each object has its own key: HKDF-SHA256 over the bundle data key, a fresh random 16-byte salt and the object context (backup ID, object name, class). Chunk nonces are the chunk counter plus a final-chunk flag, so no key ever sees a repeated nonce and chunks cannot be reordered, dropped, duplicated or truncated at a chunk boundary. The object context is also the GCM additional data: an object copied under another name, backup or class does not authenticate.
* **Keys.** Two independent per-bundle data keys: one for data and control state, one for the control envelope key files ("backups encrypt keys separately"). Each is wrapped under its own key-encryption key (KEK) held outside the destination (`KeyDir` files with mode 0600, or any `KeyProvider`; a KMS adapter implements the same interface). The two KEK IDs must differ. The wrapped keys are separate destination objects. The manifest records key IDs and KEK IDs only, never material; `Key` formats as its ID and refuses to marshal.
* **Manifest authentication.** The manifest is plain JSON plus an HMAC-SHA256 under a key derived from the data KEK. A wrong key, an edited manifest and a substituted manifest all fail before any object is opened. Every object is additionally checked against the plaintext and ciphertext SHA-256 and sizes in the manifest.
* **Rotation.** A new backup uses whatever KEK IDs the service is configured with; old backups name their own KEK IDs, so retiring a KEK is an explicit decision about which backups remain restorable. Nothing rotates implicitly.
* **Expiry.** A manifest expires at most 30 days after its cut (`Config.Retention` cannot exceed it) and `Restore` refuses an expired backup. Deleting expired objects from a destination is the destination's lifecycle policy; this package never deletes.

## The deletion authority (C12 restore authority)

The authority is a journal on a `Destination` that is **not** the data volume and whose write credentials the data node need not share with the backup destination:

```
authority/ROOT                  signed anchor: authority ID, installation ID, signing key ID
authority/head/<20-digit seq>   record seq: previous record digest, generation, the WHOLE current
                                deletion ledger and its exact tombstones (AES-256-GCM sealed),
                                Ed25519 signature
```

* **Conditional monotonic HEAD.** HEAD is the highest sequence. Advancing it is a create-if-absent of `seq+1` (`If-None-Match: *` on S3, hard-link on a directory), so two writers cannot both advance from one head, nothing is ever overwritten, and every earlier generation stays retained and immutable. A new ledger must contain every tombstone already in the head; a ledger the head already covers is answered with the head's receipt and writes nothing; anything else is a conflict.
* **Verified write.** `CheckpointDeletion` returns only after the record was read back byte for byte and the whole chain re-verified. Any failure is an error with no receipt, so retention leaves the deletion in the **fencing** phase, never complete (task 01.08 maps any authority error to that). The ingest path does not touch the authority.
* **Verified read.** `Current` verifies the root signature, every record's signature and canonical encoding, the hash chain, sequence continuity, generation order, tombstone monotonicity and the sealed payload digest. A missing root, a gap, a flipped byte, a record from another chain, a stray object or the wrong keys is an error: an unverifiable authority is never read as "no deletions".
* **Destination requirements.** Strong read-after-write and list consistency, and atomic create-only writes. `Authority.Initialize` runs `VerifyConditionalCreate` (create, refused second create, read back) against the destination and refuses one that is last-writer-wins. Enable bucket versioning and object lock on S3 for defence in depth; the journal does not depend on them. Verification of the conditional-create probe against a real S3 service has not been run (see "Not verified").
* **Key separation: old decryption keys confer no authority.** The authority has its own Ed25519 signing key and AES sealing key (`AuthorityKeys`). A backup KEK decrypts backup data and cannot write, roll back, forge or even verify the journal. Restore needs only `AuthorityKeys.Restricted()` (sealing key plus the trusted public key): it can read and verify, never write. The signing seed lives only on the node that checkpoints deletions.
* **Rollback detection.** Every manifest records the authority ID, sequence, generation and head digest it was taken under. Restore refuses an authority that belongs to another installation, is behind that sequence, or whose chain does not contain that head digest. Truncating the journal's tail below a backup's binding is therefore detected for any backup taken after it; truncating below the newest backup's binding on an installation that never takes another backup is not detectable from the data alone, which is why the authority belongs on storage with its own immutability controls.
* **Metadata exposure.** Tombstones are sealed, so the authority store learns object sizes and timing but not which organizations, projects or ranges were deleted.

## Taking a backup

`Service.Run(ctx, scope, dest)`:

1. The caller's `auth.Scope` must be an `InstanceScope` (fresh authentication, enabled instance admin, audit committed before the scope exists, 15-minute lifetime); it names no organization and cannot read telemetry.
2. Control state is captured once (`ReplicationSeed` behind a linearizable `View`); the cut C and its reservations are derived **from that same seed**, so the stored control state and the data cut name one revision. The current authority head is read and checked against every completed deletion's authority receipt in that state (a rolled-back or forked authority fails the backup).
3. H is each group's processed highwater from the injected `Processed` source. `AppliedProcessed` (each group's applied cursor) is correct only for a build with no lifecycle projection; an installation with projections must supply their checkpoints.
4. **IMP-1 (pin leaks).** A durable attempt marker is written and fsynced **before** `BeginBackup`. The driver then always seals or aborts: `Abort` runs in a defer on every path including panics and cancellation. A seal that fails because privacy deletion touched pinned evidence restarts from a new cut (three tries). `Service.Reap` is the startup reaper: for attempts with no outcome it drops the pins reported by a consumer-owned `PinReaper` (`Pins() ([]Pin, error)`, `DropPin(id string) error`; the replica group accessors will be adapted to it), then marks the attempts reaped. A pin that cannot be dropped keeps its attempt open and fails; pins with no incomplete attempt are reported, never dropped; without a `PinReaper` an incomplete attempt stays open and `Reap` fails.
5. **IMP-3 (self-asserted gaps).** The driver declares to `Backup.Seal` only evidence gaps that are committed control facts (`RecordEvidenceGap`) in the captured state, at or before the cut (a fact naming a group the installation does not own makes the control state untrusted and stops the backup before anything is pinned). Only the gaps the sealed certificate actually used are attested in the manifest, each with fact ID, interval, reason, the control revision it was verified at and the digest of the fact.
6. The sealed snapshots, bundle, control state and key files are encrypted, uploaded and read back; the manifest is written last.

## Restoring

`Restorer.Restore(ctx, manifest, root, ledger)` order is the contract:

1. `root` must not exist or be an empty directory; all work happens in a sibling `<root>.restore-<random>` staging directory that is renamed into place only after everything verified. A failed restore removes it and creates nothing.
2. The manifest authenticates under the data KEK and has not expired.
3. **Current deletion ledger, before any backup data is read.** `ledger.Current` is read from the authority and verified against the manifest's binding (authority, installation, sequence, generation, head digest in the chain). Unavailable, unverifiable, foreign, rolled-back or absent authority fails closed. This happens before keys are unwrapped and before any `obj/` object is opened.
4. The wrapped data keys are unwrapped (a wrong, missing or retired KEK fails here, still before data).
5. The snapshot generation fence (`SnapshotStore.RequireGeneration`) is armed in the staging store before any snapshot bytes are read, with the backup's snapshot generation. Note this is the storage `TombstoneGeneration` counter; the authority ledger generation is the control deletion counter, a different counter, and is applied through the ledger itself.
6. Every object is fetched, decrypted and verified against the manifest; the object set must be exactly the bundle, the two control objects and 64 slots. A missing object is `unavailable`, never silently omitted.
7. The bundle is bound to the manifest (digests, cursors, identity), `storage.ReconcileQuota` authenticates the certificates, the control state is bound to the manifest and to the bundle's cut (same installation, revision and reservations), and **every gap is re-verified** (`verifyGaps`): each `gap` interval needs an attestation, each attestation needs a fact in the control state at the cut with the same group, exact interval, reason and digest, verified at the cut's revision, with nothing left over on either side. A widened, shifted, duplicated, unattested or unbacked gap is rejected.
8. The 64 snapshots are installed with `Engine.InstallBackup` (intake closed until the quota certificate and deletion ledger are applied). Reservations created after C are rebuilt whole from the batches inside the sealed snapshots so their idempotency keys exist.
9. The control state is installed through the real replicated control path, in one update: any quarantine stash the source installation's own earlier restore left in it is discarded, then **quarantine** (below), the quota certificate (exactly one charge per consumed reservation, refunds for committed cancellation fences, pending intents kept charged), after rotating the control envelope key (old keys stay decrypt-only) and sealing a fresh bearer hash key.
10. A fresh one-time recovery bootstrap token is written to `<root>/bootstrap.token` (mode 0600; never printed or logged: `soundpost serve` on a restored root says where the file is instead of printing the token) and `restore.json` (certificate, the authority position this restore verified, no secrets) is written.

`Activate(ctx, root, target, ledger)` runs against the opened restored installation: it commits the quota certificate, re-reads the **current** deletion ledger (a deletion may have completed since `Restore`) and checks it against the authority position `Restore` verified (`restore.json` records that head's authority, sequence, generation, digest and tombstone count; an older journal, or one that does not contain that head, is `conflict`), applies exactly that head (control import plus a tombstone barrier in all 64 slots) and only then lets the engine open. Until it succeeds the engine serves no read and admits no write. It is idempotent after a crash.

The root is opened with `appcore.OpenForActivation`, which differs from `appcore.Open` in one respect: while the restore hold is armed it does not run the artifact-reference validation (it reads blob bytes through the engine, which refuses everything until the hold lifts, so on a good restore it could only fail and the root could never be activated). `appcore.App` is the `Activation`; its `RestoreReady` runs that validation immediately after the hold is lifted. A root whose hold is already lifted validates at open like any other.

### Failure matrix (covered by tests, except where a row says otherwise)

| Condition | CLI code | Result |
| --- | --- | --- |
| No ledger, authority unavailable or unverifiable (flipped byte, gap, stray record, wrong keys) | `unavailable` | restore fails before any data object is opened; no root created |
| Authority of another installation, another authority ID, behind the backup's sequence, generation or tombstone count, or whose chain does not contain the head the backup was taken under (a fork or a truncated journal) | `conflict` | restore fails before any data object is opened; no root created |
| Authority rolled back or replaced between `restore` and `activate` (older than the position `restore` verified, or not containing it) | `conflict` | activation refused before anything is applied; the root stays closed |
| The authority ledger names an organization or project the restored control state never contained (created and retired after the backup's cut) | none (succeeds) | activation completes; the tombstone is recorded as a deny predicate, no organization is created, and the retired organization and project IDs can never be created in the restored installation |
| Backup taken under an authority that forgot a completed deletion (control's receipt names a head the journal does not contain) | `corrupt` | no backup is written |
| Wrong data KEK (the manifest MAC does not verify) | `forbidden` | fails before any other object is opened |
| Retired or absent KEK | `not_found` | fails before any data object is opened |
| Wrong key-material KEK, or a missing or altered wrapped key | `corrupt` | fails before any data object is opened |
| Key file or key directory readable by group or others (POSIX) | `forbidden` | the key is not read (nor written by `keygen`) |
| Missing snapshot or control object | `unavailable` | fails; no root, no staging directory |
| Truncated, bit-flipped or swapped snapshot or control object | `corrupt` | fails; no root, no staging directory |
| Manifest edited | `forbidden` | the MAC does not verify; nothing else is opened |
| Backup expired (more than 30 days after its cut) | `stale` | never restored |
| Existing non-empty root | `conflict` | refused, untouched |
| Gap interval without a committed fact, widened or forged attestation | `corrupt` | rejected at restore |
| Authority write fails, or reads back differently | `unavailable` | no receipt; deletion stays `fencing`; backups and restores are refused while it is down |
| Root with artifact reference intents | none (succeeds) | `activate` opens the root without validating artifact bytes (the closed engine cannot serve them) and validates them right after the restore hold is lifted. A blob that then fails to verify fails the activation with `corrupt` (by construction of that validation; **not exercised by a test**, only the success path is) |
| Installation that never admitted a batch | none (succeeds) | backs up and restores like any other |

`soundpost backup ...` prints one line per failure, `soundpost backup failed: <code>` plus the approved detail and `[retryable]` when the fault says so, with exit status 1. The text of an error that is not a typed fault is withheld (it can name a path), usage mistakes print the usage text, and no line ever contains a key, a secret or an input value. Every other command keeps its single generic line.

## Bootstrap-only auth: nothing old becomes active

`auth.QuarantineRestoredState` runs inside the restore's control update. It is deterministic and one-shot on a given state (a second application over a state that already carries its stash conflicts). It is applied to what is ACTIVE in the state being restored, which is not always an installation's first generation: see "Restoring a restored installation's own backup" below.

* every session, elevation and in-flight OIDC state is removed; every server token is revoked; every source credential digest is removed and every active source is revoked; the bearer hash key is replaced by a fresh one sealed under the fresh envelope key, so no digest stored before the restore can match any credential presented afterwards;
* every account is disabled (passwords, TOTP and recovery codes stay stored but cannot be used by anything);
* every organization's members, admins, grants, teams, SSO and destination (sender) settings and secrets, and the named-source reader lists are moved out of the active structures into one stash, and the organization epoch is bumped so every scope, cache entry and cursor minted before dies;
* a fresh one-time bootstrap is armed. The recovery admin created from it is a new account with a new ID: a fresh login restores **no** former grant, however the email or password matches an old account.

Old decryption keys decrypt stored secrets and nothing else. The restored installation therefore cannot send notifications (no sender is configured; the restore itself performs no external effect) and cannot accept a source credential issued before the restore.

`Service.Reconcile` is the only way an item leaves the stash. It takes one explicit `Reconciliation` (account, org admin, membership, grant, team, integration, source reader, source), a reason, and a fresh-authenticated instance admin who is not a restored account; the audit record is committed in the same transaction. Each item is single-use and reinstated as of the backup, nothing is widened. Reauthorizing an account grants nothing by itself (its membership and grants are separate items), two enabled accounts may not share a login, and a source is reissued a **new** credential (the old secret is never revived). Server tokens and sessions are never reinstated; they are reissued through the normal flows. Logout, token revocation or demotion performed after the backup cannot be undone by a restore: the restore reinstates nothing on its own, so the administrator decides item by item with current identity information.

### Restoring a restored installation's own backup (second generation)

A restored installation takes its own nightly backups like any other, and in a second disaster that is the only surviving copy. The quarantine stash is the bookkeeping of the restore that built the installation, not installation data, so:

* `Service.Backup` writes the control state without the stash, and `Restore` discards one if a backup (for example one taken by an older build) still carries it, before it quarantines.
* The new generation quarantines what is **active** in the state it restores: the accounts the previous generation reauthorized (and its recovery admin), the source credential it reissued, the grants and memberships it reinstated, and so on. All of it is inactive again and must be reauthorized by the new generation's recovery admin; nothing minted in any earlier generation (sessions, server tokens, source credentials, passwords of disabled accounts) authenticates.
* Items an earlier generation never reconciled are not carried across: they stay inactive and the new generation cannot reconcile them (the older backup that holds them is the way to look at them again). Dropping them can only leave more inactive, never reactivate anything. This is a deliberate, conservative choice; merging the old stash is possible but widens what a second recovery admin can reinstate.
* The operator may bootstrap the new recovery admin with the same address as the previous one: it is a new account with a new ID and holds nothing.

`TestABackupOfARestoredInstallationRestoresAgain` and the second half of the `backup-restore` smoke exercise exactly this (fresh install, backup, restore, activate, reauthorize one user, backup, restore again, activate).

## Commands

```
soundpost backup keygen --key-dir DIR --id ID
soundpost backup authority-keygen --out FILE --id ID [--restricted-out FILE]
soundpost backup authority-init (--data-dir DIR | --installation ID) --authority-keys FILE --authority-dir DIR
soundpost backup create --data-dir DIR --admin-email EMAIL --key-dir DIR --data-kek ID --secret-kek ID \
     --authority-keys FILE --authority-dir DIR --dest-dir DIR       # password: SOUNDPOST_ADMIN_PASSWORD
soundpost backup list --dest-dir DIR
soundpost backup restore --backup-id ID --root DIR --key-dir DIR --authority-keys FILE \
     --authority-dir DIR --dest-dir DIR
soundpost backup activate --root DIR --authority-keys FILE --authority-dir DIR
```

S3-compatible destinations use `--dest-s3-endpoint/-region/-bucket/-prefix` and `--authority-s3-*`; credentials come only from `SOUNDPOST_DEST_S3_ACCESS_KEY/SECRET_KEY` and `SOUNDPOST_AUTHORITY_S3_ACCESS_KEY/SECRET_KEY`, endpoints must be HTTPS. `create`, `activate` and `authority-init --data-dir` open the installation exclusively, so the server must be stopped; taking a backup from the running server is the same library call (`Service.Run`) and needs the server to construct the service (not wired by this task).

Operating the authority: initialize it once when enabling off-host backup (`authority-init`), pass the same destination and the full keys to the process that runs `retention.Config.Authority`, keep the full key file only on that node, and hand `--restricted-out` keys plus the destination read access to the restore operator. Reading the restricted key file is enough to restore; it cannot checkpoint.

## Measured RPO and timings (one local drill)

`tools/smoke/backup.go` (`go run ./tools/smoke backup-restore --artifact-dir <dir>`) drives a live installation process over HTTPS while the backup copies, ACKs more batches after the seal, completes a historical-range deletion (which only completes after the authority checkpointed it), kills the process, restores into a clean root, serves the root from a second clean process and compares results. Three consecutive runs on one WSL/Linux host, one local disk, loopback only, built through a temporary overlay registration (artifacts `backup-restore.json`, no secrets, ACK ledger hashes below). The host was shared with other test jobs (load average about 5 on 32 CPUs), which is the only explanation offered for the spread; it was not investigated further.

| Measurement | Run A | Run B | Run C |
| --- | --- | --- | --- |
| Batches ACKed before / during / after the backup | 40 / 71 / 10 | 40 / 126 / 10 | 40 / 143 / 10 |
| Backup duration (67 encrypted objects, tiny data set) | 2.5 s | 15.8 s | 17.9 s |
| Of the batches ACKed during the copy: restored / not restored | 45 / 26 | 45 / 81 | 75 / 68 |
| Restore duration / activation | 2.3 s / 0.45 s | 9.2 s / 1.9 s | 11.0 s / 2.1 s |
| Disaster after the backup's control cut (loss window of the drill) | 5.8 s | 31.2 s | 34.6 s |
| ACKed after the backup finished (lost by design) | 10, all re-admitted on client retry | 10 | 10 |
| ACK ledger SHA-256 | `585814a0...eca3` | `55ae9d01...1c4d` | `a91245b4...2d92` |

Identical in every run: every batch ACKed before the backup started is present after restore except the 10 inside the deleted range (30 of 30); 0 rows of the deleted range are served; 0 batches ACKed after the backup finished are present before their clients retry; every retry of a batch the backup held returns a byte-identical receipt (85, 85 and 115 retries, including the deleted batches' original receipts); a new write inside the deleted range is refused (HTTP 409); the old source credential is refused (HTTP 403) before activation, after activation and after the recovery admin's reconciliation; no sender is configured and 0 notifications are sent by the restore.

The data cut D falls somewhere inside the copy window, so a batch ACKed during the copy may or may not be in the backup (the middle row). Treat the durations as the shape of three small runs on a shared host, not as throughput, size or time-to-restore data: the data set is tiny, the disk is local and nothing was measured under production load. They support exactly one claim: **disaster RPO is the last complete verified backup**, i.e. everything ACKed after the backup's data cut is lost with the node.

## Not verified / open items

* S3-compatible destination: tested against an in-process fake that enforces `If-None-Match`, signs-header presence and pagination, and the SigV4 signer against the published AWS test vector. It has not been run against a real S3 service or MinIO, so conditional-create support of a given store is checked at `authority-init` time by `VerifyConditionalCreate`, not assumed.
* Restore targets a single-voter root (the production single-node layout). Seeding a three-voter cluster from a restored root is not implemented here.
* A distributed node's data directory is refused, not backed up: `create`, `authority-init --data-dir`, `restore` (as `--root`) and `activate` print `soundpost backup: unsupported_mode: backup, restore and activate support single-node installations only (--mode single) ...` and exit 1 before opening anything. Cluster backup and restore are not implemented. A directory counts as distributed when the first record of `raft/control/ready.wal` names a node of a group of more than one member (`backup.IsDistributedDirectory`); this was observed on a directory a real three-process cluster had written, where the earlier behaviour was the untyped `internal error` from `internal/replica/ready.go` (the journal's node identity is not the single node's identity 1).
* The control group's own Raft snapshot is not part of the bundle; the control state travels as the seed taken at C and is re-seeded into a new single control group (control history and old Raft identity are not restored).
* `PinReaper` is a consumer interface; the replica-side `Pins()/DropPin(id)` it adapts does not exist yet, so a dead attempt's pins cannot yet be reaped in production (the marker and the reaper logic are tested with a fake).
* `AppliedProcessed` assumes no lifecycle projection. Reservations created after C are rebuilt from `batch` entries inside the snapshot machine state; `storage.ReservationEvidence` does not carry producer, batch and slot, so this reads a documented-by-test JSON shape of the engine's own state (a change there fails `TestRestoreReconcilesReceiptsTypedRowsQuotaAndTombstones`).
* The retention-side `retention.Service.Restore` imports tombstones into control and applies them to the data groups but does not itself check the authority against a backup binding; `Activate` does, and hands it a pinned read-only view of exactly the verified head.
* Backup objects of expired or abandoned backups are not deleted by this code.
* Power loss, lying fsync hardware, distinct failure domains and scale are not exercised.
* **The authority journal is O(D²) in completed deletions.** Every head record carries the whole tombstone ledger (that is what lets a restore verify one record and read the full current ledger from it), so a journal of D deletions holds D(D+1)/2 tombstones, and `Authority.Current` (run twice by every checkpoint, once by every backup, and by every restore and activation) fetches, decrypts, signature-checks and re-validates all of them. Measured on the local-disk destination of one 32-CPU WSL host (`go test ./internal/backup -run '^$' -bench AuthorityCurrent -benchtime=1x`, journals forged directly, one run each): 100 deletions 2.3 MiB and 0.10 s per read; 250: 14 MiB, 0.66-0.68 s; 500: 56 MiB, 2.4-2.6 s; **1,000: 224 MiB, 10.3-11.4 s**; 2,000: 40 s (size not printed; about 900 MiB by scaling). One record holding 10,000 tombstones is 4.5 MiB and verifies in 0.19 s; the cost is linear in tombstones read (about 19 µs and 0.45 KiB each), so **10,000 deletions are about 50 million tombstones: about 22 GiB and about 16 minutes per read** (derived, not run), and one checkpoint, which reads twice, would hold the deletion in `fencing` for over half an hour. A single record would hit the 64 MiB read limit at roughly 140,000 tombstones. This was **not** fixed: skipping re-verification of the prefix (a verified-prefix cache keyed by the head hash) saves CPU but not the bytes fetched, and trusting the destination for the prefix gives up the property that every read detects tampering. The safe fix is a record format change (each record carries the previous digest and only the tombstones it appends, plus a periodic full snapshot or a compaction digest). Until then the practical bound is a few hundred completed deletions per installation; an operator near it should expect checkpoints (and therefore deletion completion) to take tens of seconds.
* `AuthorityBinding.LedgerDigest` is computed and signed into the manifest but never compared on restore: chain containment of the head the backup names already pins exactly that ledger (the head record's sealed payload is digest-bound). Treat it as informational. (`ControlBinding.StateSHA256` is verified against the decrypted control-state object.)
* Key wrapping uses a random 96-bit nonce under a long-lived key-encryption key (birthday bound about 4 million wraps per key); `Encryption.ChunkSize` is asserted equal to the compiled constant, not honoured.
* `Service.Reap` cannot scope pins to an attempt (see the `PinReaper` contract); it is safe only at process start.
