# Failure drills

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

`tools/drills` runs the failure drills of task 07.07. A drill is an executable
claim: it acknowledges real writes, injects one failure, recovers, then compares
the **exact retained semantic data** with every acknowledged id. It never
substitutes a count for a content comparison, and a drill that cannot be
exercised on the current host is reported `not_run` with its exact reason, never
simulated as passed.

```
go run ./tools/drills --scenario NAME|all --target isolated --report DIR [--binary PATH] [--root .]
```

## Safety: isolated targets only

* `--target` accepts only the literal `isolated`. Production execution is a
  separate owner action and is not implemented here.
* The allowlist in `drills/scenarios.yaml` is explicit and never empty. A drill
  refuses (exit 2, nothing created, no report written) a data directory that is
  relative, contains `..`, is outside `data_roots` (`/tmp/soundpost-drills`), is
  the root itself, or is or contains a `forbidden_data_dirs` entry (the
  production and default locations), and any address that is not a loopback
  literal on the allowlist with an explicit non-zero port. Every scenario routes
  its directories and addresses through `Env.Approve`.
* Drills use temp data under `/tmp/soundpost-drills`, loopback only, ports chosen
  at run time, and kill only the processes they started. They use no privilege
  (no iptables/tc/netns, sysctl, setcap, mounts or privileged containers).

## Exit codes and report

| Exit | Meaning |
| --- | --- |
| 0 | every selected scenario passed (a passed scenario may list `not_run_items` for parts it could not exercise) |
| 1 | a scenario failed |
| 2 | usage error or a safety refusal |
| 10 | no failure, but at least one scenario is a `not_run` row |

`<report>/<scenario>.json` holds `ack_ledger` (every ACKed id with receipt cursor
and semantic digest), `failed_attempts`, `reconciliation`, `cursors`, `fences`,
`policy_timeline`, `notification_timeline` (hash-chained), every named `checks`
entry, `facts` and `not_run_items`. No secret or raw telemetry content is written.

## What the harness fails on

* **One lost acknowledged batch**: `Reconcile` compares each ACKed id's digest
  with the digest of the data read back after recovery. A missing id, or equal
  counts with different content, fails (`TestReceiptReconciliationDetectsOneMissingACK`).
  A retained id that was never acknowledged (committed, ACK lost) is reported, not failed.
* **A false recovered state or an overwritten failed attempt**: the timeline is
  append-only and hash-chained; `Recover` needs a delivery after the last failure
  and `VerifyTimeline` fails on a rewritten, dropped or forged entry
  (`TestOutageIsNotRecovery`).
* **An unsafe target** (`TestDrillRefusesUnapprovedTarget`).
* **A retry that changes its receipt**: the ledger refuses a second
  acknowledgement of one id with a different cursor or data.

## Scenarios

| Scenario | Drives | Result on this host |
| --- | --- | --- |
| `node-kill-restart` | three real mTLS processes of the produced static binary; SIGKILL the configured initial leader and a follower while writers stream; survivors keep acknowledging; restart; every member reconciled | run |
| `minority-pause` | same cluster; SIGSTOP one member (alive, unresponsive), SIGCONT | run |
| `majority-pause` | SIGSTOP two members; the survivor refuses with a typed 503 and the refused batch is never ACKed; SIGCONT, identical retry | run |
| `capacity-faults` | real replica journal with the committed `replica.Config.Fault` hook (failed sync, slow sync/apply) and the real application with an injected `storage.DiskMeter` (full disk) | run |
| `provider-failure-outage` | real node, outbox, worker, incident service with recording senders | run |
| `external-deadman` | the 06.09 observer as a separate OS process while every Soundpost component is stopped | run |
| `owner-cutover-rollback` | `notify.AdvanceCutover` activation, rollback, crash between phases, stale owner | run |
| `stale-policy-delete-barrier` | real in-process engine; all-shard delete barrier raced by legitimate, stale, replaying and cached-policy writers | run |
| `backup-predates-deletion` | encrypted backup older than a completed deletion, independent authority HEAD | run |
| `restore-authority-unavailable` | restore with the authority unreachable, uninitialised, wrong, rolled back: fail closed | run (one part not run, below) |
| `evidence-gap-after-retention` | retention worker after expiry; explicit evidence gap on the read path | run |
| `network-partition` | three real processes; peer traffic runs through the drill's own loopback TCP proxies (each member binds `127.0.0.<id>` as its peer source address); member 1 (initial leader) is isolated with DROPPED packets, member 3 with RESET links, both sides alive and the isolated member still reachable by clients; it must never acknowledge, the majority keeps acknowledging, every ACK reconciled on every member after the heal | run |
| `power-loss` | three real processes under the unprivileged storage fault injector; one member (initial leader, then member 3 with a torn tail) and then ALL members are power-cut inside an fsync (every fsync held, process group SIGKILLed, then every byte and directory entry the members had not fsynced rolled back); restart; every ACK reconciled | run (emulated power cut, see below) |
| `fsync-failure` | same injector; every fsync of one member (initial leader, then member 3) answers EIO while writes stream; the member is restarted on its disk; every ACK reconciled | run |
| `disk-disappearance` | same injector; one member's data directory is moved away under the running process and every fsync and path operation on it answers EIO (initial leader, member 3); then member 2's disk is replaced with a blank one and finally the original returns; every ACK reconciled | run |

### How the four storage and link drills inject their faults (no host privilege)

* **No privilege.** No sysctl, capability, iptables/tc, mount, network namespace or
  privileged container. The partition is a user-space proxy the drill owns; the
  storage faults are a seccomp filter with `SECCOMP_RET_USER_NOTIF` installed by
  the drill on the real produced binary (`PR_SET_NO_NEW_PRIVS` is all it needs;
  `tools/drills/faultfs_linux_amd64.go`). The drills binary re-executes itself
  (`SOUNDPOST_DRILL_FAULT_EXEC`) to install the filter and exec the member, so the
  member is the unmodified binary. Linux amd64 only; elsewhere the drills fail
  with a typed "injector unavailable" error (they are never reported passed).
* **What is trapped.** `fsync`, `fdatasync`, `open*`, `creat`, `mkdir*`, `unlink*`,
  `rmdir`, `rename*` of the member. Everything else runs natively. The drill
  answers `EIO` (failing fsync, vanished disk) or lets the kernel run the call.
  The same stream is the durability ledger the power cut uses: bytes covered by an
  fsync, directory entries covered by a directory fsync, renames covered by an fsync
  of both directories.
* **Power loss is emulated, not performed.** The member's whole process group is
  SIGKILLed while every fsync is held (so writes that were issued and not yet synced
  exist), then the drill rolls the disk back to the ledger: unsynced file tails are
  truncated (or, with a torn tail, half of the unsynced tail is kept), directory
  entries not published by a directory fsync are removed, renames not published are
  undone. It does **not** model write reordering in a disk cache, torn sectors,
  filesystem journal replay, or a real power cut: the kernel page cache is not dropped,
  and unsynced loss is applied by the drill. A physical power cut still needs a
  machine whose power can be cut (a VM the hypervisor can hard-reset, or a PDU).
* **Network partition is member-to-member only.** The proxy sits on the peer
  transport between members; clients reach every member directly. It models link
  failure between members (packets vanish, or connections reset and refused) but not
  switch, routing, MTU or asymmetric-path failure.
* **Debugging.** `SOUNDPOST_DRILL_LOG_DIR=/dir` also appends each member's output to
  `/dir/member-<a|b|c>.log`; unset for evidence runs. Reports never carry member output.

### What the run does NOT prove

* `minority-pause`/`majority-pause` use SIGSTOP/SIGCONT: they prove behaviour with
  an unresponsive peer, not link-level partition behaviour with both sides live.
  Which member leads the data groups is not observable, so "initial leader" means
  the configured `initial_leader`.
* `capacity-faults`: the fault hook is the replica layer's own seam and it is
  **not** a real failing disk. `storage.Engine`'s own fault field is unexported, so
  failed-sync and slow-apply run on the replica layer with a drill-owned state
  machine. Real ENOSPC/EIO need a mounted size-limited filesystem (privileged).
* `external-deadman` runs the observer on the **same host**: it proves that a
  separate process with its own state and credentials keeps detecting and
  delivering while all Soundpost processes are stopped, not that it survives a
  host, power, network or storage failure. See `docs/operations/external-deadman.md`
  and `tools/fixtures/deadman/` (how to provision the same observer separately).
  The destination is a loopback receiver; no SMS, Telegram or webhook third party is contacted.
* The scenarios of the deletion group run the real engine in process, not the
  produced binary.
* A backup taken **after** a deletion whose erased rows carried a series no
  retained row has is not restorable (`Engine.CommitQuotaReconciliation` returns a
  typed `corrupt`: the quota series digest still counts the erased series). It
  fails closed; the fixture of `restore-authority-unavailable` therefore shares a
  series, and this case is recorded not run. It is a product defect to be fixed.

### Product findings surfaced by the drills

1. A capacity-refused batch (retryable 503) retried after a project deletion
   changed the policy epoch gets a permanent `403`, because the first attempt left a
   `reserved` reservation bound to the older epoch (`internal/auth/source_reservation.go`).
   Possible quota leak from the same reservation: not checked.
2. Post-deletion backups cannot be activated in the case above.
3. With an old backup, only the independent current authority HEAD protects
   against a rolled-back authority journal: the negative control of
   `backup-predates-deletion` shows a pre-deletion journal copy brings back the
   deleted rows.
4. Deletion `Begin` was an optimistic commit on the one global control revision and
   starved under saturating intake (60/60 and 20/20 conflicts observed in 07.07; every
   intake admission is a control transition and moves that revision between the
   caller's view and its commit), so the drill takes a short write pause for that
   single commit. **Changed (10.05):** control now keeps `AuthorityRevision` (the
   revision of the last transition that could change authority, policy, retention,
   deletion or access state) and the retention commands (`DeleteScope`, `BeginFence`,
   `CompleteFence`, `PolicyChange`, `RecordEvidenceGap`) accept a caller view in
   `[AuthorityRevision, Revision]`; intake admissions, quota accounting and the book
   writers do not move `AuthorityRevision`. `TestDeleteBeginDoesNotStarveUnderSaturatingIntake`
   (`internal/retention`) shows it: four goroutines reserving admissions without pause,
   Begin conflicts 8/8 (natural race) and 8/8 (view forced stale by intake) on the
   unchanged tree, 0/8 and 0/8 after. In the `stale-policy-delete-barrier` drill itself
   (one run on Linux against a release built from this tree), `delete_begin` recorded
   0 conflicts before the Begin committed (60 of 60 in 07.07) and `retire_begin`
   recorded 2 (20 of 20 in 07.07). I did not isolate the 2; the likely cause (inferred,
   not measured) is the first deletion's own barriers and fence steps, which are
   authority-class commits that run while the second Begin is being decided.
   **Still a limit:** the drill's own write pause
   and its 60-attempt retry loop are unchanged (this change did not remove them); a
   Begin still conflicts, as it must, when its view predates an authority-class change,
   and a writer of another package (replay checkpoint index, artifact reference ledger,
   login/session writes) bumps `AuthorityRevision` until it is classified in
   `internal/control/authority.go`, so heavy traffic of those kinds can still make a
   Begin retry. The classification table is the review surface: a writer wrongly
   classified as non-authority would let a deletion commit on an outdated view.
5. The source label policy admits label values from an allow-list, which bounds
   how many distinct batches the cluster drills can identify (700 pre-declared ids).

## Preparing the produced binary

```
go run ./build release --root . --out /tmp/drill-release --version V --commit C --arch amd64
go run ./tools/drills --scenario node-kill-restart --target isolated --report /tmp/drill-report \
    --binary /tmp/drill-release/linux-amd64/soundpost --root .
```

Cluster drills run on Linux. `stale-policy-delete-barrier` needs several GiB of
RAM and several minutes; `node-kill-restart` and `minority-pause` take about three
minutes each (read-back through the query API dominates).

## After recovery: the reference journeys

`go run ./tools/smoke journeys ...` (Docker PostgreSQL, about 70 s) exercises the
three reference journeys against a recovered system; see `07.04-report.md` for the
arguments. It exits 1 by design while two rows are unsatisfied.
