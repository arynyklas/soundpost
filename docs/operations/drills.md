# Failure drills

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

`tools/drills` runs the failure drills of task 07.07. A drill is an executable
claim: it acknowledges real writes, injects one failure, recovers, then compares
the **exact retained semantic data** with every acknowledged id. It never
substitutes a count for a content comparison, and a drill that cannot be
exercised on the current host is reported `not_run` with its exact reason, never
simulated as passed.

```
go run -tags soundpost_faults ./tools/drills --scenario NAME|all --target isolated --report DIR [--binary PATH] [--root .]
```

The `soundpost_faults` tag compiles the storage engine's fault seam (`storage.Engine.SetFaultHook`) into the
drills binary only; the released `soundpost` binary is built without it, so no consumer can install a fault
hook. Without the tag every scenario still runs except the engine part of `capacity-faults`, which then fails
with that reason instead of passing.

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
| `capacity-faults` | real replica journal with the committed `replica.Config.Fault` hook (failed sync, slow sync/apply); the running application's `storage.Engine` through `SetFaultHook` over HTTPS ingest (failed `wal_sync`, group latch, restart, retry of the same batches, slow `before_apply`; builds tagged `soundpost_faults` only); and the application with an injected `storage.DiskMeter` (full disk) | run |
| `provider-failure-outage` | real node, outbox, worker, incident service with recording senders | run |
| `external-deadman` | the 06.09 observer as a separate OS process while every Soundpost component is stopped | run |
| `owner-cutover-rollback` | `notify.AdvanceCutover` activation, rollback, crash between phases, stale owner | run |
| `stale-policy-delete-barrier` | real in-process engine; all-shard delete barrier raced by legitimate, stale, replaying and cached-policy writers | run |
| `backup-predates-deletion` | encrypted backup older than a completed deletion, independent authority HEAD | run |
| `restore-authority-unavailable` | restore with the authority unreachable, uninitialised, wrong, rolled back: fail closed; and, on a post-deletion backup, restore and activation with the authority available | run |
| `evidence-gap-after-retention` | retention worker after expiry; explicit evidence gap on the read path | run |
| `network-partition` | three real processes; peer traffic runs through the drill's own loopback TCP proxies (each member binds `127.0.0.<id>` as its peer source address); member 1 (initial leader) is isolated with DROPPED packets, member 3 with RESET links, both sides alive and the isolated member still reachable by clients; it must never acknowledge, the majority keeps acknowledging, every ACK reconciled on every member after the heal | run |
| `power-loss` | three real processes under the unprivileged storage fault injector; one member (initial leader, then member 3 with a torn tail) and then ALL members are power-cut inside an fsync (every fsync held, process group SIGKILLed, then every byte and directory entry the members had not fsynced rolled back); restart; every ACK reconciled | run (emulated power cut, see below) |
| `fsync-failure` | same injector; every fsync of one member answers a real errno while writes stream: EIO on the initial leader and on member 3 (a failing disk), ENOSPC on member 2 (a full filesystem); that member fails stop in every group (it stops leading and voting, then exits), the other two keep acknowledging inside the scenario window in all three phases, the member is restarted on its disk and rejoins; every ACK reconciled | run |
| `disk-disappearance` | same injector; one member's data directory is moved away under the running process and every fsync and path operation on it answers EIO (initial leader, member 3), the survivors keep acknowledging inside the scenario window in both phases; then member 2's disk is replaced with a blank one and finally the original returns; every ACK reconciled | run |
| `membership-replace` | three real processes plus a fourth; `soundpost membership status`, a refused add of an existing voter, `add-learner` for member 4 (and its idempotent repeat), start member 4, stop member 3, `replace --remove 3 --promote 4`, all while a write stream is acknowledged; members 1, 2 and 4 each retain every acknowledged batch and 1 and 4 acknowledge with 2 stopped | run (the refusal of a real second uid is not run: no second user on the host; unit-tested per connection) |

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
* `capacity-faults`: the hooks are the replica layer's own seam and, in builds tagged
  `soundpost_faults`, the storage engine's `SetFaultHook` on the running application; neither is a
  real failing disk (the real EIO/ENOSPC errnos are the `fsync-failure` scenario's seccomp
  injection).
* `external-deadman` runs the observer on the **same host**: it proves that a
  separate process with its own state and credentials keeps detecting and
  delivering while all Soundpost processes are stopped, not that it survives a
  host, power, network or storage failure. See `docs/operations/external-deadman.md`
  and `tools/fixtures/deadman/` (how to provision the same observer separately).
  The destination is a loopback receiver; no SMS, Telegram or webhook third party is contacted.
* The scenarios of the deletion group run the real engine in process, not the
  produced binary.
* The restore case of `restore-authority-unavailable` is no longer a not-run part: its
  fixture deletes rows whose series no retained row carries (the case dc732a8 fixed), restore
  fails closed with the authority unavailable, and with the authority available the same
  restore and activation succeed and no deleted row is readable.

### Product findings surfaced by the drills

1. A capacity-refused batch (retryable 503) retried after a project deletion
   changed the policy epoch got a permanent `403`, because the first attempt left a
   `reserved` reservation bound to the older epoch (`internal/auth/source_reservation.go`).
   **Fixed** (b4263ca); the drills no longer record it. Whether the same reservation could
   have leaked quota before the fix was not checked.
2. Post-deletion backups could not be activated in the case below. **Fixed** (dc732a8):
   `restore-authority-unavailable` now runs on a backup taken after a deletion whose erased
   rows carried a series no retained row has, and its restore and activation checks pass.
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
6. **A node whose storage failed kept leading groups (fixed, 11.14).** With every fsync of the initial leader answering EIO, the two healthy members answered 503 for more than 120 s while the failed member stayed up (`/readyz` `state_unavailable`). Cause: only the group that noticed the failed write failed closed; every other group of that node (control and the 64 data groups) kept ticking and answering heartbeats, so the survivors never elected a replacement, while each proposal reaching the zombie leader was refused by its validator (its control state was unreadable) before anything was persisted, so those groups never failed either. The same cause stopped the survivors when member 3's disk vanished after member 3 had become the leader of some groups. Fix: `replica.FailDomain`, see `distributed.md`; red test `TestAStorageFailureInOneGroupFailStopsEveryGroupOfTheNode` (and the engine tests in `internal/storage/failstop_test.go`). The drills no longer exempt the leader phase: the survivors must acknowledge inside the scenario window in every phase.
7. **Restart after a failed fsync (11.14).** The member now exits non-zero after a fail-stop with one typed line (`soundpost: storage failure (reason=... group=...)`), and its restart re-verifies the journal: the Ready journal is read after the kernel is asked to drop its cached pages, every frame is CRC-verified, and the file is synced once more (`wal_open_sync`); a journal that cannot be verified or synced is refused, never reused. A restart that failed with the generic "startup or service failed" was a startup step giving up at its first five second freshness window while the member was still catching up under load (`model.Fault` `stale`): the post-ready startup reads now retry while stale within the startup budget, and a refused start prints `(reason=<closed code>)` instead of the generic line alone. Limits: the injector answers EIO but does not drop pages, so these drills cannot show a real lost page; the verification covers the Ready journals, while the other files verify themselves as far as their formats do (bbolt meta checksums, snapshot and segment hashes).
8. **Drill harness (11.14).** The write stream of a phase had a fixed budget of 100 batches; a restored member that needed 10 s to become ready (as happens) outlived it, and the check "6 acknowledgements after the member was ready" then timed out although the cluster was healthy. The stream now gets 30 more batches once the member is ready; the check itself is unchanged.
9. **A voter whose disk went back in time cannot rejoin; the remedy is a command (11.14, 07.07-W5).** `disk-disappearance` phase 3 puts a blank disk under member 2, lets it run (it acknowledges), then puts the original disk back. The original journal is shorter than what the leaders recorded for member 2. Before 11.14 raft panicked on every heartbeat and the member exited after its 60 s startup budget with `reason=stale`. Now the member refuses to rejoin with `reason=journal_behind_acknowledged` (`replica.ErrJournalBehind`, `docs/operations/distributed.md`) and the phase requires exactly that typed refusal while the other two keep acknowledging. The replacement of such a voter (new identity, learner, joint change) is `soundpost membership add-learner` / `replace` on the running nodes (`distributed.md`, "Replacing a voter"); the `membership-replace` scenario drives that on the produced binary with a fourth process.

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

`go run ./tools/smoke journeys ...` (a Docker PostgreSQL container, about 70 s) exercises the
three reference journeys against a recovered system; `docs/acceptance/reference-journeys.md`
lists the rows and what is satisfied (the replay and profile rows are satisfied since 11.02 and
10.17; the remaining unsatisfied rows are named there). The smoke needs Docker, a local
PostgreSQL 16 image, Linux Chrome and a built UI, so it is **not** part of a drills run and was **not**
re-run against a cluster recovered by these drills (07.07-W3): the drill machine used for the last
full run (07.07-W4 below) has no Docker. Until it is run there, the claim is limited to what
the drills themselves reconcile (every ACKed id on every member, through the query API).
