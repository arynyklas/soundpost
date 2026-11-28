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

The same tag also builds the `soundpost serve` shard-removal seam used by the browser end-to-end suite (`cmd/soundpost/faultcontrol.go`): with `SOUNDPOST_FAULT_DIR` set, a `close-groups` file there (comma-separated data slots 0-63) closes those replica groups of the running server, so readers find shards unanswering. It is never compiled into the released binary (`faultcontrol_off.go` is a no-op); `web/e2e-harness/h.sh` builds it with `E2E_FAULTS=1` for `web/e2e/shard-loss.spec.ts`, which needs a server of its own because the removal is permanent.

The same tag also compiles two observation hooks for the load-gate harnesses, both inert unless `SOUNDPOST_FAULT_DIR` names a directory and both empty inline no-ops in the released binary (`internal/rules/gate_observe_off.go`, `internal/httpapi/gate_scan_off.go`). The rule engine appends one JSON line per committed evaluation (`"k":"e"`: wall time `t_ns`, grid time `at_ns`, `project`, `rule`, `mode`, `outcome`, `reason`, `blocked`, `members`, `ms`, `kind`) and one per rule query (`"k":"q"`: `pages`, `rows`, `bytes`, `peak_mem`, `ok`) to `rules.jsonl`. A `POST /api/v1/traces/view` or `POST /api/v1/services/red` request that carries an `X-Gate-Request` header of exactly 16 lowercase hex characters has the pages, rows and bytes of its storage scan counted per request and appended to `scans.jsonl` as `{"req","route","pages","rows","bytes","ms","partial"}` when the handler returns, error answers included. A write failure is dropped and never changes an evaluation or an answer.

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
| `node-loss-journeys` | the `node-kill-restart` loss (SIGKILL of member 1, then member 3, while writers stream), then, only once the recovery is proved, the real reference journeys of `tools/smoke` against the same three processes (`journeys --cluster-attach`); every row of `tools/smoke/journeys_assert.go` (eighteen), all must pass; every ACKed id of the whole run reconciled on every member afterwards | run on a host with the journeys' tools (`--journeys-smoke`, `--journeys-arg`, `--serve-arg`), see "After recovery: the reference journeys" |
| `vm-hard-reset` | a REAL guest hard reset (`echo b > /proc/sysrq-trigger`: immediate reboot, no sync, no unmount, page cache dropped) of the machine that holds the three processes, while writers stream; two phases because the harness dies with the machine; after the reboot every acknowledged id is retained with identical data on every member | run on a machine that may be rebooted (`--vm-reset-state`, `--allow-vm-reset <hostname>`, root), see "A real guest hard reset" |

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
   have leaked quota before the fix: by reading `internal/control/quota.go` (not by running the
   unfixed build), it looks so. `ReserveAdmission` charges the quota before the capacity refusal,
   which refunds nothing, the only release of a `reserved` row that file contains is
   `CancelAdmission` with the owner group's proof, and the 403 retry never consumed or cancelled
   it; so the charge stayed until a cancel. After the fix the retry reuses the same reservation
   and the quota is unchanged by it
   (`internal/storage/reservation_epoch_retry_test.go`). `capacity-faults` and
   `stale-policy-delete-barrier` re-run on the lane 1 wave 14 tree: both `passed`, exit 0.
2. Post-deletion backups could not be activated in the case below. **Fixed** (dc732a8):
   `restore-authority-unavailable` now runs on a backup taken after a deletion whose erased
   rows carried a series no retained row has, and its restore and activation checks pass
   (re-run on the lane 1 wave 7 tree: `restore-authority-unavailable: passed`, exit 0).
3. With an old backup, only the independent current authority HEAD protects
   against a rolled-back authority journal: the negative control of
   `backup-predates-deletion` shows a pre-deletion journal copy brings back the
   deleted rows.
4. Deletion `Begin` was an optimistic commit on the one global control revision and
   starved under saturating intake (60/60 and 20/20 conflicts observed in 07.07; every
   intake admission is a control transition and moves that revision between the
   caller's view and its commit), so the drill took a short write pause for that
   single commit. **Changed (10.05):** control now keeps `AuthorityRevision` (the
   revision of the last transition that could change authority, policy, retention,
   deletion or access state) and the retention commands (`DeleteScope`, `BeginFence`,
   `CompleteFence`, `PolicyChange`, `RecordEvidenceGap`) accept a caller view in
   `[AuthorityRevision, Revision]`; intake admissions, quota accounting and the book
   writers do not move `AuthorityRevision`. `TestDeleteBeginDoesNotStarveUnderSaturatingIntake`
   (`internal/retention`) shows it: four goroutines reserving admissions without pause,
   Begin conflicts 8/8 (natural race) and 8/8 (view forced stale by intake) on the
   unchanged tree, 0/8 and 0/8 after. **The drill's write pause is removed (lane 1 wave 7):**
   `stale-policy-delete-barrier` no longer holds a gate over the racing writers; both
   Begins (`delete_begin`, `retire_begin`) run under the full concurrent load of
   legitimate, in-range, stale, replaying and cached-policy writers, with a retry bound of
   400 attempts. Ten consecutive runs on Linux (one VM, a release-style `sp-bin` built from
   the tree, `go run -tags soundpost_faults ./tools/drills --scenario
   stale-policy-delete-barrier ...`), all `passed`, exit 0: every run recorded `delete_begin`
   and `retire_begin` with 1 attempt and 0 conflicts before the Begin committed (the facts
   carry `"write_pause": false`). Conflict distribution of the writers' refused attempts
   (the report's `failed_attempts`, ten runs, totals 8819 `refused:stale` and 797
   `refused:conflict`):

   | run | refused:stale | refused:conflict | acknowledged |
   | --- | --- | --- | --- |
   | 1 | 891 | 79 | 214 |
   | 2 | 916 | 83 | 217 |
   | 3 | 929 | 81 | 216 |
   | 4 | 930 | 79 | 215 |
   | 5 | 909 | 78 | 213 |
   | 6 | 930 | 77 | 215 |
   | 7 | 862 | 78 | 213 |
   | 8 | 894 | 79 | 213 |
   | 9 | 743 | 81 | 215 |
   | 10 | 815 | 82 | 216 |

   `refused:stale` are, by the codes' names (inferred, not separately measured per writer), the stale/replaying/cached-policy writers refused after the policy
   changed, `refused:conflict` are racers refused for a revision conflict; neither is a
   deletion Begin, and the drill's reconciliation accepted every ACKed row in all ten runs.
   The earlier reading of 2 `retire_begin` conflicts (one run, with the pause still in the
   drill) did not recur: 0 in ten runs; its cause was never isolated. **Still a limit:** a
   Begin still conflicts, as it must, when its view predates an authority-class change,
   and a writer of another package that is not classified in `internal/control/authority.go`
   bumps `AuthorityRevision`, so heavy traffic of those kinds can still make a Begin retry
   (the drill's writers are intake only). The classification table is the review surface: a
   writer wrongly classified as non-authority would let a deletion commit on an outdated
   view. **Changed (10.05, F-10.05-2):** an organization's admin commands (every
   kind except `create_user`, which writes the installation-wide user table) no
   longer move the installation-wide `AuthorityRevision`; they move the
   organization's own authority revision (`authority_rev` in its Settings), and a
   retention command of an organization is judged against the later of the two. A
   tenant's admin commands therefore cannot conflict another tenant's deletion
   Begin (`TestAnotherOrganizationsAdminCommandsDoNotConflictABegin`). The exemption
   is verified per commit (`verifyOrgTransition`: the encodings of the state before and
   after must differ only in the organization's own record, appended audit rows and added
   commands, else the commit bumps the installation-wide revision, as a
   `source_policy` command for a live source does, and as an admin `retention` command does: it
   appends to `RetentionPolicies`, which the admin class does not own, so both keep the global check
   on this release too, `TestAdminSourcePolicyAndRetentionKeepTheGlobalCheck`).
   **Changed (10.05, F-10.05-2 residual):** the retention-class commands of an organization
   (deletion Begin, hold, retention policy, the fence steps, the worker's saga transitions and
   delete-generation advances) move the organization's own revision as well, when control has
   verified that the commit wrote only that organization's rows in the retention tables
   (`verifyOrgTransition`, `orgRetentionTables` in `internal/control/authority_org.go`, besides
   appended audit rows and added commands). A new evidence gap (keyed by a hash, bound by the
   backup attestation), a source fence, a user, a quota or another organization's row keeps the
   installation-wide bump. Another tenant's retention commands therefore no longer make a Begin
   retry (`TestAnotherOrganizationsRetentionCommandsDoNotConflictABegin`, 19 commit shapes;
   `TestOwnRetentionCommandsStillConflictAStaleView`: the organization's own stale view still
   conflicts). The verification is free only for a command proposed as a state patch (every member of
   the control group declared protocol 5); a replacement is an ordinary bump. **Both revisions move
   (decision D75):** a verified commit of an organization moves the installation-wide
   `AuthorityRevision` as well as the organization's own `authority_rev`, because the previous
   release (5475ef6 declares protocol 5 but predates the rule) judges a retention command against
   that scalar alone and has to keep refusing a same-organization view older than the commit.
   This release checks the organization's revision and the installation floor
   (`installationFloor`: the last change that was not a verified commit of one organization,
   kept in `State.OIDC["authority:scope"]` beside the `AuthorityRevision` it belongs to and void
   when another binary moves that scalar), so no other organization's verified commit conflicts it;
   a previous-release leader may still refuse a view that is stale only for another organization,
   as it always did, while it leads
   (`TestStaleSameOrganizationViewIsRefusedByBothReleaseRules`,
   `TestAnotherOrganizationsAdminCommandMovesTheScalarButNotTheFloor`,
   `TestACommitThatDoesNotWriteThePairVoidsTheFloor`,
   `TestAViewStaleThroughASharedTableStillConflictsOnThisRelease`, and with real binaries
   `TestMixedBinaryStaleSameOrgCommandsAreRefusedByThePreviousReleaseLeader`).
   **Why lane 1 wave 26 could not ship it:** the verification encoded the state twice more per
   attempt inside a whole-state replacement. A Begin that has to be proposed again after losing
   the application-index race (up to 64 times) then took 24 ms of CPU per attempt against 7 ms
   (CPU profile: 5.69 s of `json.Marshal` inside `Transact` against 0.27 s), won the race 4 % of
   the time against 26 %, and was refused as `stale` after 64 losses. The wave-26 bisect pointed at
   the stamp because only the stamping path ran the extra encodings: the stamp itself, with or
   without the installation-wide bump, left the test at 10 to 14 s, and two extra
   `json.Marshal(state)` alone made it fail (186 to 222 s). The verification now reuses the one
   encoding a state patch makes anyway and is not made in a replacement
   (`l1w28-evidence/lane/cause-evidence.txt`).
   `TestDeleteWithViewOlderThanAuthorityChangeStillConflicts` has a stale-view
   subtest for every admin kind that reaches `Store.Update` or
   `Store.UpdateOrgAuthority` against the organization's own Begin (`create_user`,
   `create_project`, `membership`, `org_admin`, `grant`, `team`, `source_policy`,
   `sso`, `destination`, `retention`); `notification_policy` is reached only through
   `PolicyCommand` (a retention-class policy kind) and has no subtest of its own.

   **Three voters (independent review of 10.05, F-10.05-1):** the figures above are one voter. In a
   three-voter control group every commit is one application-index compare-and-swap, and with intake on
   every voter a Begin submitted through a voter that does not lead lost that race on 75 to 88 % of its
   attempts (35/40 and 30/40; 20 % on the leader; 0/40 on one voter) and answered `stale` (HTTP 409)
   although no authority-relevant write had moved. The retention commands now read, re-judge and propose
   again (at most 64 times) when their proposal was refused as stale, so the caller's view is checked against
   the new state each time (a view that predates an authority-class change still conflicts).
   `TestBeginIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake` (`internal/control`) is the
   three-voter probe: 11, 10 and 6 of 12 Begins refused from voters 3, 2 and 1 before, none after (three runs).
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

## After recovery: the reference journeys (`node-loss-journeys`, 07.07#16)

`node-loss-journeys` loses and restores members exactly as `node-kill-restart` does (SIGKILL of member 1, the configured
initial leader, then of member 3, while writers stream; each phase reconciles every ACKed id on every member), and **only
after the cluster has recovered** runs the three real reference journeys (`tools/smoke journeys`, rows and applications in
`docs/acceptance/reference-journeys.md`) against those same three processes. The rows are the smoke's own: the drill copies
them from the smoke's observation file into its report (`journey_row_<name>` checks and `facts.journeys/rows`) and evaluates nothing itself.

```
go run ./build release --root . --out /tmp/drill-release --version V --arch amd64 --web-dist DIR   # the produced static binary
go build -o /tmp/smoke ./tools/smoke
go run ./tools/drills --scenario node-loss-journeys --target isolated --report /tmp/drill-report \
    --binary /tmp/drill-release/linux-amd64/soundpost --root . --journeys-smoke /tmp/smoke \
    --journeys-arg=--bun=/usr/local/bin/bun --journeys-arg=--node-linux=/usr/local/bin/node \
    --journeys-arg=--python=/usr/local/bin/python3.13 --journeys-arg=--chrome=/path/to/chrome \
    --journeys-arg=--pg-local=/path/to/postgresql-16 \
    --serve-arg=--symbolicate-cgroup-root=/delegated/empty/cgroup
```

`--journeys-arg` flags go verbatim to `smoke journeys` (any flag of a single-node run, for example Docker's `--pg-image` instead of
`--pg-local`); `--serve-arg` flags are added to the `soundpost serve` of every member. The members run the native
symbolication sandbox, so run the drill inside a delegated cgroup (`systemd-run --user --wait --pipe -p "Delegate=memory pids" -p
DelegateSubgroup=main`) and pass that unit's cgroup as the root. Without `--journeys-smoke` (or with a path that is not a file) the
scenario is reported `not_run` with that reason, as every drill is that cannot be exercised on the host (exit status 10 if nothing
else failed; `TestJourneysScenarioWithoutTheJourneysToolsIsNotRun`), so `--scenario all` on a host without the tools still
runs everything else. It is deliberately **not** tagged `evidence: node_loss`: the release gate's node_loss envelope is unchanged.

**The order, and what stops it**

1. Bootstrap one installation, start three members (mTLS between them, one shared public TLS leaf on their HTTPS listeners, so the
   applications and the browser trust one CA and the browser one public-key pin), the two node losses, the per-phase reconciliation.
2. **The recovery gate (`dcRecoveryGate`)**. The journeys do not start unless every acknowledged id is read back identically from every
   member (`recovered_every_acknowledged_id_reconciled`), every member answers ready now (`recovered_member_N_ready`), none is stopped or
   paused (`recovered_no_member_down`), the control applied cursors are equal (`recovered_applied_cursors_converged`) and the outage
   timeline is closed with its four failed attempts kept (`recovered_outage_closed`). Each failing part ends the scenario before the
   journeys (`TestJourneysAfterNodeLossRecoveryDoNotStartBeforeTheClusterRecovered`).
3. The attach document (`dcJourneyAttachDocument`, read by `smoke journeys --cluster-attach`) names the members, the TLS, the
   installation's owner (bootstrapped by the drill; the smoke logs in, it does not bootstrap), the members that were killed and
   restored, and which member each leg uses: the owner's provisioning and the API through member 2 (never killed); the gateway, its page and the web
   build's artifact upload through member 3 (killed and restored); the job through member 1 (killed and restored); member 1 is
   also the **scan member**. The drill refuses a document in which a leg names a member that is not answering, or in which the scan
   member was not killed and restored (`TestJourneysAfterNodeLossRecoveryRefuseLegsOnADeadOrUnrestoredMember`), and the smoke
   refuses the same again and waits for `/readyz` of every member before it provisions.
4. The smoke runs as a child of the drill. Its stdin/stdout are a one-request-at-a-time control channel (`dcJourneyOwner`):
   `phase drive_begin|drive_end` start and stop the drill's own write stream (two writers, a batch every half second, through
   whichever members answer) around the applications' traffic; between the two the applications ingest through their members
   and the browser acts on the page. The smoke's collect step scans storage in process, which needs the data directory of a member to itself, so the smoke asks the
   drill to **shut down the scan member** (SIGTERM, exit status 0 required), opens that member's directory in the smoke process with
   `appcore.OpenDistributed` and its node file (it joins the two members that keep running and answers once every group has its
   quorum), scans, closes, and asks the drill to **start the member again** and wait for ready. Every login and every read of the
   rows after that goes through that restored member. The owner refuses any other member, any request out of order and any
   request twice (`TestJourneysAfterNodeLossRecoveryOwnerFollowsTheJourneysInOrder`).
5. Control writes and reads against a recovering cluster retry the answers it documents as retryable (HTTP 400/409 `stale`/`conflict`, the
   typed 503); every other answer is the row's evidence as it is.
6. Afterwards the drill takes **every row of the smoke's assertion list (eighteen)** from `observed.json` (a row that is missing, repeated, not required, not satisfied
   or not in the closed list fails; `TestJourneysAfterNodeLossRecoveryRowsMustAllPass` runs the verdict on the recorded
   observation and on five wrong ones), requires every SDK client's final flush to have nothing pending and nothing lost
   (`journeys_sdk_delivery_acknowledged`: gateway, API, job and the three browser pages), and then, on the whole run, repeats the
   cursor convergence, the retry of already acknowledged batches on every member (same receipt), the read-back of every member
   with exact reconciliation of **every** acknowledged id, and requires acknowledged batches in each period of the run
   (`acks_written_before_during_and_next_to_the_journeys`: the two losses and the writes next to the journeys).

**What the run covers, and what it does not**

* Three processes of the produced binary on one host share a kernel, a disk, a clock and a power supply: **not three failure
  domains** (`facts.topology` says so). The two node losses happen **before** the journeys; the journeys run on a recovered
  cluster, they are not run through a failure. The one member stop during the journeys is a clean shutdown for the in-process scan, not a loss.
* The acknowledged ids of the journeys' own applications are not entries of the drill's ledger: the SDKs hand back counts, not batch
  ids, and the ledger's exact comparison needs the batch's data back through the query API (which a trace or a job is not).
  What covers them: each client's final flush (nothing pending, nothing lost), the eighteen rows (traces, errors, job attempts,
  the profile and the replay read back from what the cluster stored, and the ids compared with the expected ones in
  `actual_ids_equal_expected`) and the drill's own writes next to them, reconciled exactly.
* The members of this scenario serve one shared TLS leaf; production nodes do not (the browser pins a single key). The smoke's canary
  scan reads the members' directories while two of them run (a file that vanishes between listing and reading is skipped and counted,
  `scan_skipped_vanished_files`), and the scan member's directory is opened in the smoke process as that member (a second process image
  of one member, never running at the same time as the real one).
* Evidence of the committed run: `.superpowers/sdd/approved-product/l5w24-evidence/recovered/` (private development ledger, not shipped).
  The single-node `smoke journeys` is unchanged (`--cluster-attach` is the only addition, and nothing is started or changed without it).

## A real guest hard reset (`vm-hard-reset`, 07.07#7)

`power-loss` is **emulated** (see above): the drill SIGKILLs the members and rolls the unsynced bytes back itself, and the kernel page
cache is not dropped. `vm-hard-reset` resets the machine for real: it writes `b` to `/proc/sysrq-trigger`, which reboots the kernel at once
with no sync and no unmount, so the page cache and every write that was not fsynced are gone, as after a crash reboot, while the three
processes (all on that machine) are being written to. It is **a guest-level crash reboot, not a hypervisor power-off**: a write the guest
believes flushed but the host still holds in the virtual disk's cache is not exercised, and three processes on one machine are not three
failure domains. Run it only on a machine that may be rebooted (it is a drill of a throwaway VM, never a host with other work).

```
go run ./tools/drills --scenario vm-hard-reset --target isolated --report DIR --binary B \
    --vm-reset-state /var/tmp/soundpost-drills/state --allow-vm-reset "$(hostname)"      # phase 1: resets the machine
go run ./tools/drills ...same command...                                                   # phase 2, after the machine is back
```

The same command is both phases: the **marker** file in the state directory says which. Without the two flags the scenario is `not_run`.
The state directory holds everything phase 2 needs and must survive a reboot: it must be under an allowlisted data root
(`/var/tmp/soundpost-drills` is one, because `/tmp` is cleaned at boot on Debian), and phase 1 refuses to start in a directory that is not empty.

**Phase 1 refuses unless** it runs as root, `--allow-vm-reset` equals the machine's hostname exactly, the state directory is under the allowlist
(not a production directory, not the root itself, absolute, no `..`), is empty, and magic sysrq can be enabled and the trigger opened
(`TestVMHardResetRefusesEveryUnsafeStart`). Then it bootstraps the three-process cluster with its data under the state directory
(`dcOptions.workDir`), saves the addresses and the fixture (`state.json`), streams writes with four writers, and **journals** them:
every issued batch (id and exact body) is appended to `issued.jsonl` and fsynced before its first send, every acknowledgement (id, receipt
cursor, semantic digest) to `ledger.jsonl` and fsynced before the drill counts it (`Ledger.Sink`, `dcWriter.onIssue`). Each journal line
carries its sequence number and a hash chained to the line before (`vmJournal`). After at least 80 acknowledgements it writes the boot id and
the **marker** (acknowledgement and issue counts and chain heads, fsynced), writes the phase 1 report (`vm-hard-reset.phase1.json`, fsynced,
because the harness will not survive to write it), and resets the machine **with the stream still running**, so batches are in flight.

**Phase 2 refuses unless** the boot id differs from the marker's (no reset happened otherwise), the hostname flag matches, and the journals are
exactly what phase 1 wrote: a marker or journal that is missing, cut short, changed, reordered, or shorter than the marker counted is a refusal
(`TestVMHardResetResumeRefusesWhatIsNotAResetOrNotWhatPhaseOneLeft`, `TestVMJournalRoundTripAndEveryWayItBreaks`). Then it restarts the three members on
the same data, PKI and ports, waits for ready, sends the batches that were in flight (issued, never acknowledged) again with the **identical body**
until they are acknowledged, and runs the verification of the whole-cluster power cut: cursors converge; a retry of acknowledged batches returns the
**original receipt** on every member (the reloaded ledger refuses a changed receipt); every acknowledged id, those of the journal and those of the
retries, is retained with identical semantic data on every member, stored once, with no id the drill never issued. The report records both boot ids,
the uptime after the reboot, the acknowledgements before the reset, the in-flight batches and how many member log lines mention a torn tail
(`vm_reset/member_log_mentions_torn`: the member prints nothing about decision D16's drop of a torn final frame, so that is observed only as "the members became
ready and reconciled"). A verification that loses one acknowledged id fails (`TestVMHardResetReloadedLedgerCatchesADroppedACK`).

The scenario is not tagged `evidence: node_loss`. Orchestration of the committed run: `.superpowers/sdd/approved-product/l5w24-evidence/vmreset/orchestrate.sh`
(private development ledger, not shipped).

**Observed (a lab VM, Debian 12, kernel 6.1.0-54, ext4 on one virtual disk).** Phase 1 journalled 81 acknowledgements and 85 issued
batches and reset the machine with the stream running; `last -x` shows the new `reboot` record with no `shutdown` record before it, the journal of
the previous boot ends mid-session with no shutdown sequence, and journald logged `corrupted or uncleanly shut down` for the previous boot's file. Phase 2
(boot id changed, uptime 20 s) started the three members in under a second, retried the 4 batches that were in flight, and reconciled all 85 acknowledged
ids exactly on every member, each stored once, with the original receipt on retry. Two earlier real resets failed for reasons that were the harness's own,
and are fixed: the files the harness itself had written for the members (PKI, node files) were zero-length after the reset because they had never been
fsynced (phase 1 now fsyncs exactly those, phase 2 refuses with a clear check if one is missing: `TestVMSetupFilesAreTheHarnessOwnFilesAndEmptyOnesAreRefused`),
and the orchestration's own freshly copied binaries were zero-length (it now `sync`s and verifies their digests across the reset).

**Limits.** The drill's own journal fsyncs commit the filesystem's shared journal, so some data the members wrote without an fsync can be
persisted as a side effect; what the reset takes away is everything written after the last such commit plus the whole page cache, and what matters for the
claim (an acknowledged write was fsynced by the member before its acknowledgement) is unaffected. The member logs say nothing about decision D16's drop of a torn
final frame, so that is not observable here (`vm_reset/member_log_mentions_torn` is 0). One reset on one filesystem, with an ordinary guest disk cache setting,
is one observation, not a statistical claim. The host's virtual-disk cache is not exercised (see above).

## A real hypervisor power cut of one voter (`tools/pcut`, 07.07#7)

`vm-hard-reset` resets a guest that holds all three members. This drill is the other half of 07.07#7: **three voters on three machines**, one of
them powered off by the **hypervisor** (`qm stop` of its VM, no guest shutdown, no `sysrq`), left down for about two minutes and started again, under a
continuous ingest load with a durable-ACK proof. It is operator-driven (the cut is the hypervisor operator's act on a throwaway VM), so it is not a
`tools/drills` scenario; `tools/pcut` is its load, journal, prober and verifier.

| command | what it does |
|---|---|
| `pcut bootstrap` | one-time bootstrap of the single installation the cluster seed is made from (owner, organization, project, reader, one source); writes the fixture the other commands read (it holds the source credential: never commit or copy it) |
| `pcut gen` | the continuous ingest. Each batch is `--records` samples of ONE series (label `w`), the value of a sample is its per-series sequence number, observed times 1 ms apart. The journal line `issue` is fsynced before the first send and the line `ack` (with the receipt) before the writer counts the acknowledgement or sends the next batch; an unacknowledged batch is resent with the identical body to the voters in turn (the original dedup identity makes the answer the original receipt). The journal is hash-chained; a reader refuses a cut, changed, dropped or swapped line. A stop request (`--stop-file`, SIGTERM) drains: every in-flight batch is resent until acknowledged |
| `pcut probe` | from a host that is never cut: every second each voter's `/readyz`, and on its own loop one complete PromQL read per voter as the project reader (`--query-interval`, `--query-timeout`); one JSON line per probe |
| `pcut verify` | after the cut: waits until every voter is ready with one control leader, keeps the load running a little, stops the generator (drain), reads **every series of every voter**, and judges the data against the journal |

**The verdict** (`pcut-verdict.json`, `PASS` only when every required check passes): every acknowledged record is read back on every voter with its exact observed time
and value (0 missing); the three voters retain byte-identical data (a SHA-256 over the sorted `(series, time, value)` lines), so the cut voter has caught up; no record is stored
twice, no sample is a record the generator never issued, none has a changed time, and no batch is retained in part (a batch is atomic); the outage of the cut voter
is observed in the probe log for at least `--min-outage`; during it (after `--grace` for the survivors to elect leaders) each surviving voter is ready and answers complete reads for at
least `--min-availability` of its probes, and acknowledgements continue with no gap longer than `--max-ack-gap`. A batch issued and never acknowledged may be retained or absent; it is
counted, not judged. `--rehearsal` runs the same judgement against the live load without a cut (only batches older than 30 s, no outage checks) to prove the tooling.

**Setup used** (`pcut-evidence/scripts/`, private development ledger): the release built with `go run ./build release` from a `git archive` of the commit on one VM, the same binary on
every voter, a cluster CA and one leaf per voter (URI SAN `spiffe://soundpost/node/<identity>`, IP SAN of the VM), the installation file rendered by `soundpost-config`, the seed
exported from one single installation, a systemd unit **enabled** on every voter so a powered-off voter serves again after power-on without an operator, and `sync` plus a page-cache drop
before the cut with the binary's digest read back from the disk (a power-off loses unsynced writes: the first real guest reset left zero-length binaries that had just been copied).
The placement is attested `simulated`: three VMs of one hypervisor cluster are not an attestation of independent hardware, power or storage.

**Load shape.** Measured on this build: every acknowledged batch costs about two control-group commits (4.3 commits/s at 2 batches/s), and a query scans every record of its time range whatever its
selector (a 5-minute window took 1.3 s with about 4,800 records retained, a 10-second window 0.28 s, and so did a query for a metric that does not exist), so the cost of a read is the data volume of its
window. A first run with one-record batches at 20/s and three 5-minute reads per second fell to about 5 acknowledgements/s within four minutes while the leader wrote about 28 MB/s of disk. The load is
therefore a bounded number of multi-record batches (default 1 batch/s of 16 records, one series per batch), the probe reads only the last 15 seconds, and the verifier's full read-back (one query over the whole run,
or per series when that fails) must finish inside the service's 30 s query cap: at the measured scan rate (about 3,700 records/s) that is an estimated run of about an hour and a half at this load, not a measured one.

**Limits.** One cut of one voter of three, with the survivors keeping the quorum; the cut guest's virtual-disk cache at the hypervisor is what a power-off exercises, and it is one observation, not a
statistical claim. Losing two voters, a whole-site power loss and the hypervisor host's own loss are not exercised.

**How to run.** Hosts, paths and the cut voter are all flags; nothing is built in. (1) Bring up three voters on three machines from one seed (the installation
`pcut bootstrap` bootstrapped) with a systemd unit that is enabled. (2) `pcut bootstrap --url … --trust … --token-file … --ca … --endpoints name=id=https://host:port,… --out fixture.json`.
(3) On a host that is never cut: `pcut probe --fixture fixture.json --log probe.log --pid-file probe.pid` and
`pcut gen --fixture fixture.json --journal ack-journal.jsonl --stop-file STOP --pid-file gen.pid --rate 1 --records 16`, both detached; wait until every voter is ready and the load is
acknowledged. (3b) `pcut verify --rehearsal …` proves the tooling against the live load. (4) Within about half an hour order the hypervisor to hard-stop the voter's VM, keep it down for
about two minutes, start it. (5) `pcut verify --fixture fixture.json --journal ack-journal.jsonl --probe-log probe.log --out DIR --gen-pid-file gen.pid --stop-file STOP --cut NAME`
(`--cut` is the endpoint name from `--endpoints`); it waits for the recovery itself and exits 0 only on `PASS`. Also keep the cut guest's boot id from before and after (it must change)
and its `last -x` (a reboot record with no shutdown record before it): the hypervisor's act is the operator's evidence, not the verifier's. The unit tests of the checks
(`go test ./tools/pcut`) feed each check crafted bad input and need no cluster.

**What each check proves.**

| check | proves | fails on |
|---|---|---|
| `membership_healthy` | after the cut every voter is ready with one control leader and one term | a voter that does not come back, split or absent leader |
| `generator_drained`, `journal_intact` | the generator resent every in-flight batch and ended cleanly; the journal's hash chain is whole, so the claims below are made against an untampered record | a cut, changed, dropped, swapped or torn journal; a generator still running |
| `generator_no_rejects`, `some_acks_to_verify` | no batch was refused as non-retryable; the run acknowledged something | rejected batches; an empty run |
| `acked_all_readable_on_<voter>` | every acknowledged record is read back with its exact value on this voter | one missing acknowledged record |
| `no_duplicate_records_on_<voter>` | no record, and no series timestamp, is stored twice | a duplicate |
| `no_torn_or_unknown_records_on_<voter>` | every retained sample is a record the generator issued, with its issued time, and every batch is retained whole | garbage or foreign value, changed time, half a batch |
| `voters_digests_equal` | the voters retain byte-identical data (SHA-256 over sorted series, time, value) | any difference between voters, or an unreadable voter |
| `cut_voter_caught_up` | the cut voter holds everything acknowledged and equals the others | a cut voter that is behind |
| `outage_observed` | the probe log shows the cut voter not ready for at least `--min-outage` and back inside the log | no outage, a short one, one that never ended |
| `survivors_ready_and_reading_during_outage` | both survivors stay ready and answer complete reads in at least `--min-availability` of probes after `--grace` | a survivor that stops serving, or fewer than two survivors probed |
| `cluster_acknowledged_writes_during_outage` | the cluster kept acknowledging writes with no gap over `--max-ack-gap` | no acknowledgement, or a longer gap |
| `cut_voter_really_down` | no readiness probe of the cut voter succeeded inside the outage window | a voter that answered during the "outage" |
| `control_applied_cursors_equal`, `acked_after_recovery` (not required) | the control states agree; the load was acknowledged after the recovery | reported as a warning only |

**Recorded run (2026-11-20).** Three voters on three VMs of one hypervisor cluster (placement `simulated`), one ingest of 1 batch/s of 16 records over 4 writers for about eleven minutes before the verdict,
the prober at 1 s readiness and a read every 2 s. The hypervisor hard-stopped one voter's VM at 23:05:09 UTC and started it at 23:07:16 UTC; the prober saw it not ready for 153.6 s (115 probes
in that window, none ready) and the boot id changed with no shutdown record. The generator issued and had acknowledged 652 batches (10,432 records; 0 lost, 0 rejected, 433 resent attempts);
156 acknowledgements came during the outage (first one 1.6 s after the first failed probe, longest gap after the grace 3.9 s). Every voter was ready with one control leader 2 s after the verifier started; the load ran 60 s
longer and drained. The read-back took 6 to 8 s per voter: 10,432 samples retained on each, 0 acknowledged missing, 0 duplicate, 0 torn or foreign, 0 partial batches, one identical digest on all three.
After the 30 s grace both survivors were ready in 124 of 124 probes and answered 62 of 62 complete reads (slowest 1.1 s). Verdict `PASS` (every required check; the two advisory ones passed too).
