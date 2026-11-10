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
| `network-partition` | link-level partition | **not_run**: needs `iptables`/`tc`/network namespaces (privilege) |
| `power-loss` | power loss of one/all members | **not_run**: no power control; SIGKILL is not power loss |
| `fsync-failure` | failing fsync on a real disk | **not_run**: no failing disk; a hook is not a disk |
| `disk-disappearance` | a member's disk disappears | **not_run**: needs privilege to remove or unmount a device |

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
4. Deletion `Begin` is an optimistic commit on the control revision and can starve
   under saturating intake (60/60 and 20/20 conflicts observed), so the drill
   takes a short write pause for that single commit.
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
