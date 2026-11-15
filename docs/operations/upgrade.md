<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Rolling upgrade, certificate rotation and maintenance of a three-voter installation

A three-voter installation keeps acknowledging writes while **one** voter is down. It stops acknowledging (a typed retryable `503` with code `stale`, `unavailable` or `timeout`; never a local acknowledgement) while **two** are down. Every procedure below therefore has the same rule: **never two members down, and never start the next member's restart before the previous member reports ready.** Nothing in Docker, Compose, Kubernetes or Helm enforces this for you by default; the manifests are built so that a routine `helm upgrade` or `docker compose up -d` does *not* restart everything at once, and the order is then yours.

"Ready" is exactly `GET /readyz` of that member returning `200` with `ready:true` (`internal/httpapi/health.go`, `docs/operations/install-single.md` section 5): its own quorum round, apply backlog, disk, policy fences and schema. A listening port, a running container or a Kubernetes `Running` phase is not readiness. `soundpost ready --data-dir /var/lib/soundpost` asks the same route and is the Compose/Docker health check.

## Preconditions (check before the first restart)

1. All three members ready: `kubectl get pods -l app.kubernetes.io/component=member` shows `1/1` for every pod, or `docker compose ps` shows three `healthy`; or `GET /readyz` returns 200 from each.
2. The control `applied_cursor` in the three `/readyz` answers is equal (quiescent) or within a few entries; a member that is behind is still catching up and must not be the one that makes the other two the only voters.
3. A current verified backup exists and its label is `deletion-safe-disaster-backup` (`backup-authority.md`). A recovery copy on the same host is not enough to roll back a failed migration. This is an offline, operator-checked precondition: a running distributed server does not build or check the backup service (`config.BackupChecker` runs only from the CLI), and multi-voter restore seeding is still an open item (see `backup-authority.md`), so a restore of that backup into a rolled cluster has not been demonstrated.
4. The target version is documented as rolling-compatible with the running one. A member whose binary supports a different stored format than its data reports `schema_old` or `schema_newer` and stays unready: that member will not serve. Do not roll across a release that needs a data migration; use a planned full stop with a backup instead.
5. Disk: every member's volume is below the 80% warning level.

## Order

Upgrade one member at a time, **followers first if you can tell the leader** (there is no operator command to move leadership in this release; a leader restart simply causes one election, during which writes through any member are retried with `503` with `retryable: true`, and then succeed). Keep at most one member down at a time so a quorum remains. Rolling a member onto a *different binary* has not been exercised by any test or drill (the cluster drills restart the same binary; Kubernetes was never run, see `distributed.md`), so the ordering above is a precaution, not a verified guarantee; check each member's `/readyz` before moving on.

For each member in turn:

1. Confirm the other two members are ready.
2. Restart that one member on the new image (below).
3. Wait until **that member's** `/readyz` is 200 again. A restarted member rejoins from its own durable journal and catches up from the other two; it is not ready until its quorum read round and apply backlog pass. Allow minutes for a large journal.
4. Confirm the control `applied_cursor` of the three members agree, and a write plus a read through the upgraded member succeed.
5. Only then move to the next member.

If the restarted member does not become ready within your bound (suggested: 10 minutes), **stop**. The other two voters still form a quorum and the installation is serving. Read that member's log (safe to read: it holds no credential), fix the cause, or put the previous image back on that one member. Never restart a second member while one is unready. Rolling back after the member has migrated its data is not possible (`schema_newer`).

### Compose (`deploy/compose.distributed.yaml`)

`SOUNDPOST_IMAGE` is the default for all three members; `SOUNDPOST_IMAGE_A`, `_B`, `_C` pin one member. Pin all three to the running image first so that a later plain `docker compose up -d` cannot move more than the member you choose:

```sh
export SOUNDPOST_IMAGE_A=soundpost:1.0.0 SOUNDPOST_IMAGE_B=soundpost:1.0.0 SOUNDPOST_IMAGE_C=soundpost:1.0.0
# member c first
export SOUNDPOST_IMAGE_C=soundpost:1.1.0
docker compose -f deploy/compose.distributed.yaml up -d --no-deps soundpost-c
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose -f deploy/compose.distributed.yaml ps -q soundpost-c)")" = healthy ]; do sleep 5; done
# then, with the cursors equal and a test write through c, b and finally a
```

`--no-deps soundpost-c` recreates only that container; its named data volume (its durable identity) is reused. Never `docker compose down -v` an installation you intend to keep: `-v` deletes the data volumes.

### Kubernetes (`deploy/helm/soundpost`)

Each member is its own single-replica StatefulSet with `updateStrategy: OnDelete`. **That is deliberate.** The StatefulSet controller does not consult a PodDisruptionBudget when it applies a rolling update, so three `RollingUpdate` sets (or one set with three replicas and a misconfigured `partition`) would restart voters without waiting for each other and could lose quorum. With `OnDelete`, `helm upgrade` only changes the desired pod template; no pod restarts until you delete it:

```sh
helm upgrade soundpost deploy/helm/soundpost -f values.yaml --set image.tag=1.1.0   # nothing restarts
for member in c b a; do
  kubectl delete pod "soundpost-$member-0"
  kubectl wait --for=condition=Ready "pod/soundpost-$member-0" --timeout=600s   # /readyz via the readiness probe
  # verify the other two are still Ready and the applied cursors agree before the next one
done
```

**Chart data layout change (`--data-dir=/var/lib/soundpost/data`).** Earlier chart versions passed `--data-dir=/var/lib/soundpost`, the PVC root. The chart now uses the `data/` subdirectory, which `serve` creates itself with mode `0700`; the PVC root cannot be private because `fsGroup` makes the kubelet set it group-writable (and a root-owned root on some provisioners cannot be chmod-ed by uid 65532). If you have a release whose members already hold data at the volume root, `helm upgrade` is still safe, because `OnDelete` restarts nothing. The old root holds `control.db`, `raft/` and the storage engine's own `data/` directory (`data/apply.db`, the slot WALs), so the new `data/` is the old engine directory and **the whole old root, including that `data/`, moves one level down**. For each such member, before `kubectl delete pod`, with the pod stopped (scale is not available; use a one-off pod that mounts the claim `data-soundpost-<m>-0` while the member is down, or do it on the node's volume), run once as uid/gid 65532 in the volume root:

```sh
cd /var/lib/soundpost            # the volume root as mounted in that pod; <m> is the member's claim
mkdir -m 0700 .layout-move
for e in $(ls -A); do case "$e" in .layout-move|lost+found) ;; *) mv "$e" .layout-move/ ;; esac; done
mv .layout-move data             # control.db -> data/control.db, raft/ -> data/raft, the old data/ -> data/data
ls -A                            # expect: data (and lost+found where the volume has one)
```

Then delete the pod and verify `/readyz` as above. A fresh install needs no step. (An earlier revision of this section said `mkdir -m 0700 data && mv <every entry except data> data/`; that cannot work, because `data/` already exists in the old root as the engine directory.)

**Guard against a missed move (`legacy_volume_layout`).** A pod deleted before the move would start its member on a fresh control state inside the old engine directory (the new `data/`), with the old `control.db` and `raft/` sitting unread one level up. `serve` therefore refuses to start when its data directory is named `data` and the directory above it holds `control.db` or `raft/` (the earlier layout). It checks first, before it creates or opens anything, prints `soundpost: legacy_volume_layout: ...` (no path) and exits 1; the volume is left exactly as it was. On Kubernetes the pod crash-loops and `kubectl wait --for=condition=Ready` times out, which is the "does not become ready: stop" case above: read the log, do the move, and delete the pod once more. The guard also fires when `control.db` or `raft/` is left beside a `data/` that already holds the member's data (a copy instead of a move): delete the stale copy once you have verified `data/`, and the member starts. Only a directory named `data` is judged, so the Compose files and the systemd unit (which pass the volume root itself) are not affected. The chart's `--data-dir` must stay `<mount>/data`; `TestChartDataDirIsWhatTheLegacyVolumeLayoutGuardJudges` fails if it does not.

Decision proposed by lane 1 wave 7, recommendation: accept. The check is in `serve` and not in a Helm pre-upgrade hook Job: a hook Job would have to mount each member's ReadWriteOnce claim while that member's pod is running, and a Job pod scheduled on another node cannot attach it; it would also guard only `helm upgrade`, not a pod recreated by any other means. `serve` runs with the volume mounted, on every start. What it cannot decide: old data that was moved somewhere other than `data/` is not recognised, and when both `data/` and the old files exist as copies (for example a member that ran once on a fresh `data/` under a build without this guard) it fires but which copy is current is the operator's call.

`kubectl wait` returns when the pod's readiness probe (`GET /readyz` over HTTPS) is satisfied. Run the loop by hand, one iteration at a time, if you want to check the cursors in between. The PodDisruptionBudget (`minAvailable: 2`) protects against a *second voluntary eviction* (node drain, cluster autoscaler) while one member is down; it is not an upgrade orchestrator.

Draining nodes: drain one node at a time and wait for the evicted member to become ready elsewhere before the next drain. Required anti-affinity means a member can only land on a node without another member; with exactly three eligible nodes the evicted member stays `Pending` until its node returns, which is correct (two voters keep serving).

## Running an older binary on a control.db (downgrade)

Not supported, and detected where it matters. Every state write of a build that keeps the node-local scrub marker also stores the SHA-256 of the stored state next to it (`state_seal` in the `control` bucket of `control.db`). An older binary that commits on the file does not know the seal, so the stored state no longer matches it; the next start of the newer binary then refuses the file at open with a typed `unsupported` fault instead of trusting a settled scrub marker the older binary never maintained (it applied erasures without recording that the free pages still held their payload). The refusal changes nothing in the file. Recovery is to restore a backup taken before the downgrade, or to roll the data onto a member rebuilt from the other voters (`Replacing a lost voter`). Residual: an older binary that opened the file and committed nothing leaves state and seal equal; nothing changed, so nothing is lost. A file written before this seal existed gets one at its first open. The same applies to `soundpost` rollbacks across the release that introduced the seal: a member that must go back to the older image has to be rebuilt, not rolled back in place.

## Deletion receipts across an upgrade (erase protocol)

The replicated acknowledgements a deletion receipt waits for (`docs/privacy/retention.md`, "Deletion") have three shapes: the attributed one of the release before this (`erase_ack` / `erase_unack` carrying a `proposer`), and the new ones (`erase_notice`, an acknowledgement with `basis` and `incarnation`, an `erase_unack` that declares a disk). A binary decodes these entries strictly, so a member that does not know a shape cannot apply it. The rule that keeps a rolling upgrade safe:

1. Roll every voter and learner to the new binary, one at a time, as above. A binary older than the one that introduced `proposer` is not supported in a mixed installation at all.
2. Until every member of the committed configuration has declared the protocol, the new binary proposes only the previous shapes; each upgraded member declares itself once it has a leader (an acknowledgement of a reserved operation in a shape the previous binary applies and ignores). A deletion receipt during that time behaves as it did before the upgrade: it names `data_apply_db` until every member acknowledged, and the protection against a snapshot install and a replaced disk (retention.md, limits (a) and (b2)) is not in force yet.
3. Once the last member declared, the new shapes start on their own; every voter acknowledges its completed deletions once more (previous-shape acknowledgements of a voter that declared its disk never stand), so receipts name the data store again until each voter has.
4. Never add a member that runs the older binary to an installation that already declared the protocol: it cannot apply the new entries and its group would fail. Upgrade a replacement before it joins.

## Fragment envelope (artifact fragments on the wire)

An artifact fragment is proposed to the replica group either as the JSON command every release has used (the fragment base64-encoded, then base64-encoded again by the replica layer) or, in this release, as a binary envelope (`internal/storage/envelope.go`: magic `0xF7 S P F`, version 1, head JSON, SHA-256, cursor, raw bytes). The envelope is a wire form only: every voter decodes either form, re-verifies the fragment digest while decoding, and stores the command as the same JSON text, so `replica_commands`, snapshots, backups, redaction digests and state digests do not depend on which form a proposer chose (`TestMixedFormatProposersLeaveIdenticalState`). Records written by older releases are JSON and keep reading (`TestDualFormatReaderReadsOldRecords`, golden `e805349` fragment).

A release without the dual-format reader refuses an envelope: its JSON decoder answers the typed `corrupt` fault for the leading `0xF7` byte (never a misread), and on a voter that is an apply failure of that group. So the envelope is off by default (`Engine.EnableFragmentEnvelope`), and the rule is: roll every voter to a release that reads both forms first, and enable proposing only after the last voter runs it; never add a member that runs an older release once it is enabled (the same rule as the erase protocol above). A reader that knows the envelope but not its version byte answers `invalid` with the detail `unsupported_fragment_envelope_version`.

## mTLS certificate rotation

A member loads its certificate, key and CA once at start (`tls.LoadX509KeyPair`, one CA pool); rotation therefore replaces files and **restarts that member**, one at a time, under the rules above. Identities never change: the leaf's URI SAN stays `spiffe://soundpost/node/<identity>` and its DNS/IP SANs still cover the member's peer address. A certificate with another identity or without the exact peer name is refused by the other members.

* **Leaf rotation (same CA).** Issue the new leaf and key for one member, replace that member's files (Compose: that member's configuration volume; Kubernetes: update its `pkiSecret`), restart that member, wait for `/readyz`, continue with the next. Peers that still hold the old leaf keep verifying the new one against the same CA.
* **CA rotation.** (1) Put the old and new CA certificates in one bundle file and roll every member to trust the bundle. (2) Roll every member to a leaf issued by the new CA. (3) Remove the old CA from the bundle and roll every member again. Each step is a full one-at-a-time roll; the installation is never trusting a CA that was not distributed everywhere first.
* Expiry: certificates must outlive your roll time by a wide margin. A member whose certificate has expired cannot be reached by peers and is a lost voter (two members still serve; a second expiry loses quorum).

This release rotates by restart. The live-rotation behaviour is documented from the code (`internal/appcore/replicated.go`), and the `install-distributed` smoke (process mode) exercises both procedures above: a leaf rotation under the same CA, then a CA rotation (bundle, new-CA leaves, bundle without the old CA), restarting one member at a time with the cluster ready and converged after each, and then requires a peer to refuse a client presenting an old-CA leaf. Container (Compose) mode does not run the rotation.

## Replacing a lost voter

A voter whose disk is lost is **not** restarted empty under its old identity. Follow `distributed.md` (new identity, learner first, joint-consensus replacement). The Compose/Helm manifests install the three initial voters; replacement is a membership operation, not a redeploy.
