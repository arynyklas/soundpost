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

**Chart data layout change (`--data-dir=/var/lib/soundpost/data`).** Earlier chart versions passed `--data-dir=/var/lib/soundpost`, the PVC root. The chart now uses the `data/` subdirectory, which `serve` creates itself with mode `0700`; the PVC root cannot be private because `fsGroup` makes the kubelet set it group-writable (and a root-owned root on some provisioners cannot be chmod-ed by uid 65532). If you have a release whose members already hold data at the volume root, `helm upgrade` is still safe, because `OnDelete` restarts nothing, but **deleting a pod before the move would start that member on an empty `data/` directory**. For each member, before `kubectl delete pod`, move the contents once, as uid/gid 65532, with the pod stopped (scale is not available; use a one-off pod that mounts the claim `data-soundpost-<m>-0` while the member is down, or do it on the node's volume): `mkdir -m 0700 data && mv <every entry except data> data/`. Then delete the pod and verify `/readyz` as above. A fresh install needs no step.

`kubectl wait` returns when the pod's readiness probe (`GET /readyz` over HTTPS) is satisfied. Run the loop by hand, one iteration at a time, if you want to check the cursors in between. The PodDisruptionBudget (`minAvailable: 2`) protects against a *second voluntary eviction* (node drain, cluster autoscaler) while one member is down; it is not an upgrade orchestrator.

Draining nodes: drain one node at a time and wait for the evicted member to become ready elsewhere before the next drain. Required anti-affinity means a member can only land on a node without another member; with exactly three eligible nodes the evicted member stays `Pending` until its node returns, which is correct (two voters keep serving).

## Deletion receipts across an upgrade (erase protocol)

The replicated acknowledgements a deletion receipt waits for (`docs/privacy/retention.md`, "Deletion") have three shapes: the attributed one of the release before this (`erase_ack` / `erase_unack` carrying a `proposer`), and the new ones (`erase_notice`, an acknowledgement with `basis` and `incarnation`, an `erase_unack` that declares a disk). A binary decodes these entries strictly, so a member that does not know a shape cannot apply it. The rule that keeps a rolling upgrade safe:

1. Roll every voter and learner to the new binary, one at a time, as above. A binary older than the one that introduced `proposer` is not supported in a mixed installation at all.
2. Until every member of the committed configuration has declared the protocol, the new binary proposes only the previous shapes; each upgraded member declares itself once it has a leader (an acknowledgement of a reserved operation in a shape the previous binary applies and ignores). A deletion receipt during that time behaves as it did before the upgrade: it names `data_apply_db` until every member acknowledged, and the protection against a snapshot install and a replaced disk (retention.md, limits (a) and (b2)) is not in force yet.
3. Once the last member declared, the new shapes start on their own; every voter acknowledges its completed deletions once more (previous-shape acknowledgements of a voter that declared its disk never stand), so receipts name the data store again until each voter has.
4. Never add a member that runs the older binary to an installation that already declared the protocol: it cannot apply the new entries and its group would fail. Upgrade a replacement before it joins.

## mTLS certificate rotation

A member loads its certificate, key and CA once at start (`tls.LoadX509KeyPair`, one CA pool); rotation therefore replaces files and **restarts that member**, one at a time, under the rules above. Identities never change: the leaf's URI SAN stays `spiffe://soundpost/node/<identity>` and its DNS/IP SANs still cover the member's peer address. A certificate with another identity or without the exact peer name is refused by the other members.

* **Leaf rotation (same CA).** Issue the new leaf and key for one member, replace that member's files (Compose: that member's configuration volume; Kubernetes: update its `pkiSecret`), restart that member, wait for `/readyz`, continue with the next. Peers that still hold the old leaf keep verifying the new one against the same CA.
* **CA rotation.** (1) Put the old and new CA certificates in one bundle file and roll every member to trust the bundle. (2) Roll every member to a leaf issued by the new CA. (3) Remove the old CA from the bundle and roll every member again. Each step is a full one-at-a-time roll; the installation is never trusting a CA that was not distributed everywhere first.
* Expiry: certificates must outlive your roll time by a wide margin. A member whose certificate has expired cannot be reached by peers and is a lost voter (two members still serve; a second expiry loses quorum).

This release rotates by restart. The live-rotation behaviour is documented from the code (`internal/appcore/replicated.go`), and the `install-distributed` smoke does not exercise a rotation.

## Replacing a lost voter

A voter whose disk is lost is **not** restarted empty under its old identity. Follow `distributed.md` (new identity, learner first, joint-consensus replacement). The Compose/Helm manifests install the three initial voters; replacement is a membership operation, not a redeploy.
