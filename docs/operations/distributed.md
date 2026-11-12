# Distributed durable groups

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

## Guarantee and qualification boundaries

The installed single-host application and distributed application use the same owned control/data state machines and the same etcd Raft Ready path. Single-host has one voter and is **not HA**. Distributed groups have three voters; a newly acknowledged command requires a durable Raft majority and installed application state, not merely a follower receiving network bytes.

The pinned primitive is generic `go.etcd.io/raft/v3 v3.7.0`, proxy origin `b867cf13f6bc0dae21204302df97bc2355c3af55`, with Go 1.26 minimum; the integration toolchain is Go 1.27.3. Raft is not an upstream telemetry backend. Soundpost owns admission, typed rows, receipts, scans, artifacts, quotas and application transitions.

Three directories and three processes on one host are **not three independent physical failure domains**. `ValidateFailureDomains` rejects duplicate/empty voter placement attestations, separately from node identity/URL validation. Those operator-supplied attestations do not prove hardware independence. Production HA qualification additionally requires independently verified hosts, storage devices, power and failure boundaries. That physical-hardware and power-loss qualification is not supplied by a local process drill.

## Persistence and response ordering

Each group has a private versioned, length-bounded, CRC32C Ready journal. New entries, HardState (including commit-only changes), and complete snapshots are fsynced before dependent messages, follower durable acknowledgements or `Advance`. Message-only Ready work relies on the previously durable prefix; it does not create fake durable copies. Write, short-write, sync and apply failures withhold acknowledgements and fail the affected group closed.

The application transaction installs typed records, original receipts, quota consumption/cancellation, index roots, private artifact fragments/GC state, exact applied command bytes and both applied watermarks together. The Raft journal is the only WAL for new proposals. Historical SPW1 files are a read-only import prefix, not an alternative runtime proposer. `storage.Open` is recovery/bootstrap only: no append, artifact mutation or publication may acknowledge before real consensus activation.

`replica_format`, its applied-command history and progress namespaces are authoritative. Missing initialized buckets, identity, required legacy coverage, acknowledged Ready journal coverage, corrupt interior frames or incomplete retained application coverage refuse startup. Only an incomplete unacknowledged journal tail can be truncated and synchronized. A missing initialized journal is never replaced with a newly bootstrapped authority. Supported filesystem namespace synchronization remains required; no error is converted to successful durability on Windows or unsupported filesystems.

Snapshots carry the complete authoritative application-command history, including normalized bytes, original receipts, artifact bytes/GC fences, source barriers and consumption/cancellation proofs. Control snapshots include leaf state and required protected envelope material. Snapshots carry membership and both cursor domains. This implementation deliberately does not truncate the durable Raft journal; manifests alone never authorize truncation or dropping the last committed copy. Capacity failures are unavailable, not a manifest-only substitute for retained bytes.

## Two explicit cursor domains

* `CommittedEntry.Term` and `CommittedEntry.Index` are physical Raft term/index.
* `CommittedEntry.ApplicationCursor` and C05 receipts/control results are stable, consecutive logical application cursors. Election no-ops and membership entries advance physical progress only.

ReadIndex obtains a real quorum-confirmed physical cut, waits for physical application, and returns its mapped logical application cut. A required receipt that has not applied produces a freshness/unavailable fault, never absence/EOF. Forwarded proposals also wait for the receiving node's physical application before returning; this prevents post-response local cleanup racing delayed application. Receipt hashes, retention deadlines, source/producer/slot identity and original logical cursors are unchanged by leadership or placement changes.

A complete legacy local prefix can be imported at a Raft snapshot cut without changing its old receipts. Offline seeds exported from an already-Raft installation carry physical progress and bootstrap at strictly later physical term/index; terms are not reset and an old worker's token cannot become current by coincidence.

## Actual authority and lock order

Control `Update` prepares an authorized transition on a detached leaf `model.ControlState`, outside a bbolt write transaction, then proposes an expected-revision replacement. Time/random/secret generation remains at the originating caller. Authorization callbacks and opaque `auth.Scope` values are never serialized or replayed. A stale revision returns a typed rejection; callbacks are not retried to regenerate IDs, timestamps or ciphertext. The deterministic applier performs the state CAS and applied-progress transaction only.

Every proposing storage path acquires `proposalMu` before `e.mu`. Only `e.mu` is released while waiting for Raft, so the same applier can acquire it. Admission preflight remains serial, and ordered apply uses the same index/receipt/private-blob hooks. Control apply never calls back into the engine. Owner outcome verification finishes before control mutation, preserving engine-order-lock → control-read ordering.

The internal forwarding route is mutual-TLS, certificate-identity and active-membership bound. It accepts only the closed, already-authorized leaf command union; it does not accept Scope objects, callbacks or raw user/source credentials. Consensus peers are a trusted non-Byzantine boundary, **not a source/user grant**. The actual leader revalidates current control revision or source liveness, policy epoch/revision, reservation and artifact cancellation/reference fences before ordering. Source expiry/revocation and post-commit release revalidation are not bypassed by forwarding. Requests are bounded and never follow arbitrary redirects or recursively forward through followers.

## Reservation reconciliation and cancellation

A reserved charge stays charged after an ambiguous append. The installed owner periodically reconciles actual durable consumption against control reservations, independently of a now-dead source credential. It installs the exact consumed cursor once and never recharges/refunds that consumption. No timer/router-death refund exists.

Before a new cancellation is ordered, the current owner obtains a fresh quorum/application fence and checks its commit-set ledger, including committed-but-unapplied and known uncommitted proposals. Any known candidate for that reservation prevents an absence proof. The owner records a watermark with physical commit/last index, logical applied cut and term, then commits the permanent no-use cancellation in the same ordered group. The persisted owner certificate and logical-to-physical coverage are checked before control can refund. An applied receipt's absence alone is not a Raft proof. A legacy imported cancellation relies only on its fully recovered, snapshot-certified local prefix, never on receipt absence in an unrecovered or new Raft stream.

## Identity and configuration

The peer listener is separate from public telemetry/session HTTPS. Peer TLS requires TLS 1.3, the configured CA, a client certificate and exactly one `spiffe://soundpost/node/<node_identity>` URI. Outgoing TLS also verifies the advertised server name and expected node URI. Sender IDs must match the verified peer certificate. A source bearer is never a peer credential.

A private node configuration contains, for example:

```json
{
  "node_id": "1",
  "peer_listen": "0.0.0.0:9444",
  "certificate": "/private/node-a.pem",
  "private_key": "/private/node-a.key",
  "ca": "/private/cluster-ca.pem",
  "seed": "/private/cluster.seed",
  "initial_leader": "1",
  "members": {
    "revision": "1",
    "nodes": [
      {"id":"1","address":"https://node-a.example.invalid:9444","node_identity":"node-a","failure_domain":"verified-host-a/disk-a"},
      {"id":"2","address":"https://node-b.example.invalid:9444","node_identity":"node-b","failure_domain":"verified-host-b/disk-b"},
      {"id":"3","address":"https://node-c.example.invalid:9444","node_identity":"node-c","failure_domain":"verified-host-c/disk-c"}
    ]
  }
}
```

`peer_source_ip` optionally binds outgoing connections to a real configured local interface/address. It changes neither certificate identity nor authorization. The local smoke uses distinct loopback source addresses only so ordinary user-space TCP relays can partition processes without firewall, network namespace or privilege changes.

## Initial seed and startup

Stop the one-voter service and obtain exclusive ownership of its private databases before generating an initial cluster seed:

```sh
soundpost cluster-seed --data-dir /private/single-installation --output /private/cluster.seed
soundpost serve --mode=distributed --node-id=1 --cluster-config=/private/node-a.json --data-dir=/private/node-a --listen=:8443 --tls-cert=/private/public-a.pem --tls-key=/private/public-a.key
```

Start the other configured voter processes concurrently with their own node IDs, certificates and independent private directories. Startup is bounded; lack of quorum, incomplete transfer, authority mismatch or required barrier failure does not open intake. The seed contains private telemetry and installation secrets. Transfer it only through an authenticated confidential operator channel and retain restrictive permissions. New nodes import the same complete authenticated installation seed before auth initializes; they do not independently bootstrap users, source keys or envelope authority.

Do not use an initial seed as an unaudited live membership reset, disaster restore or permission to reuse a lost voter identity. Normal bootstrap does not implement C12 disaster-restore authentication reactivation, backup authority or independent deletion-ledger qualification.

## Membership, readiness and maintenance

The injected `replica.Node` exposes `Propose`, `ReadIndex` and `ChangeMembers` by installed group ID. Membership changes are expected-revision, per-group operations. Add a fresh node identity as a learner first. Its authenticated readiness response must demonstrate physical application through the current cut (including inherited barriers); durable log match alone is insufficient. Promotion/replacement uses explicit joint consensus and waits for joint entry and exit application. Retiring peers remain authenticated during the joint phase. Repeating the same installed target can finish an interrupted explicit-joint exit. Missing groups never count as ready and there is no fake atomic transaction across the control and 64 data groups.

The 64 routing slots and their group identity derivation do not change with placement. C05 original dedup identities and source scope bindings remain fixed. Losing a voter disk requires a new identity, caught-up learner and joint replacement, not starting an empty old voter.

Physical layout manifests are node-local compare-and-swap operations on that node's own manifest revision; every voter rebuilds its layout from the replicated history. Publication (flush, compaction, snapshot coverage) therefore takes no leadership fence, no quorum round trip and no group lock: a leader, a follower, or a node that leads only some groups flushes, compacts and truncates its own journals (see [recovery.md](recovery.md)). The manifest's old format term is not mislabeled as a physical Raft term and stays a constant. Anything with an external effect (outbox sends, deletion, retention decisions) must be a replicated command and/or use `Group.Fence`/`ValidateFence`, never this local path.

Workers must validate current group term/revision through a fresh quorum before publication/effects. FenceToken is not a user grant, destination credential or clock-only send lease. External send destinations still require their own durable fencing/idempotency protocol.

## Deploying three voters: typed configuration, Compose, Kubernetes

Task 07.02 packages the engine described above; it adds no new consensus behaviour. The deployable artifacts are `internal/config` (typed installation file and validator), `deploy/compose.distributed.yaml`, `deploy/helm/soundpost`, [upgrade.md](upgrade.md) and [backup-authority.md](backup-authority.md).

### What the installation file is, and what it generates

`internal/config.InstallConfig` is a typed YAML document: `mode`, `replication_factor`, `cluster` (placement attestation, CA path, seed reference, initial leader, membership revision), `nodes` (identity, failure domain, peer address, disk, certificate, private-key reference), `listen` (address and exact public origins), `sources`, `quotas`, `retention`, `backup` (none, local, or off-host with the C12 authority) and optional `collector_grants`. For a distributed installation it **generates the real per-node file** shown under "Identity and configuration" (it marshals `appcore.NodeConfig` itself, so the schema cannot drift from `serve --cluster-config`):

```sh
go run ./internal/config/cmd/soundpost-config validate install.yaml
go run ./internal/config/cmd/soundpost-config render   install.yaml --out out/    # out/node-1.json ... node-3.json (0600)
```

A complete Compose-shaped example (generic names; nothing here is a credential):

```yaml
mode: distributed
replication_factor: 3
cluster:
  placement: simulated                 # simulated | physical (an operator attestation)
  ca: /etc/soundpost/pki/ca.pem
  seed: file:/etc/soundpost/cluster.seed
  initial_leader: 1
  members_revision: 1
nodes:                                  # repeat for node-b (id 2) and node-c (id 3): every value below must differ
  - id: 1
    identity: node-a                    # certificate URI SAN spiffe://soundpost/node/node-a
    failure_domain: compose-volume-a
    peer_address: https://soundpost-a:9444
    peer_listen: 0.0.0.0:9444
    disk: {id: volume-a, volume: soundpost-a-data, path: /var/lib/soundpost, capacity_bytes: 107374182400}
    certificate: /etc/soundpost/pki/a.pem
    private_key: file:/etc/soundpost/pki/a.key
listen: {address: 0.0.0.0:8443, public_origins: ["https://soundpost.example.invalid"]}
sources: [{id: backend, class: private}, {id: web, class: browser, origins: ["https://app.example.invalid"]}]
quotas: {max_bytes_per_source: 1073741824, max_series_per_source: 1000}
retention: {days: {metric: 30, log: 14}}
backup: {mode: none}                    # none | local | offhost (see backup-authority.md)
```

`Validate` refuses what would make three nodes fewer than three, before the engine starts: a shared member identity or raft id; a shared volume, disk device, certificate, private key or peer address; a shared or empty failure-domain attestation; data directories that contain each other; not exactly three voters (a learner is not a voter and may not be in the initial membership); a replication factor other than 3 (the engine implements one or three voters, and `OpenDistributed` requires three); an initial leader that is not a voter; missing mTLS trust material (CA, per-member certificate and `file:` key reference, seed). It then runs the engine's own `replica.ValidateMembers` on the generated membership, so it can only be stricter than startup. Errors name the field and the rule, never a value. Secret references (`env:`, `file:`, `k8s:`) are redacted by every formatter, JSON/YAML encoder and `slog` value. `config.Qualification` prints what the placement does and does not prove.

### Failure domains: what Compose is and is not

`cluster.placement: simulated` is the only honest value for Compose and for three directories on one host. **Three containers with three named volumes on one Docker host are process and disk simulations, not three physical failure domains**: they share the kernel, disk controller, power and the Docker daemon, so a host loss loses all three voters. The Compose file exists to rehearse the protocol and to test; the smoke below runs it. `physical` is an operator attestation of independent hosts, storage, power and network that nothing here verifies.

### Compose (three containers of the produced image)

```sh
go run ./build image-context --release dist --arch amd64 --out ctx
docker build --network=none -t soundpost:1.0.0 ctx          # offline: FROM scratch, no download
export SOUNDPOST_IMAGE=soundpost:1.0.0
```

1. Bootstrap one single installation (`install-single.md`), stop it, and export the seed from its stopped data volume: `docker run --name seed-out -v <its volume>:/var/lib/soundpost "$SOUNDPOST_IMAGE" cluster-seed --data-dir /var/lib/soundpost --output /var/lib/soundpost/cluster.seed`, then `docker cp seed-out:/var/lib/soundpost/cluster.seed .` and `docker rm seed-out`. The seed contains private installation secrets; keep it in a restricted directory and delete the single installation's volume when the cluster is up (the seed is not a membership reset).
2. Write `install.yaml` for three members with `placement: simulated`, peer addresses `https://soundpost-a:9444` (the Compose service names, which are also the certificates' DNS SANs), `peer_listen: 0.0.0.0:9444`, per-member certificate `/etc/soundpost/pki/<name>.pem` and key `file:/etc/soundpost/pki/<name>.key`, `cluster.ca: /etc/soundpost/pki/ca.pem` and `cluster.seed: file:/etc/soundpost/cluster.seed`. Each member's certificate carries the URI SAN `spiffe://soundpost/node/<identity>`, the DNS name of its service and is signed by the cluster CA.
3. Render the node files and fill **one configuration volume per member** with only that member's files, owned by uid 65532 and unreadable by anyone else (the image runs as 65532 and the key must not be readable by other members):

```sh
for m in a b c; do   # stage/<m> holds node-N.json, cluster.seed, pki/ca.pem, pki/<m>.pem, pki/<m>.key
  docker volume create soundpost-$m-config
  docker create --name fill-$m -v soundpost-$m-config:/etc/soundpost "$SOUNDPOST_IMAGE"
  tar -C stage/$m --owner=65532 --group=65532 --mode='u=rX,go=' -cf - . | docker cp - fill-$m:/etc/soundpost
  docker rm fill-$m
done
docker compose -f deploy/compose.distributed.yaml up -d
```

The data volumes `soundpost-{a,b,c}-data` are created empty on first start (mode 0700, uid 65532 inherited from the image) and hold each member's durable identity. The three configuration volumes are mounted read-only. The public ports are published on `127.0.0.1` only (`SOUNDPOST_PUBLISH_A/B/C` change that); the peer port 9444 is on an `internal` network and is never published. Each container's health check is `soundpost ready`, which asks that member's own `/readyz`: a member is healthy only when it has quorum and has applied its backlog. Do not `docker compose down -v` an installation you keep.

The optional native helper is the `native` Compose profile; see "Native acquisition permissions" below.

### Kubernetes (Helm)

`deploy/helm/soundpost` renders, for three members, one StatefulSet **each** (`replicas: 1`, a literal `--node-id`, its own PersistentVolumeClaim `data-soundpost-<m>-0`, `Retain` on delete, `updateStrategy: OnDelete`), a per-member configuration Secret containing exactly the node file (paths and membership, no key material), a headless peer Service with `publishNotReadyAddresses` and per-pod DNS names, a ClusterIP public Service that selects only ready pods, a PodDisruptionBudget with `minAvailable: 2`, a NetworkPolicy and required pod anti-affinity (a member cannot share a node with another). It creates **no** certificate, key or seed: you create these Secrets out of band and reference them by name in `values.yaml`:

```sh
kubectl -n soundpost create secret generic soundpost-a-pki --from-file=tls.crt=a.pem --from-file=tls.key=a.key   # and b, c
kubectl -n soundpost create secret generic soundpost-cluster-ca   --from-file=ca.crt=ca.pem
kubectl -n soundpost create secret generic soundpost-cluster-seed --from-file=cluster.seed=cluster.seed
helm install soundpost deploy/helm/soundpost -n soundpost --set image.repository=REGISTRY/soundpost --set image.digest=sha256:...
```

Each member certificate needs the URI SAN `spiffe://soundpost/node/<identity>` and the DNS SAN `soundpost-<m>-0.soundpost-peer.<namespace>.svc`. The chart refuses to render without an image, with a replication factor other than 3, with a `minAvailable` other than 2, or with other than three members. The NetworkPolicy lets members reach each other **only on the mTLS peer port** (ingress and egress), allows DNS and any `extraEgress` you add (an object store for off-host backup), and denies public ingress until you list `publicIngressFrom`; it is enforced only by a CNI that implements NetworkPolicy. Readiness is the committed `GET /readyz` route over HTTPS (startup and readiness probes); there is deliberately no liveness probe, because restarting a member that lost quorum only deepens an outage. `failureDomain` in `values.yaml` is an attestation: it is true only if your scheduler really places the pods on independent nodes, zones and storage.

Rolling upgrades and certificate rotation are one-member-at-a-time procedures: [upgrade.md](upgrade.md).

### Native acquisition permissions (server versus helper)

The server container never holds `CAP_PERFMON`, never has a seccomp relaxation, is never privileged and never shares a host PID, network or IPC namespace. Without `CAP_PERFMON` (and under the runtime-default seccomp profile, which admits `perf_event_open` only with that capability) the server cannot perf-open. Native acquisition is a **separate, optional helper** (`cmd/soundpost-perf-acquire`, its own image that this release does not build): the Compose `native` profile or the chart's `perfHelper.enabled`. It holds exactly `PERFMON` (every other capability dropped, `no-new-privileges`), the audited seccomp profile `deploy/seccomp/soundpost-perf.json` (deny by default; `perf_event_open` only with `PERF_FLAG_FD_CLOEXEC`; no ptrace, bpf, memory inspection), no network, a read-only root. There is no privileged, unconfined or `SYS_ADMIN` fallback anywhere. A deployment the host refuses (`perf_event_paranoid`, LSM, missing target PID visibility, tracefs, the profile not installed) leaves the capability **denied**; the platform reports it unavailable and never as a zero or complete profile.

Two runtime findings shape the manifests (observed with `install-distributed` on Docker 29.9.2 / runc 1.5.2, kernel 6.6 WSL2, `perf_event_paranoid=2`): (1) the helper container runs as **uid 0 holding only `CAP_PERFMON`**, because Docker and Kubernetes have no ambient capabilities: a non-root container process with `cap_add: [PERFMON]` is still denied (`EACCES`) while uid 0 with only `PERFMON` is allowed, and uid 0 without it is denied. The systemd helper (`packaging/systemd/soundpost-perf-acquire.service`) uses `AmbientCapabilities` for a dedicated non-root account instead; prefer it where a host service is acceptable. (2) runc needs `execve` and `fstatfs` after it installs the filter and before the container process runs its first instruction. Without them a container fails to start: observed on runc 1.5.2 (Docker) and again on runc 1.4.2 under k3s v1.37.2, where the profile without them gives `StartError ... fstatfs ... operation not permitted`, and with only `fstatfs` added `exec /soundpost: operation not permitted`. The shipped profile therefore allows exactly those two syscalls in one unconditional rule (JSON has no comments; this paragraph and `build/deploy_sandbox_test.go` are the record); nothing else was added, and `PERFMON` is still required for `perf_event_open`.

Operator setup that the manifests cannot do for you: install the seccomp profile (Compose: the file path, `SOUNDPOST_PERF_SECCOMP`; Kubernetes: `<kubelet root>/seccomp/soundpost/soundpost-perf.json` on every node, `type: Localhost`), provision the root-owned operator policy (`SOUNDPOST_PERF_POLICY` / `perfHelper.policySecret`), choose the PID namespace of the workload to profile explicitly (`SOUNDPOST_PERF_PID=container:<workload>`; Kubernetes `perfHelper.hostPID`, default `false`, which keeps the capability denied) and create the root-owned 0700 `/run/soundpost-perf` socket directory (a host-path exception in Kubernetes). The Compose defaults for the helper image, PID namespace and policy name things that do not exist, so an unconfigured `--profile native` fails closed. The container tag cannot supply a kernel: record `uname -r` of the host (the smoke does). Kernel 6.1/6.6 amd64/arm64 qualification (plan 04) is a property of the host kernel, not of an image.

`install-distributed` checks the permission separation at runtime when Docker and an image are available: a `perf_event_open` probe runs under the **Compose file's own settings** for a server member, for the helper, and for the helper without `PERFMON`, and the smoke records what the kernel and seccomp did on that host.

### Evidence: the three-member smoke

```sh
go run ./tools/smoke install-distributed --artifact-dir smoke-out --binary dist/linux-amd64/soundpost --release dist     # three processes
go run ./tools/smoke install-distributed --artifact-dir smoke-out --container soundpost:1.0.0                              # three containers via deploy/compose.distributed.yaml
```

Both generate the node files with `internal/config`, bootstrap and seed an installation, start three members, wait for each member's `/readyz`, ingest through the initial leader and query through followers, kill the initial leader and require writes to keep committing through another member, restart it and require it to rejoin and converge (same query answer, same control applied cursor), kill two members and require a typed `503` refusal (retryable, no cursor, no receipt; observed code `stale`) with no acknowledgement, and a `503` `/readyz` from the survivor (observed reason `state_unavailable`: the 3 s evaluation bound elapses before the failed quorum round is reported as `no_quorum`), restart them and require convergence again, check private modes and that no log line contains a credential or private-key material, run the off-host backup authority gate of [backup-authority.md](backup-authority.md) against the real authority on a local directory and run the native-permission probe. The artifact (`install-distributed.json`) lists what was **not** run: an authorized Kubernetes cluster, independent physical hosts, restore into a three-voter cluster, kernel 6.1 and arm64.

## Required local process drill

Run with the parent-controlled supported Linux Go toolchain:

```sh
GOTOOLCHAIN=local .tools/linux/go/bin/go test ./internal/replica ./internal/control ./internal/storage ./internal/appcore ./cmd/soundpost ./tools/smoke -count=1
GOTOOLCHAIN=local .tools/linux/go/bin/go run ./tools/smoke quorum-node-loss --nodes=3 --artifact-dir .superpowers/sdd/approved-product/01.06-quorum-linux
```

The drill provisions real authority through HTTPS, starts three actual server processes and private directories, and uses end-to-end-mTLS opaque TCP relays for a live bidirectional minority partition. It checks minority admission/fences, continued majority writes, then removes the current control/storage leader and quarantines its actual directory. A fresh fourth identity catches up as learner and is jointly promoted while replacing the lost voter. Every acknowledged batch, original receipt, origin cursor, timestamp and exact histogram count `9007199254740993` is reconciled using real authenticated scans and source receipt lookup on the surviving/replacement processes. Each original node is exercised as the current lost leader in an independent scenario.

A generated evidence artifact exists only after those runtime assertions finish. It explicitly reports local-process scope and missing distinct-physical-hardware/power-loss qualification. Authored code or an unexecuted command is not a process-drill PASS.
