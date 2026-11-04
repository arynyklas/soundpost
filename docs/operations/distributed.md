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

Physical layout manifests remain installation-wide local CAS operations. Their old format term is not mislabeled as a physical Raft term. Actual publication is guarded by fresh fences for all 64 owners and their serialized term checks; it returns unavailable when the node is not current leader for every required slot. That common-leader maintenance restriction is explicit: ordinary scoped ingestion/reads may route across independent leaders, but local manifest maintenance is not silently published under a pretend fixed leader term.

Workers must validate current group term/revision through a fresh quorum before publication/effects. FenceToken is not a user grant, destination credential or clock-only send lease. External send destinations still require their own durable fencing/idempotency protocol.

## Required local process drill

Run with the parent-controlled supported Linux Go toolchain:

```sh
GOTOOLCHAIN=local .tools/linux/go/bin/go test ./internal/replica ./internal/control ./internal/storage ./internal/appcore ./cmd/soundpost ./tools/smoke -count=1
GOTOOLCHAIN=local .tools/linux/go/bin/go run ./tools/smoke quorum-node-loss --nodes=3 --artifact-dir .superpowers/sdd/approved-product/01.06-quorum-linux
```

The drill provisions real authority through HTTPS, starts three actual server processes and private directories, and uses end-to-end-mTLS opaque TCP relays for a live bidirectional minority partition. It checks minority admission/fences, continued majority writes, then removes the current control/storage leader and quarantines its actual directory. A fresh fourth identity catches up as learner and is jointly promoted while replacing the lost voter. Every acknowledged batch, original receipt, origin cursor, timestamp and exact histogram count `9007199254740993` is reconciled using real authenticated scans and source receipt lookup on the surviving/replacement processes. Each original node is exercised as the current lost leader in an independent scenario.

A generated evidence artifact exists only after those runtime assertions finish. It explicitly reports local-process scope and missing distinct-physical-hardware/power-loss qualification. Authored code or an unexecuted command is not a process-drill PASS.
