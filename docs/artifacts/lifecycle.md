<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Artifact lifecycle in the served process

`artifacts.Lifecycle` owns artifact references, the retention decision for a map and the read fences. `appcore.Open` builds exactly one, over the application's own artifact service (`appcore.NewArtifactLifecycle`, exposed as `App.ArtifactLifecycle`), and installs it in two places.

| Install point | Effect |
|---|---|
| read gate of `App.Artifacts` | every read (`Get`, `ReadAuthorized`, `ReadSourcesAuthorized`, the HTTP read operation) also fences on the organization delete generation and on the artifact's reference state, and uses the visibility-bound fragment cache (4 MiB) |
| `App.Retention` as its `References` source (`retention.Service.UseReferences`) | an expiry pass asks `LatestReference` before it erases an artifact root |

The retention service is built before the lifecycle, because the lifecycle takes it as its delete-generation source (`LifecycleConfig.Deletes`). `UseReferences` binds the source once after `retention.New`, in the style of `UseAuthority`; a second binding is a `Conflict` and replaces nothing, and `nil` is `Invalid`.

## What a retention pass does with a map

The upload's own deadline (`RetainUntil` of the manifest) makes a root a candidate for `EraseExpired`. The guard then asks `LatestReference`:

* a deletion that covers the root answers zero: **deletion takes precedence** over any live reference, and the root is erased by the deletion's own saga (the deletion path never consults references);
* the latest deadline of any unreleased reference (error occurrence, profile or build record; `Reference` without a deadline means 90 days, at most 10 years) or the upload's own deadline, whichever is later, holds the root: the pass keeps it;
* when nothing holds it, the answer is zero **and the GC fence is taken in the same control transaction as the last check**: the reference ledger is marked retired and the artifact intent moves from `published` to `retired` together (see below), the map is unreadable from that moment, no reference can be added to it, and the erasure that follows removes it. A reference racing the erasure either was seen by the check or is refused afterwards;
* a durable journal pin (below) answers "retained": the map is neither fenced nor erased;
* a reference ledger that does not verify (edited, removed, rolled back to an older valid copy) makes `LatestReference` fail. The guard error aborts the whole pass **before anything is erased**; `RunOnce` returns the typed fault and `WorkerStatus.LastError` carries its code. The next pass over readable state erases what has expired.

A retention service with **no** References source never erases an artifact root: nothing could prove the root fenced, and erasing it would leave a published intent over missing bytes. The root is kept, `WorkerStatus.UnfencedBlobs` counts it, and the pass does not fail (records expire as always). The served process always binds a source.

## The retired intent and restart

Startup validation (`control.Store.ValidateArtifactReferences`) requires the bytes of every `published` artifact intent: a published intent whose blob is missing or corrupt stays `corrupt` (control never repairs authority from missing files). The GC fence therefore flips the intent itself to `retired` in the **same** control transition that sets the ledger's retired flag, before retention erases anything. Control reads only the plain intent state (it cannot import `artifacts`); a retired intent is still validated for structure and reservations but owns no bytes, is never returned by `LookupArtifact`, and cannot be published again (a re-upload of the same root is a conflict).

Crash safety follows from the order: a crash after the fence leaves a **retired** intent over **present** bytes, an orphan the next pass erases (`LatestReference` answers zero for a retired root); a published intent over missing bytes cannot arise from the lifecycle. A ledger fenced by an earlier build over a still-published intent is healed to `retired` by the next lifecycle operation on it, but an installation already in that state, with the bytes erased, still fails startup validation.

## Snapshot pins

`artifacts.SnapshotPins` is answered by the real durable journal pins of the control group and of every data group (`storage.Engine.JournalPins`, `replica.Group.Pins`), which are what a backup in flight and the copy of a snapshot hold. A pin names a Raft group's journal, not an organization, project or artifact root, so the answer is deliberately conservative: **while any pin is live every map is pinned**. Pins carry a lease; a pin left by a dead backup stops holding maps when it lapses or is dropped. A pin source that cannot be read is an error, never "no pin": the lifecycle reports `Unavailable` and the pass keeps the map.

## Not wired, and known gaps

* **Nothing in the product calls `Reference` yet.** `Reference` needs a user or server-token scope with `artifacts.write` over the artifact's project; the error intake runs under a source credential, which the artifact route and the lifecycle refuse by design, and the issue and job producers that would reconcile error occurrences and profiles with the artifacts they name do not exist in the served process. Until one does, a served process retains a map for the upload's own deadline only, and `Reference`/`Unreference` are reachable from Go code (the `artifact-policy` smoke and the tests) but from no route or worker.
* **Reads follow the upload's deadline, not the reference.** The scope check refuses a map whose manifest `RetainUntil` has passed, whatever a reference retains: a referenced map is kept as bytes until its last reference ends but is not readable after its own upload deadline. `Lifecycle.EffectiveRetention` reports the later deadline; no read path uses it.
* The expiry pass runs at most hourly (`WorkerConfig.ExpiryInterval`), so an expired map stays unerased until the next pass.
* The lifecycle reads the wall clock, the same clock `retention.New` defaults to; a test that needs time travel must restart the process or wait.
