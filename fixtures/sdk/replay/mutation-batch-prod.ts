// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The page side of the "recorder p95 per mutation batch through the production consumer" budget test (mutation-batch.spec.ts): the REAL `startReplay` of the browser SDK feeding a REAL
// core client (`init`, replay enabled by a signed policy, the same fixture the unit tests use). Every chunk the recorder emits goes through core's own `captureReplay` -> normalisation ->
// serialisation -> admission, exactly as in production. The transport is a ledger in this page that issues receipts and never touches the network. The `tap` only counts chunks,
// checkpoints and gaps (it reads `sequence`, `checkpoint_sequence` and `gap`, never `nodes`), so what the spec times is the recorder plus the production serialisation.
import {init} from "../../../packages/browser/src/index.ts";
import {setReplayConsent, startReplay} from "../../../packages/browser/src/replay.ts";
import {config} from "../../../packages/core/test/fixture.ts";
import type {FrozenBatch, Outcome, ReceiptTransport} from "../../../packages/core/src/transport.ts";

/** Accepts every batch with a genuine receipt; nothing leaves the page. */
class InPageLedger implements ReceiptTransport {
 batches = 0;
 async send(batch: FrozenBatch): Promise<Outcome> {
  this.batches++;
  return {kind: "receipt", receipt: {version: 1, batch_id: batch.id, hash: batch.hash, cursor: {group: "9".repeat(32), index: String(this.batches)}, retain_until_ns: "9007199254740994", dedup_until_ns: "9007199254740994",
   signal_deadlines: batch.kinds.map(kind => ({kind, retain_until_ns: "9007199254740994"}))}};
 }
 async lookup(): Promise<Outcome> { return {kind: "not_found"}; }
 close(): void {}
}

const ledger = new InPageLedger();
const client = init({...config(), transport: ledger, deploymentReplay: true});
const counts = {chunks: 0, checkpoints: 0, gaps: 0};
const recorder = startReplay(client, {
 root: document.documentElement, replayId: "a".repeat(32), sessionId: "b".repeat(32), capturePolicyRevision: "1", domain: {host: "c".repeat(32), boot: "d".repeat(32), runtime: "e".repeat(32)},
 clock: () => ({wall_ns: String(BigInt(Date.now()) * 1000000n), mono_ns: String(BigInt(Math.round(performance.now() * 1e6))), uncertainty_ns: "1000000"}),
 viewport: () => ({w: innerWidth, h: innerHeight, x: scrollX, y: scrollY}),
}, chunk => {
 counts.chunks++;
 if (chunk.sequence === chunk.checkpoint_sequence) counts.checkpoints++;
 if (chunk.gap) counts.gaps++;
});
Object.assign(window, {
 __replay: {setConsent: (on: boolean) => { setReplayConsent(client, on); }},
 __counts: () => ({...counts}),
 /** Drains the client's queue through the ledger (a real page's own flush), between batches, never inside a timed callback. */
 __flush: async () => { const report = await client.flush(5000); return {pending: report.pending, lost: report.lost, receipts: report.receipts.length}; },
 __diagnostics: () => ({...client.diagnostics(), batches: ledger.batches}),
 __stop: () => { recorder.close(); },
 __ready: true,
});
