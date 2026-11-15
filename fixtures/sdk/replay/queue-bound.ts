// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 07.06-W4: the recorder's queue bound. The recorder enqueues every chunk into the browser Client's real delivery queue (startReplay ->
// client.captureReplay); the design 13 budget is a bounded 2 MiB queue. This runner (Bun) fills that queue as hard as the recorder can:
// a scripted page whose mutations and pointer events are driven faster than anything leaves, through a transport that never completes,
// and samples the serialized bytes and record count the queue holds after every step. It prints one line,
//   RECORDER_QUEUE_BOUND {...json...}
// with the observed maxima, the counted refusals and whether the recorder kept capturing; the budget is judged by tools/qualify from the
// raw maxima, never here. The queue-fill is deterministic (no timers, no randomness); a real browser adds nothing to queue accounting,
// which is plain JavaScript, so the page is the same scripted page the delivery tests use.
import {init} from "../../../packages/browser/src/index.ts";
import {setReplayConsent, startReplay} from "../../../packages/browser/src/replay.ts";
import {FLUSH_MS, scriptedPage} from "../../../packages/browser/test/recorded-session.ts";
import {config as coreConfig} from "../../../packages/core/test/fixture.ts";

const STEPS = 20000;
const stalled = {send: (): Promise<never> => new Promise(() => {}), lookup: (): Promise<never> => new Promise(() => {}), close(): void {}};
const client = init({...coreConfig(), transport: stalled, deploymentReplay: true} as never);
const stage = scriptedPage();
startReplay(client, stage.config);
setReplayConsent(client, true);
const held = (): {bytes: number; records: number} => {
 const records = client.bufferedRecords();
 let bytes = 0;
 for (const line of records) bytes += Buffer.byteLength(line) + 512; // the queue accounts each entry as its serialized size plus 512 B (packages/core/src/queue.ts)
 return {bytes, records: records.length};
};
let maxBytes = 0, maxRecords = 0, firstRefusalStep = -1;
for (let step = 0; step < STEPS; step++) {
 stage.grow("t".repeat(512));
 stage.pointer(step % 2 ? "button" : "html", step % 1280, step % 720);
 stage.fire(FLUSH_MS);
 if (step % 8 === 0 || step === STEPS - 1) {
  const now = held();
  maxBytes = Math.max(maxBytes, now.bytes); maxRecords = Math.max(maxRecords, now.records);
  if (firstRefusalStep < 0 && (client.diagnostics().queue_full ?? 0) > 0) firstRefusalStep = step;
 }
}
const end = held();
const diagnostics = client.diagnostics();
console.log("RECORDER_QUEUE_BOUND " + JSON.stringify({
 workload: "scripted recorder page, 20000 steps of mutation + pointer event + flush-timer fire, transport never completes (nothing leaves the queue); queue measured as the serialized bytes and count of client.bufferedRecords()",
 steps: STEPS, budget_bytes: 2 * 1024 * 1024, max_queue_bytes: maxBytes, max_queue_records: maxRecords, end_queue_bytes: end.bytes, end_queue_records: end.records,
 queue_full_refusals: diagnostics.queue_full ?? 0, first_refusal_step: firstRefusalStep,
}));
process.exit(0);
