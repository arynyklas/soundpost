// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Delivery of a finished JS Self-Profiling report through the browser Client's REAL delivery queue (batching, canonical wire
// validation, receipts). The Profiler, clocks, timers and trace below are FAKES built in this file (bun has no DOM or JS
// Self-Profiling API); the transport is a recording ledger that issues genuine receipts for the batches the queue freezes.
// What the real server stores for these records is observed by the journeys smoke on Linux Chrome, not here.
import {test, expect} from "bun:test";
import {init, type Client, type Config} from "../src/index.ts";
import {createProfiler, startClientProfile, submitProfile, type ProfileOptions, type ProfileReport, type ProfilerEnv} from "../src/profile.ts";
import {config as coreConfig, signed, ORG, PROJECT, SOURCE} from "../../core/test/fixture.ts";
import {parseSafeRecord} from "../../core/src/wire.ts";
import type {FrozenBatch, Outcome, ReceiptTransport} from "../../core/src/transport.ts";

const ORIGIN = "https://soundpost.test";
const CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
const WALL = "1700000000000000000";

class DOMError extends Error {constructor(readonly domName: string) { super(domName); this.name = domName; }}
class Timers {
 now = 0; private next = 1; readonly queue = new Map<number, {at: number; fn: () => void}>();
 set = (fn: () => void, ms: number): number => { const id = this.next++; this.queue.set(id, {at: this.now + ms, fn}); return id; };
 clear = (handle: unknown): void => { this.queue.delete(handle as number); };
 async advance(ms: number): Promise<void> {
  const target = this.now + ms;
  for (;;) {
   const due = [...this.queue.entries()].filter(([, entry]) => entry.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
   if (!due) break;
   this.now = due[1].at; this.queue.delete(due[0]); due[1].fn(); await settle();
  }
  this.now = target;
 }
}
const settle = async (): Promise<void> => { for (let i = 0; i < 30; i++) await Promise.resolve(); };

interface Trace {resources: unknown; frames: unknown; stacks: unknown; samples: unknown}
interface Rig {env: ProfilerEnv; timers: Timers; trace: Trace | undefined; ctorError: unknown; hasProfiler: boolean; scope: "main" | "worker" | "unknown"}
function rig(over: Partial<Pick<Rig, "ctorError" | "hasProfiler" | "scope">> = {}): Rig {
 const r: Rig = {timers: new Timers(), trace: undefined, ctorError: undefined, hasProfiler: true, scope: "main", ...over} as Rig;
 let counter = 0;
 const Profiler = function (this: unknown) {
  if (r.ctorError !== undefined) throw r.ctorError;
  return {sampleInterval: 10, addEventListener() {}, removeEventListener() {}, stop: () => Promise.resolve(r.trace ?? {resources: [], frames: [], stacks: [], samples: []})};
 } as unknown;
 r.env = {
  get Profiler() { return r.hasProfiler ? Profiler : undefined; }, PerformanceObserver: undefined, get scope() { return r.scope; },
  origin: () => ORIGIN, userAgent: () => CHROME_UA, userAgentData: () => undefined, visibility: () => "visible", onVisibilityChange: () => () => {},
  isDOMException: error => error instanceof DOMError, now: () => 1000, wallNs: () => WALL,
  randomBytes: length => { counter++; return Uint8Array.from({length}, (_, i) => (counter * 17 + i * 3 + 1) % 255 + 1); },
  setTimeout: r.timers.set, clearTimeout: r.timers.clear, leaseHost: {},
 };
 return r;
}

/** A transport that records every frozen batch body and answers with a receipt that verifyReceipt accepts. */
class Ledger implements ReceiptTransport {
 readonly bodies: string[] = [];
 async send(batch: FrozenBatch): Promise<Outcome> {
  this.bodies.push(batch.body);
  return {kind: "receipt", receipt: {version: 1, batch_id: batch.id, hash: batch.hash, cursor: {group: "9".repeat(32), index: String(this.bodies.length)}, retain_until_ns: "9007199254740994", dedup_until_ns: "9007199254740994",
   signal_deadlines: batch.kinds.map(kind => ({kind, retain_until_ns: "9007199254740994"}))}};
 }
 async lookup(): Promise<Outcome> { return {kind: "not_found"}; }
 close(): void {}
}
type Wire = {id: string; kind: string; observed_at_ns: string; payload: Record<string, any>};
const sent = (ledger: Ledger): Wire[] => ledger.bodies.flatMap(body => (JSON.parse(body) as {records: Wire[]}).records);
function delivering(enable = true) {
 const ledger = new Ledger();
 const client = init({...coreConfig(), transport: ledger, ...(enable ? {deploymentProfiles: true} : {})});
 return {ledger, client};
}
/** One profile run through the real profiler with the delivery sink bound to the client, then a real flush. */
async function profileRun(rg: Rig, client: Client, options: ProfileOptions, trace?: Trace, stop = true) {
 const api = createProfiler(rg.env, report => submitProfile(client, report));
 const handle = await api.startProfile(options);
 rg.trace = trace;
 const report: ProfileReport | undefined = stop ? await handle.stop() : undefined;
 await settle();
 const flush = await client.flush(2000);
 return {report, flush, handle};
}

const OPTIONS: ProfileOptions = {durationMs: 5000, intervalUs: 10_000, scope: "main"};
function simpleTrace(): Trace {
 return {
  resources: [`${ORIGIN}/assets/app.js`],
  frames: [{name: "busyLoop", resourceId: 0, line: 10, column: 5}, {name: "outer", resourceId: 0, line: 20, column: 3}],
  stacks: [{frameId: 1}, {parentId: 0, frameId: 0}],
  samples: [{timestamp: 2000, stackId: 1}, {timestamp: 2010.5, stackId: 1}, {timestamp: 2021, stackId: 0}],
 };
}

test("a supported run enqueues exactly one capability and one linked profile chunk through the real queue", async () => {
 const {ledger, client} = delivering();
 const {report, flush} = await profileRun(rig(), client, OPTIONS, simpleTrace());
 expect(report?.capability.status).toBe("supported");
 expect(flush.pending).toBe(0); expect(flush.lost).toBe(0); expect(flush.receipts.length).toBeGreaterThan(0);
 const records = sent(ledger);
 expect(records.map(record => record.kind).sort()).toEqual(["capability", "profile_chunk"]);
 const capability = records.find(record => record.kind === "capability")!, chunk = records.find(record => record.kind === "profile_chunk")!;
 // The chunk names the capability record's own id, in the same clock domain.
 expect(chunk.payload.capability_id).toBe(capability.id);
 expect(chunk.payload.capability_id).toBe(report!.capability.id);
 expect(chunk.payload.clock.domain).toEqual(capability.payload.clock_domain);
 expect(capability.payload.signal).toBe("profile_chunk");
 expect(capability.payload.method).toBe("browser_js_self_profile");
 expect(capability.payload.status).toBe("supported"); expect(capability.payload.reason).toBe("ok");
 expect(capability.payload.coverage).toEqual({frames: "partial", threads: "partial", workers: "none", tasks: "none"});
 expect(BigInt(capability.payload.expires_ns)).toBeGreaterThan(BigInt(capability.observed_at_ns));
 // Chunk shape: the server's runtime_cpu vocabulary, relative sample times in ns, no line/column, an honest clock.
 expect(chunk.payload.method).toBe("runtime_cpu"); expect(chunk.payload.units).toBe("samples");
 expect(chunk.payload.samples.map((s: Record<string, string>) => s.at_ns)).toEqual(["0", "10500000", "21000000"]);
 expect(chunk.payload.samples.every((s: Record<string, string>) => s.count === "1" && s.thread === "1")).toBe(true);
 expect(chunk.payload.intervals).toEqual([]);
 expect(chunk.payload.clock.wall_ns).toBe(report!.clock.wall_start_ns); expect(chunk.payload.clock.mono_ns).toBe("0");
 expect(chunk.payload.clock.uncertainty_ns).toBe(report!.clock.uncertainty_ns);
 expect(BigInt(chunk.payload.end_ns)).toBeGreaterThanOrEqual(BigInt(chunk.payload.start_ns));
 expect(chunk.payload.frames.length).toBe(report!.frames.length); expect(chunk.payload.stacks.length).toBe(report!.stacks.length);
 for (const frame of chunk.payload.frames) { expect(Object.keys(frame).sort()).toEqual(["artifact_id", "function", "module_id", "offset", "reason"]); }
 expect(chunk.payload.frames.map((f: Record<string, string>) => f.module_id + "#" + f.function)).toContain("assets/app.js#busyLoop");
 expect(chunk.payload.process_id).not.toBe(chunk.payload.profile_id);
 // Every delivered record passes the SDK's own closed wire validation.
 for (const record of records) expect(() => parseSafeRecord(JSON.stringify({id: record.id, kind: record.kind, observed_at_ns: record.observed_at_ns, payload: record.payload, policy_revision: "1"}))).not.toThrow();
 expect(client.diagnostics()).toEqual({});
 await client.close();
});

test("a denied capability (Document-Policy missing) is delivered as the capability record only: no chunk, no samples", async () => {
 const {ledger, client} = delivering();
 const rg = rig({ctorError: new DOMError("NotAllowedError")});
 const {report} = await profileRun(rg, client, OPTIONS, simpleTrace());
 expect(report?.capability.status).toBe("denied"); expect(report?.capability.reason).toBe("document_policy_missing");
 const records = sent(ledger);
 expect(records.map(record => record.kind)).toEqual(["capability"]);
 const [capability] = records;
 expect(capability!.payload.status).toBe("denied"); expect(capability!.payload.reason).toBe("document_policy_missing");
 expect(capability!.payload.coverage).toEqual({frames: "none", threads: "none", workers: "none", tasks: "none"});
 expect(JSON.stringify(ledger.bodies)).not.toContain("profile_chunk\",\"");
 await client.close();
});

test("unsupported, scope-mismatch and invalid-option refusals are each delivered as capability truth with zero samples", async () => {
 for (const [rg, options, status, reason] of [
  [rig({hasProfiler: false}), OPTIONS, "unsupported", "js_self_profiling_unavailable"],
  [rig(), {...OPTIONS, scope: "worker"} as ProfileOptions, "denied", "isolate_scope_mismatch"],
  [rig(), {durationMs: 0} as ProfileOptions, "denied", "invalid_options"],
  [rig({ctorError: new Error("boom")}), OPTIONS, "error", "sampler_failed"],
 ] as const) {
  const {ledger, client} = delivering();
  await profileRun(rg, client, options, simpleTrace());
  const records = sent(ledger);
  expect(records.map(record => record.kind)).toEqual(["capability"]);
  expect([records[0]!.payload.status, records[0]!.payload.reason]).toEqual([status, reason]);
  await client.close();
 }
});

test("a malformed trace (status error) never becomes a fabricated profile", async () => {
 const {ledger, client} = delivering();
 const {report} = await profileRun(rig(), client, OPTIONS, {resources: [], frames: [], stacks: [{frameId: 9}], samples: [{timestamp: 1, stackId: 0}]});
 expect(report?.capability.status).toBe("error"); expect(report?.capability.reason).toBe("sampler_failed");
 expect(sent(ledger).map(record => record.kind)).toEqual(["capability"]);
 await client.close();
});

test("a supported run with only idle samples delivers its capability and a zero-sample chunk (truth, not a refusal)", async () => {
 const {ledger, client} = delivering();
 await profileRun(rig(), client, OPTIONS, {resources: [], frames: [], stacks: [], samples: [{timestamp: 5}, {timestamp: 15}]});
 const records = sent(ledger);
 expect(records.map(record => record.kind).sort()).toEqual(["capability", "profile_chunk"]);
 expect(records.find(record => record.kind === "profile_chunk")!.payload.samples).toEqual([]);
 await client.close();
});

test("privacy canary: query strings, fragments, foreign origins, argument-bearing names and extra trace fields never reach the wire", async () => {
 const {ledger, client} = delivering();
 const trace: Trace = {
  resources: [`${ORIGIN}/assets/app.js`, `${ORIGIN}/assets/app.js?token=CANARY_QUERY`, `${ORIGIN}/assets/chunk.js#CANARY_FRAGMENT`, "https://cdn.CANARY-host.example/lib/vendor.js", `${ORIGIN}/CANARY_PATH?x=1`],
  frames: [
   {name: "okFn", resourceId: 0, line: 1, column: 1, arguments: ["CANARY_ARG"], locals: {secret: "CANARY_LOCAL"}, source: "const CANARY_SOURCE = 1"},
   {name: "queryFn", resourceId: 1, line: 2, column: 2}, {name: "fragFn", resourceId: 2, line: 3, column: 3}, {name: "vendorFn", resourceId: 3, line: 4, column: 4},
   {name: "pathFn", resourceId: 4, line: 5, column: 5}, {name: 'handler("CANARY_CALL")', resourceId: 0, line: 6, column: 6}, {name: "/home/CANARY_USER/x.js", resourceId: 0, line: 7, column: 7},
  ],
  stacks: [{frameId: 0}, {frameId: 1}, {frameId: 2}, {frameId: 3}, {frameId: 4}, {frameId: 5}, {frameId: 6}],
  samples: [0, 1, 2, 3, 4, 5, 6].map(stackId => ({timestamp: 100 + stackId * 10, stackId})),
 };
 const {report} = await profileRun(rig(), client, OPTIONS, trace);
 expect(report?.capability.status).toBe("supported");
 expect(ledger.bodies.length).toBeGreaterThan(0);
 const wire = ledger.bodies.join("\n") + "\n" + client.bufferedRecords().join("\n");
 for (const canary of ["CANARY", "token=", "?x", "#", "arguments", "locals", "cdn.", "\\u0023"]) expect(wire).not.toContain(canary);
 const chunk = sent(ledger).find(record => record.kind === "profile_chunk")!;
 const modules = new Set(chunk.payload.frames.map((f: Record<string, string>) => f.module_id));
 expect([...modules].sort()).toEqual(["assets/app.js", "external"]);
 await client.close();
});

test("without the deployment opt-in nothing is enqueued and the refusal is counted, never sent", async () => {
 const {ledger, client} = delivering(false);
 await profileRun(rig(), client, OPTIONS, simpleTrace());
 expect(client.policyDecision.profiles).toBe(false);
 expect(ledger.bodies).toEqual([]); expect(client.bufferedRecords()).toEqual([]);
 expect(client.diagnostics().policy_disabled).toBe(1); expect(client.diagnostics().profile_chunk_dropped).toBe(1);
 await client.close();
});

test("a duration-timer finish delivers exactly once, and a later stop() does not deliver again", async () => {
 const {ledger, client} = delivering();
 const rg = rig();
 const api = createProfiler(rg.env, report => submitProfile(client, report));
 const handle = await api.startProfile({durationMs: 500, intervalUs: 10_000, scope: "main"});
 rg.trace = simpleTrace();
 await rg.timers.advance(500); await settle();
 expect(client.bufferedRecords().length).toBe(2);
 await handle.stop(); await handle.stop(); await settle();
 expect(client.bufferedRecords().length).toBe(2);
 await client.flush(2000);
 expect(sent(ledger).length).toBe(2);
 await client.close();
});

test("a large profile is split into bounded chunks that each stay under the queue's per-record cap and lose no sample", async () => {
 const {ledger, client} = delivering();
 const count = 3000, pad = "p".repeat(200);
 const trace: Trace = {
  resources: Array.from({length: count}, (_, i) => `${ORIGIN}/assets/${pad}${i}.js`),
  frames: Array.from({length: count}, (_, i) => ({name: "fn" + i, resourceId: i, line: 1, column: 1})),
  stacks: Array.from({length: count}, (_, i) => ({frameId: i})),
  samples: Array.from({length: count}, (_, i) => ({timestamp: 1000 + i * 10, stackId: i})),
 };
 const {report, flush} = await profileRun(rig(), client, {durationMs: 60000, intervalUs: 10_000, scope: "main", maxSamples: 8192}, trace);
 expect(report?.sample_count).toBe(count);
 const records = sent(ledger), chunks = records.filter(record => record.kind === "profile_chunk");
 expect(chunks.length).toBeGreaterThan(1);
 expect(flush.pending).toBe(0); expect(client.diagnostics().record_too_large).toBeUndefined();
 let total = 0;
 for (const chunk of chunks) {
  total += chunk.payload.samples.length;
  expect(new TextEncoder().encode(JSON.stringify(chunk)).length).toBeLessThan(262144);
  for (const sample of chunk.payload.samples) expect(sample.stack).toBeLessThan(chunk.payload.stacks.length);
  for (const stack of chunk.payload.stacks) for (const frame of stack.frames) expect(frame).toBeLessThan(chunk.payload.frames.length);
  expect(chunk.payload.profile_id).toBe(chunks[0]!.payload.profile_id);
  expect(chunk.payload.capability_id).toBe(records.find(record => record.kind === "capability")!.id);
 }
 expect(total).toBe(count);
 expect(new Set(chunks.map(chunk => chunk.id)).size).toBe(chunks.length);
 await client.close();
});

test("a closed client counts the profile as lost and never throws into the application", async () => {
 const {ledger, client} = delivering();
 await client.close();
 const api = createProfiler(rig().env, report => submitProfile(client, report));
 const handle = await api.startProfile(OPTIONS);
 await expect(handle.stop()).resolves.toBeDefined();
 expect(ledger.bodies).toEqual([]);
 expect(client.diagnostics().closed).toBeGreaterThan(0);
});

// Truncation (samples past maxSamples, frame/stack table bounds, browser buffer-full) is recorded as a delivery loss for the
// profile_chunk signal with reason "truncated", the way the core records every other signal loss: a durable `loss` record plus the
// delivery queue's per-signal counters. The chunk's own `loss`/`truncated` fields stay as they were.
const lossDoc = (loss: boolean): Config => {
 const doc: Record<string, unknown> = {version: 1, org: ORG, source: SOURCE, project: PROJECT, revision: "1", expires_ns: "9223372036854775807", errors: true, logs: true, replay: true, bodies: true, ...(loss ? {loss: true} : {})};
 return {...coreConfig(), deploymentProfiles: true, policy: signed(JSON.stringify(doc, Object.keys(doc).sort()))};
};
function truncatedTrace(samples: number): Trace {
 return {
  resources: [`${ORIGIN}/assets/app.js`], frames: [{name: "busyLoop", resourceId: 0, line: 10, column: 5}], stacks: [{frameId: 0}],
  samples: Array.from({length: samples}, (_, i) => ({timestamp: 2000 + i * 10, stackId: 0})),
 };
}

test("samples dropped past maxSamples are recorded as a profile_chunk truncated loss with the exact dropped count", async () => {
 const ledger = new Ledger();
 const client = init({...lossDoc(true), transport: ledger});
 const {report} = await profileRun(rig(), client, {...OPTIONS, maxSamples: 2}, truncatedTrace(5));
 expect(report?.sample_count).toBe(2); expect(report?.truncated).toBe(true);
 expect(report?.losses).toEqual([{reason: "truncated", count: "3"}]);
 const records = sent(ledger);
 const losses = records.filter(record => record.kind === "loss");
 expect(losses.length).toBe(1);
 expect(losses[0]!.payload.signal).toBe("profile_chunk"); expect(losses[0]!.payload.reason).toBe("truncated"); expect(losses[0]!.payload.count).toBe("3");
 expect(records.filter(record => record.kind === "profile_chunk")[0]!.payload.loss).toBe("3");
 expect(client.diagnostics().profile_samples_truncated).toBe(3);
 await client.close();
});

test("a profile that fits records no truncation loss", async () => {
 const ledger = new Ledger();
 const client = init({...lossDoc(true), transport: ledger});
 await profileRun(rig(), client, OPTIONS, truncatedTrace(3));
 expect(sent(ledger).filter(record => record.kind === "loss")).toEqual([]);
 expect(client.diagnostics().profile_samples_truncated).toBeUndefined();
 await client.close();
});

test("when the policy does not allow loss records the truncation is counted in diagnostics only and no loss record is sent", async () => {
 const ledger = new Ledger();
 const client = init({...lossDoc(false), transport: ledger});
 await profileRun(rig(), client, {...OPTIONS, maxSamples: 2}, truncatedTrace(5));
 expect(sent(ledger).filter(record => record.kind === "loss")).toEqual([]);
 expect(client.diagnostics().profile_samples_truncated).toBe(3);
 await client.close();
});

// ---- 10.17-W4: the acknowledgement cursor and the client's close ----------------------------------------------------------------
test("startClientProfile: the finished report carries the cursors the server acknowledged for its records", async () => {
 const {ledger, client} = delivering();
 const rg = rig();
 const handle = await startClientProfile(client, OPTIONS, rg.env);
 rg.trace = simpleTrace();
 const report = await handle.stop();
 expect(report.stopped_by).toBe("caller");
 expect(report.ack.status).toBe("obtained");
 const cursors = report.ack.status === "obtained" ? report.ack.cursors : [];
 expect(cursors.length).toBeGreaterThan(0);
 expect(cursors.every(cursor => typeof cursor === "string" && cursor.includes(":"))).toBe(true);
 expect(sent(ledger).map(record => record.kind).sort()).toEqual(["capability", "profile_chunk"]);
 expect((await handle.stop()).ack).toEqual(report.ack); // the same finished report, not a second delivery
 expect(sent(ledger).length).toBe(2);
 await client.close();
});

test("startClientProfile: a refusal at start is acknowledged as capability truth and the report says so", async () => {
 const {ledger, client} = delivering();
 const handle = await startClientProfile(client, OPTIONS, rig({ctorError: new DOMError("NotAllowedError")}).env);
 const report = await handle.stop();
 expect(report.stopped_by).toBe("not_started"); expect(report.capability.reason).toBe("document_policy_missing");
 expect(report.ack.status).toBe("obtained");
 expect(sent(ledger).map(record => record.kind)).toEqual(["capability"]);
 await client.close();
});

test("startClientProfile: records the policy refused are not_available, never a fabricated acknowledgement", async () => {
 const {ledger, client} = delivering(false);
 const handle = await startClientProfile(client, OPTIONS, rig().env);
 const report = await handle.stop();
 expect(report.ack).toEqual({status: "not_available", reason: "profile_not_admitted"});
 expect(sent(ledger)).toEqual([]);
 await client.close();
});

test("startClientProfile: a transport that never acknowledges is a failed ack, not an obtained one", async () => {
 const deaf = new (class extends Ledger { override async send(batch: FrozenBatch): Promise<Outcome> { this.bodies.push(batch.body); return {kind: "retry", delayMs: 1} as unknown as Outcome; } })();
 const client = init({...coreConfig(), transport: deaf, deploymentProfiles: true});
 const rg = rig();
 const handle = await startClientProfile(client, OPTIONS, rg.env);
 rg.trace = simpleTrace();
 const report = await handle.stop();
 expect(report.ack.status).toBe("failed");
 expect(report.ack.status === "failed" ? ["flush_deadline_exceeded", "no_acknowledged_cursor"].includes(report.ack.reason) : false).toBe(true);
 void client.close().catch(() => {});
});

test("startClientProfile: closing the client stops a running profile, delivers its report and only then shuts the queue", async () => {
 const {ledger, client} = delivering();
 const rg = rig();
 const handle = await startClientProfile(client, OPTIONS, rg.env);
 rg.trace = simpleTrace();
 await client.close();
 expect(sent(ledger).map(record => record.kind).sort()).toEqual(["capability", "profile_chunk"]); // delivered before the queue closed, not lost to it
 expect(client.diagnostics().closed).toBeUndefined();
 const report = await handle.stop();
 expect(report.stopped_by).toBe("client_close");
 expect(report.capability.status).toBe("supported"); expect(report.sample_count).toBe(3);
 expect(report.ack.status).toBe("obtained");
 expect(rg.timers.queue.size).toBe(0); // the duration timer is gone
});

test("startClientProfile: a run that already finished leaves no lease, so a later close does not touch it", async () => {
 const {ledger, client} = delivering();
 const rg = rig();
 const handle = await startClientProfile(client, {durationMs: 500, intervalUs: 10_000, scope: "main"}, rg.env);
 rg.trace = simpleTrace();
 await rg.timers.advance(500); await settle();
 await client.close();
 const report = await handle.stop();
 expect(report.stopped_by).toBe("duration");
 expect(sent(ledger).length).toBe(2);
});

test("startClientProfile: finished runs release their lease (the client holds at most 8), so a later run is still stopped by close", async () => {
 const {client} = delivering();
 for (let i = 0; i < 10; i++) {
  const rg = rig();
  const handle = await startClientProfile(client, {durationMs: 500, intervalUs: 10_000, scope: "main"}, rg.env);
  rg.trace = simpleTrace();
  await rg.timers.advance(500); await settle();
  expect((await handle.stop()).stopped_by).toBe("duration");
 }
 const rg = rig();
 const handle = await startClientProfile(client, OPTIONS, rg.env);
 rg.trace = simpleTrace();
 await client.close();
 expect((await handle.stop()).stopped_by).toBe("client_close"); // a leaked lease would have exhausted the cap and left this run unowned
});

test("Client.close: concurrent calls share one shutdown and the second resolves only after the profile was delivered", async () => {
 const {ledger, client} = delivering();
 const rg = rig();
 await startClientProfile(client, OPTIONS, rg.env);
 rg.trace = simpleTrace();
 const first = client.close(), second = client.close();
 expect(second).toBe(first);
 await second;
 expect(sent(ledger).map(record => record.kind).sort()).toEqual(["capability", "profile_chunk"]);
});

test("long-task entries are collected in the report and are NOT delivered: the wire carries the capability and the chunk only, nothing is dropped or counted", async () => {
 // Boundary test of the open part of 10.17#13: the SDK has no metric capture path (core CaptureInput has no metric kind, the signed policy has no metrics
 // switch, and a metric series has no label a browser could use to stay unique: internal/storage/apply.go refuses two values of one series at one instant).
 // Until the owner decides how a long task is represented, a collected entry is a local report field. This test fails the day delivery is added without a decision.
 class LongTaskObserver {
  static get supportedEntryTypes(): string[] { return ["longtask"]; }
  constructor(readonly callback: unknown) {}
  observe(): void {}
  disconnect(): void {}
  takeRecords(): unknown[] { return [{entryType: "longtask", name: "self", startTime: 1500.4, duration: 120.25}, {entryType: "longtask", name: "self", startTime: 1900, duration: 80}]; }
 }
 const {ledger, client} = delivering();
 const rg = rig();
 rg.env = {...rg.env, PerformanceObserver: LongTaskObserver};
 const {report} = await profileRun(rg, client, {...OPTIONS, longTasks: true}, simpleTrace());
 expect(report?.capability.status).toBe("supported");
 expect(report?.scope.long_tasks).toBe("observed");
 expect(report?.non_profile.map(entry => entry.duration_ms)).toEqual([120.3, 80]);
 expect(sent(ledger).map(record => record.kind).sort()).toEqual(["capability", "profile_chunk"]);
 expect(ledger.bodies.join("")).not.toContain("long_task");
 expect(client.diagnostics()).toEqual({});
 await client.close();
});
