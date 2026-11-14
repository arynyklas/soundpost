// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Delivery of recorder chunks through the browser Client's REAL queue: closed wire validation, policy gate, batching and
// receipts. The page, clock and timers are scripted fakes (recorded-session.ts); the transport is a ledger that issues
// genuine receipts. What the real server stores for these chunks is observed by the evidence and journeys smokes.
import {test, expect} from "bun:test";
import {createHash} from "node:crypto";
import {init, type Client} from "../src/index.ts";
import {setReplayConsent, startReplay} from "../src/replay.ts";
import {canonicalJSON} from "../src/replay/policy.ts";
import {FLUSH_MS, scriptedPage} from "./recorded-session.ts";
import {config as coreConfig} from "../../core/test/fixture.ts";
import type {FrozenBatch, Outcome, ReceiptTransport} from "../../core/src/transport.ts";
import type {ReplayChunk} from "../src/replay/types.ts";

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
interface Wire {id: string; kind: string; observed_at_ns: string; payload: Record<string, unknown>}
const sent = (ledger: Ledger): Wire[] => ledger.bodies.flatMap(body => (JSON.parse(body) as {records: Wire[]}).records);
const hash = (payload: unknown): string => createHash("sha256").update(canonicalJSON(payload)).digest("hex");
const queued = (client: Client): Wire[] => client.bufferedRecords().map(line => JSON.parse(line) as Wire);

function rig(over: Record<string, unknown> = {}, enable = true) {
 const ledger = new Ledger();
 const client = init({...coreConfig(), transport: ledger, ...(enable ? {deploymentReplay: true} : {}), ...over});
 return {ledger, client, stage: scriptedPage()};
}

test("recorder chunks are enqueued by the client itself, flushed with receipts, and chain exactly as recorded", async () => {
 const {ledger, client, stage} = rig();
 startReplay(client, stage.config);
 setReplayConsent(client, true);
 stage.pointer("button", 123, 45); stage.fire(FLUSH_MS);
 stage.grow("SECRET-LATE-TEXT");
 expect(queued(client).map(record => record.kind)).toEqual(["replay_chunk", "replay_chunk", "replay_chunk"]);
 const report = await client.flush(2000);
 setReplayConsent(client, false);
 expect(report.pending).toBe(0); expect(report.lost).toBe(0); expect(report.receipts.length).toBeGreaterThan(0);
 const records = sent(ledger);
 expect(records.map(record => record.kind)).toEqual(["replay_chunk", "replay_chunk", "replay_chunk"]);
 const chunks = records.map(record => record.payload);
 expect(chunks.map(chunk => chunk.sequence)).toEqual(["1", "2", "3"]);
 expect(chunks[0]!.previous_hash).toBe("0".repeat(64));
 expect(chunks[1]!.previous_hash).toBe(hash(chunks[0]));
 expect(chunks[2]!.previous_hash).toBe(hash(chunks[1]));
 expect(chunks[2]!.checkpoint_hash).toBe(hash(chunks[0]));
 for (const record of records) expect(record.observed_at_ns).toBe((record.payload.clock as {wall_ns: string}).wall_ns);
 expect(JSON.stringify(records)).not.toContain("SECRET");
 expect(client.diagnostics()).toEqual({});
 await client.close();
});

test("the optional tap sees every chunk, and its own failure does not break delivery", async () => {
 const {ledger, client, stage} = rig();
 const tapped: ReplayChunk[] = [];
 startReplay(client, stage.config, chunk => { tapped.push(chunk); throw Error("viewer broke"); });
 setReplayConsent(client, true);
 stage.pointer("html", 8, 8); stage.fire(FLUSH_MS);
 await client.flush(2000);
 setReplayConsent(client, false);
 expect(tapped.map(chunk => chunk.sequence)).toEqual(["1", "2"]);
 expect(sent(ledger).map(record => record.payload.sequence)).toEqual(["1", "2"]);
 await client.close();
});

test("without the deployment's replay opt-in nothing is observed or queued", async () => {
 const {ledger, client, stage} = rig({}, false);
 startReplay(client, stage.config);
 setReplayConsent(client, true);
 stage.pointer("button", 1, 1); stage.fire(FLUSH_MS);
 expect(client.bufferedRecords()).toEqual([]);
 await client.flush(500);
 expect(ledger.bodies).toEqual([]);
 await client.close();
});

test("revoking consent destroys the replay chunks still waiting in the queue and leaves every other record alone", async () => {
 const {ledger, client, stage} = rig();
 startReplay(client, stage.config);
 client.captureException(Error("BEFORE"));
 setReplayConsent(client, true);
 stage.pointer("button", 5, 5); stage.fire(FLUSH_MS);
 expect(queued(client).filter(record => record.kind === "replay_chunk")).toHaveLength(2);
 setReplayConsent(client, false);
 expect(queued(client).map(record => record.kind)).toEqual(["error"]);
 client.captureException(Error("AFTER"));
 await client.flush(2000);
 expect(sent(ledger).map(record => record.kind)).toEqual(["error", "error"]);
 // A resumed recording restarts with a gap-marked checkpoint that continues the sequence: the destroyed chunks are a visible hole.
 setReplayConsent(client, true);
 await client.flush(2000);
 const resumed = sent(ledger).filter(record => record.kind === "replay_chunk").map(record => record.payload);
 expect(resumed).toHaveLength(1);
 expect(resumed[0]!.sequence).toBe("3"); expect(resumed[0]!.gap).toBe(true);
 await client.close();
});

test("a full queue refuses the chunk to the recorder, which counts the loss and heals with a gap-marked checkpoint", async () => {
 const {ledger, client, stage} = rig({maxRecords: 2});
 client.captureException(Error("ONE")); client.captureException(Error("TWO"));
 startReplay(client, stage.config);
 setReplayConsent(client, true); // checkpoint 1 refused: queue_full
 expect(client.diagnostics().queue_full).toBeGreaterThan(0);
 await client.flush(2000); // room again
 stage.fire(FLUSH_MS); // recovery checkpoint
 await client.flush(2000);
 const chunks = sent(ledger).filter(record => record.kind === "replay_chunk").map(record => record.payload);
 expect(chunks).toHaveLength(1);
 expect(chunks[0]!.gap).toBe(true); expect(chunks[0]!.loss).toBe("1"); expect(chunks[0]!.sequence).toBe("2");
 await client.close();
});
