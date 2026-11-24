// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The recount an id-space checkpoint does (ids are unique since the last checkpoint, so the live tree is only recounted by a checkpoint) used to happen inside the observer
// callback that reached the cap: 5-8 ms for a few thousand nodes, the slowest batches of the 400-node Firefox row. It is now prepared between callbacks once the ids are nearly
// used up: the page is walked into a second epoch of ids in slices of PREPARE_SLICE_NODES nodes, fitted, then written, each its own timer task. The chunk is an ordinary
// checkpoint (wire unchanged); a batch that arrives after the walk began makes it stale and it starts over. Driven through the real recorder over the scripted page.
import {test, expect} from "bun:test";
import {createHash} from "node:crypto";
import {createRecorder} from "../src/replay/recorder.ts";
import {canonicalJSON, MAX_NODES, PREPARE_HEADROOM, PREPARE_RESTARTS, PREPARE_SLICE_NODES} from "../src/replay/policy.ts";
import type {ReplayChunk} from "../src/replay/types.ts";
import {CHECKPOINT_MS, scriptedPage} from "./recorded-session.ts";

class Inert { observe(): void {} disconnect(): void {} }
type Stage = ReturnType<typeof scriptedPage>;

function rig() {
 const stage = scriptedPage();
 const chunks: ReplayChunk[] = [];
 let slices = 0;
 const base = stage.config.timers!;
 const timers = {set: (callback: () => void, ms: number) => { if (ms === 0) slices++; return base.set(callback, ms); }, clear: base.clear};
 const recorder = createRecorder({...stage.config, timers, projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(JSON.parse(JSON.stringify(chunk))); return "accepted"; });
 recorder.setConsent(true);
 return {stage, chunks, recorder, slices: () => slices};
}
/** Churns until the ids used since the checkpoint pass the point where a recount is prepared (each call re-reads <section> with 1,000 new paragraphs: 1,000 new ids, a small live tree). */
function churnToThreshold(stage: Stage): void { for (let i = 0; i < Math.ceil((MAX_NODES - PREPARE_HEADROOM) / 1000); i++) stage.churn(1000); }
const checkpoints = (chunks: readonly ReplayChunk[]): ReplayChunk[] => chunks.filter(chunk => chunk.sequence === chunk.checkpoint_sequence);
/** Runs the prepared checkpoint's timer tasks (each `fire(0)` is one slice) until a second checkpoint exists; returns how many ran. */
function slicesUntilCheckpoint(stage: Stage, chunks: readonly ReplayChunk[], have = 1): number {
 let passes = 0;
 while (checkpoints(chunks).length === have && passes < 200) { stage.fire(0); passes++; }
 return passes;
}
/** The first checkpoint a recorder makes of the page as it is now: what a synchronous recount would emit. */
function fresh(stage: Stage): ReplayChunk {
 const chunks: ReplayChunk[] = [];
 createRecorder({...stage.config, observer: Inert, timers: {set: () => 1, clear: () => {}}, projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(JSON.parse(JSON.stringify(chunk))); return "accepted"; }).setConsent(true);
 return chunks[0]!;
}
const sameChain = (chunks: readonly ReplayChunk[]): boolean => chunks.every((chunk, at) => at === 0 || chunk.previous_hash === createHash("sha256").update(canonicalJSON(chunks[at - 1])).digest("hex"));

test("the recount is prepared in slices between callbacks: no callback emits it, the chunk is the checkpoint a synchronous recount would make, and the chain goes on", () => {
 const {stage, chunks, slices} = rig();
 churnToThreshold(stage);
 const before = chunks.length;
 expect(checkpoints(chunks)).toHaveLength(1); // no callback made a recount: it is only scheduled
 expect(slices()).toBe(1);
 const passes = slicesUntilCheckpoint(stage, chunks);
 expect(passes).toBeGreaterThanOrEqual(4); // several walk slices (a 1,000-node tree is two or more), the fit, the write: never one task
 expect(passes).toBeLessThanOrEqual(1 + Math.ceil(1100 / PREPARE_SLICE_NODES) + 3);
 expect(chunks.length).toBe(before + 1);
 const made = chunks.at(-1)!, expected = fresh(stage);
 expect(made.sequence).toBe(made.checkpoint_sequence);
 expect(made.nodes).toEqual(expected.nodes); // ids from 1 again, same order, same marks
 expect(made.gap).toBe(false);
 expect(made.events.map(event => event.kind)).toEqual(["checkpoint"]);
 expect(Math.max(...made.nodes.map(node => Number(node.id)))).toBeLessThan(2000);
 // The prepared epoch is the live one: an append is recorded under its ids and the hash chain is unbroken.
 stage.attach("SECRET-AFTER");
 const delta = chunks.at(-1)!;
 expect(delta.sequence).not.toBe(delta.checkpoint_sequence);
 expect(delta.checkpoint_sequence).toBe(made.sequence);
 expect(delta.nodes.map(node => node.tag)).toEqual(["p", "masked"]);
 expect(Number(delta.nodes[0]!.id)).toBeGreaterThan(made.nodes.length);
 expect(sameChain(chunks)).toBe(true);
 expect(slices()).toBe(passes); // one timer per slice, none left over
});

test("a batch that arrives while the page is being walked makes the preparation start over, so the checkpoint shows the page as it is when it is written", () => {
 const {stage, chunks} = rig();
 churnToThreshold(stage);
 stage.fire(0); stage.fire(0); // the walk has begun
 stage.churn(40); // the page changes: 40 paragraphs instead of 1,000
 slicesUntilCheckpoint(stage, chunks, 1);
 const made = chunks.at(-1)!;
 expect(made.sequence).toBe(made.checkpoint_sequence);
 expect(made.nodes).toEqual(fresh(stage).nodes);
 expect(made.nodes.length).toBeLessThan(200);
});

test("a page that changes after every slice never gets the prepared checkpoint: the recount stays with the callback that reaches the cap, as before", () => {
 const {stage, chunks, slices} = rig();
 churnToThreshold(stage);
 for (let round = 0; round < PREPARE_RESTARTS + 4; round++) { stage.fire(0); stage.attach("S"); }
 expect(checkpoints(chunks)).toHaveLength(1); // nothing was prepared into a checkpoint
 const slicesAfterGiveUp = slices();
 for (let round = 0; round < 5; round++) { stage.fire(0); stage.attach("S"); }
 expect(slices()).toBe(slicesAfterGiveUp); // no further preparation this epoch
 for (let i = 0; i < 30; i++) stage.churn(1000); // the cap is reached in a callback: the recount happens there
 expect(checkpoints(chunks).length).toBeGreaterThan(1);
 expect(Math.max(...chunks.flatMap(chunk => chunk.nodes.map(node => Number(node.id))))).toBeLessThanOrEqual(MAX_NODES);
});

test("a checkpoint made by the cadence or after a gap supersedes the preparation: its slices stop, no second recount is written", () => {
 const {stage, chunks} = rig();
 churnToThreshold(stage);
 stage.fire(0);
 stage.fire(CHECKPOINT_MS); // the 30 s cadence: a full checkpoint in its own task
 const afterCadence = checkpoints(chunks).length;
 expect(afterCadence).toBe(2);
 for (let i = 0; i < 20; i++) stage.fire(0);
 expect(checkpoints(chunks)).toHaveLength(afterCadence);
 expect(sameChain(chunks)).toBe(true);
});

test("revoking consent in the middle of a preparation destroys it: no chunk, no timer", () => {
 const {stage, chunks, recorder} = rig();
 churnToThreshold(stage);
 stage.fire(0);
 const count = chunks.length;
 recorder.setConsent(false);
 for (let i = 0; i < 20; i++) stage.fire(0);
 expect(chunks).toHaveLength(count);
});

test("a tree larger than one chunk is fitted in its own slice with the same placeholders, loss and gap as a synchronous recount", () => {
 const {stage, chunks} = rig();
 for (let i = 0; i < 15; i++) stage.churn(1000);
 stage.churn(2500); // 2,500 paragraphs: more than a chunk holds, so this delta is already collapsed; the ids used pass the point where the recount is prepared
 slicesUntilCheckpoint(stage, chunks);
 const made = chunks.at(-1)!, expected = fresh(stage);
 expect(made.sequence).toBe(made.checkpoint_sequence);
 expect(made.gap).toBe(true);
 expect(made.nodes).toEqual(expected.nodes);
 expect(made.events.map(event => event.kind)).toEqual(expected.events.map(event => event.kind));
 expect(sameChain(chunks)).toBe(true);
});

test("the iterative walk keeps the recorder's order: a prepared checkpoint of a page that grew and was rewritten equals a synchronous one node for node", () => {
 const {stage, chunks} = rig();
 stage.grow("SECRET-1"); stage.attach("SECRET-2", "SECRET-3"); stage.churn(30);
 churnToThreshold(stage);
 slicesUntilCheckpoint(stage, chunks);
 expect(checkpoints(chunks)).toHaveLength(2);
 expect(chunks.at(-1)!.nodes).toEqual(fresh(stage).nodes);
});
