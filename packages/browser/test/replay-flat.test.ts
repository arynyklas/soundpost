// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The recorder keeps a batch's nodes in one flat, reused table of numbers and writes their canonical form straight into the hash buffer: no node object and no
// id string per node (Firefox charged the minor collections those caused to the 400-node batch, 03.07 / 03.09 p95 row). The wire is unchanged: these tests pin
// the table's canonical text to canonicalJSON, its objects to the closed wire model, and the chunk the consumers see to what it was.
import {test, expect} from "bun:test";
import {createHash} from "node:crypto";
import {NodeTable, TAG_NAMES} from "../src/replay/nodes.ts";
import {canonicalJSON} from "../src/replay/policy.ts";
import {createRecorder} from "../src/replay/recorder.ts";
import type {ReplayChunk, ReplayNode} from "../src/replay/types.ts";
import {recordSession, scriptedPage} from "./recorded-session.ts";

const IDS = [1, 9, 10, 99, 100, 12345, 999999999, 1000000000, 2 ** 31], PARENTS = [0, 1, 10, 2 ** 31];
function everyShape(): ReplayNode[] {
 const nodes: ReplayNode[] = [];
 for (const tag of TAG_NAMES) for (const cls of ["", "masked"] as const) for (const text of ["", "[masked]"] as const) {
  const at = nodes.length;
  nodes.push({id: String(IDS[at % IDS.length]), parent: String(PARENTS[at % PARENTS.length]), tag, class: cls, text});
 }
 return nodes;
}

test("the table's objects are exactly the closed wire nodes, and its byte count is their JSON size, for every tag, class, text and id width", () => {
 const nodes = everyShape(), table = NodeTable.of(nodes);
 expect(table.toArray()).toEqual(nodes);
 expect(JSON.stringify(table.toArray())).toBe(JSON.stringify(nodes));
 expect(table.bytes).toBe(nodes.reduce((sum, node) => sum + JSON.stringify(node).length + 1, 0));
});

test("the table's canonical text (what the chain hash covers) is exactly canonicalJSON of the node objects", () => {
 const nodes = everyShape(), table = NodeTable.of(nodes);
 const buffer = new Uint8Array(table.bytes + 8);
 const end = table.canonical(buffer, 3);
 expect(new TextDecoder().decode(buffer.subarray(3, end))).toBe(canonicalJSON(nodes));
 expect(end - 3).toBeLessThanOrEqual(table.bytes + 1);
});

test("the table is reused: clearing keeps its backing store, growth keeps the content, and a huge walk's store is dropped", () => {
 const table = new NodeTable(), ids = table.ids, parents = table.parents, marks = table.marks;
 for (let round = 0; round < 3; round++) {
  table.clear();
  for (let i = 0; i < 1000; i++) table.add(i + 1, i % 7, i % 32);
  expect(table.ids).toBe(ids); expect(table.parents).toBe(parents); expect(table.marks).toBe(marks); // the same typed arrays, not new ones
  expect(table.length).toBe(1000);
 }
 table.clear();
 for (let i = 0; i < 20000; i++) table.add(i + 1, i % 5, i % 16);
 expect(table.length).toBe(20000);
 expect(table.toArray()[19999]).toEqual({id: "20000", parent: "4", tag: TAG_NAMES[19999 % 16 % 8]!, class: (19999 % 16) & 8 ? "masked" : "", text: ""});
 expect(table.ids.length).toBeGreaterThan(8192);
 table.trim();
 expect(table.ids.length).toBeLessThanOrEqual(1024);
 table.clear();
 table.add(1, 0, 0);
 expect(table.toArray()).toEqual([{id: "1", parent: "0", tag: "div", class: "", text: ""}]);
});

function record() {
 const stage = scriptedPage();
 const chunks: ReplayChunk[] = [];
 const recorder = createRecorder({...stage.config, projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(chunk); return "accepted"; });
 recorder.setConsent(true);
 return {stage, chunks, recorder};
}

test("a chunk keeps its own copy of the nodes: the table is reused by later batches and the chunk's objects are still the ones it was emitted with", () => {
 const expected = recordSession("session").wire[0]!; // the first checkpoint of the same scripted page
 const {stage, chunks} = record();
 stage.grow("SECRET-GROW"); stage.attach("SECRET-ATTACH"); stage.churn(30); // three more walks into the one table
 expect(chunks.length).toBeGreaterThan(3);
 expect(JSON.stringify(chunks[0])).toBe(expected); // read only now
 const table = new NodeTable();
 table.add(7, 3, 1);
 const frozen = table.freeze();
 table.clear(); table.add(9, 9, 2);
 expect(frozen.toArray()).toEqual([{id: "7", parent: "3", tag: "span", class: "", text: ""}]);
 expect(new NodeTable().freeze().toArray()).toEqual([]);
});

test("a chunk is the closed wire object it always was: key order, lazy memoized nodes, spread", () => {
 const {stage, chunks} = record();
 stage.grow("SECRET-GROW");
 stage.attach("SECRET-ATTACH");
 for (const chunk of chunks) {
  expect(Object.keys(chunk)).toEqual(["replay_id", "session_id", "recorder_version", "sequence", "previous_hash", "checkpoint_sequence", "checkpoint_hash", "clock", "nodes", "events", "loss", "gap", "capture_policy_revision"]);
  expect(chunk.nodes).toBe(chunk.nodes);
  const copy = {...chunk};
  expect(Array.isArray(copy.nodes)).toBe(true); // what core's captureReplay({...chunk}) receives
  expect(JSON.stringify(copy)).toBe(JSON.stringify(chunk));
 }
});

test("a chunk the fit had to truncate keeps its hash chain", () => {
 const {stage, chunks} = record();
 stage.churn(5000); // more nodes than one chunk holds: whole subtrees become placeholders, the chunk is gap-marked
 stage.churn(40);
 expect(chunks.some(chunk => chunk.gap)).toBe(true);
 expect(chunks.some(chunk => chunk.nodes.some(node => node.class === "masked"))).toBe(true);
 for (let i = 1; i < chunks.length; i++) expect(chunks[i]!.previous_hash).toBe(createHash("sha256").update(canonicalJSON(chunks[i - 1])).digest("hex"));
});
