// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The production consumer path: startReplay -> the real core client's queue. A chunk's nodes are numbers in the recorder; the queue must take their canonical JSON text without ever making
// node objects (Firefox charged the minor collections of those objects to the MutationObserver callback), and what it queues must be, byte for byte, what the object path queues.
import {test, expect, afterEach} from "bun:test";
import {heapStats} from "bun:jsc";
import {readFileSync, readdirSync} from "node:fs";
import {init, type Client} from "../src/index.ts";
import {setReplayConsent, startReplay} from "../src/replay.ts";
import {chunkNodes} from "../src/replay/recorder.ts";
import {Nodes, NodeTable, markOf} from "../src/replay/nodes.ts";
import {canonicalJSON} from "../src/replay/policy.ts";
import {FLUSH_MS, SESSION_NAMES, recordSession, scriptedPage} from "./recorded-session.ts";
import {config as coreConfig} from "../../core/test/fixture.ts";
import type {FrozenBatch, Outcome, ReceiptTransport} from "../../core/src/transport.ts";
import type {DomAccessors, ReplayChunk, ReplayNode} from "../src/replay/types.ts";

class Idle implements ReceiptTransport {
 async send(batch: FrozenBatch): Promise<Outcome> {
  return {kind: "receipt", receipt: {version: 1, batch_id: batch.id, hash: batch.hash, cursor: {group: "9".repeat(32), index: "1"}, retain_until_ns: "9007199254740994", dedup_until_ns: "9007199254740994",
   signal_deadlines: batch.kinds.map(kind => ({kind, retain_until_ns: "9007199254740994"}))}};
 }
 async lookup(): Promise<Outcome> { return {kind: "not_found"}; }
 close(): void {}
}
const clients: Client[] = [];
const open = (): Client => { const client = init({...coreConfig(), transport: new Idle(), deploymentReplay: true}); clients.push(client); return client; };
afterEach(async () => { for (const client of clients.splice(0)) await client.close(); });
/** Queued record texts without their random event ID, so two clients' records compare byte for byte. */
const texts = (client: Client): string[] => client.bufferedRecords().map(line => line.replace(/^\{"id":"[0-9a-f]{32}"/, '{"id":""'));
/** The texts the OLD object path queues for these chunks: `captureReplay({...chunk})`. */
function objectPath(chunks: readonly ReplayChunk[]): string[] {
 const client = open();
 for (const chunk of chunks) expect(client.captureReplay({...chunk})).toBe(true);
 return texts(client);
}

/** Counts every call of the two ways a node object is made, for the duration of `run`. */
function watchNodeObjects<T>(run: () => T): {result: T; made: number} {
 const toArray = Nodes.prototype.toArray, at = Nodes.prototype.at;
 let made = 0;
 Nodes.prototype.toArray = function (this: Nodes) { made++; return toArray.call(this); };
 Nodes.prototype.at = function (this: Nodes, index: number) { made++; return at.call(this, index); };
 try { const result = run(); return {result, made}; } finally { Nodes.prototype.toArray = toArray; Nodes.prototype.at = at; }
}

interface Fake { t: number; name: string; kids: Fake[]; parent: Fake | null }
const fake = (name: string, ...kids: Fake[]): Fake => { const out: Fake = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = out; return out; };
function wideDom(): DomAccessors {
 return {
  nodeType: n => (n as Fake).t, firstChild: n => (n as Fake).kids[0] ?? null,
  nextSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) + 1] ?? null; },
  lastChild: n => (n as Fake).kids.at(-1) ?? null,
  previousSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) - 1] ?? null; },
  parentNode: n => (n as Fake).parent, localName: n => (n as Fake).name, openShadowRoot: () => null, editable: () => false,
  mutationTarget: record => (record as {target: object}).target, childListChange: () => null, eventTarget: () => null, clientX: () => 0, clientY: () => 0,
 };
}
function widePage(count: number): Fake {
 const body = fake("body");
 for (let i = 0; i < count; i++) { const p = fake(i % 2 ? "p" : "span"); p.parent = body; body.kids.push(p); }
 const html = fake("html", body);
 const document: Fake = {t: 9, name: "#document", kids: [html], parent: null}; html.parent = document;
 return document;
}
const objectCount = (): number => { Bun.gc(true); return (heapStats().objectTypeCounts as Record<string, number>)["Object"] ?? 0; };

test("Nodes.canonicalText is the canonical JSON array of the node objects, for every tag, class, text and id width", () => {
 const tags = ["div", "span", "p", "button", "input", "section", "canvas", "masked"] as const;
 const table = new NodeTable();
 let next = 1;
 for (let code = 0; code < tags.length; code++) for (const opaque of [false, true]) for (const masked of [false, true]) table.add(next++, 0, markOf(code, opaque, masked));
 for (const id of [0, 9, 10, 99, 100, 999, 1000, 65535, 65536, 999999, 4294967295]) table.add(id, 4294967295 - id, markOf(0, false, false));
 const frozen = table.freeze();
 expect(frozen.canonicalText()).toBe(canonicalJSON(frozen.toArray()));
 expect(table.canonicalText()).toBe(canonicalJSON(table.toArray()));
 expect(new NodeTable().canonicalText()).toBe("[]");
 expect(frozen.canonicalText()).toBe(frozen.canonicalText());
 const again = new NodeTable(); again.add(5, 1, markOf(2, false, false));
 expect(again.canonicalText()).toBe('[{"class":"","id":"5","parent":"1","tag":"p","text":""}]'); // a reused buffer carries nothing over from the longer text
 for (const name of ["session", "recovery", "append"]) for (const file of readdirSync(new URL(`../../../fixtures/replays/recorder/${name}/`, import.meta.url)).filter(f => /^\d+\.json$/.test(f))) {
  const chunk = JSON.parse(readFileSync(new URL(`../../../fixtures/replays/recorder/${name}/${file}`, import.meta.url), "utf8")) as {nodes: ReplayNode[]};
  expect(NodeTable.of(chunk.nodes).canonicalText(), `${name}/${file}`).toBe(canonicalJSON(chunk.nodes));
 }
});

test("startReplay queues the scripted session without making one node object, with the bytes the object path queues", () => {
 const client = open(), stage = scriptedPage();
 const kept: ReplayChunk[] = [];
 const {made} = watchNodeObjects(() => {
  startReplay(client, stage.config, chunk => { kept.push(chunk); void chunk.sequence; void chunk.checkpoint_sequence; void chunk.gap; });
  setReplayConsent(client, true);
  stage.pointer("button", 123, 45); stage.fire(FLUSH_MS);
  stage.grow("SECRET-LATE-TEXT");
  stage.pointer("html", 7, 9); stage.fire(FLUSH_MS);
 });
 expect(kept.length).toBeGreaterThanOrEqual(3);
 expect(client.diagnostics()).toEqual({});
 expect(made).toBe(0);
 const queued = texts(client);
 expect(queued).toHaveLength(kept.length);
 expect(queued.join("")).not.toContain("SECRET");
 expect(objectPath(kept)).toEqual(queued); // reading chunk.nodes happens only here, after the assertion above
});

test("a chunk of 1,500 nodes reaches the queue without a node object, and a tap that reads chunk.nodes still gets the closed objects", () => {
 const client = open(), base = scriptedPage();
 const kept: ReplayChunk[] = [];
 const {made} = watchNodeObjects(() => {
  startReplay(client, {...base.config, root: widePage(1500), dom: wideDom()}, chunk => { kept.push(chunk); });
  setReplayConsent(client, true);
 });
 expect(made).toBe(0);
 expect(kept).toHaveLength(1);
 const columns = chunkNodes(kept[0]!)!;
 expect(columns.length).toBe(1502);
 const queued = texts(client);
 expect(queued).toHaveLength(1);
 expect(client.diagnostics()).toEqual({});
 expect(queued[0]!.includes('"nodes":' + columns.canonicalText())).toBe(true);
 // A viewer-like tap reads the nodes: the objects are made then, once, and are the closed objects the queue holds as text.
 const second = open(), reader = scriptedPage();
 let seen: readonly ReplayNode[] = [];
 startReplay(second, {...reader.config, root: widePage(1500), dom: wideDom()}, chunk => { seen = chunk.nodes; });
 setReplayConsent(second, true);
 expect(seen).toHaveLength(1502);
 expect(Object.keys(seen[0]!)).toEqual(["id", "parent", "tag", "class", "text"]);
 expect(canonicalJSON(seen)).toBe(columns.canonicalText());
 expect(texts(second)).toEqual(queued);
 expect(second.diagnostics()).toEqual({});
 expect(objectPath(kept)).toEqual(queued);
});

test("queuing a 1,500-node chunk through startReplay leaves far fewer than 1,500 objects on the heap while the chunk is held", () => {
 const client = open(), base = scriptedPage();
 const kept: ReplayChunk[] = [];
 const page = widePage(1500), dom = wideDom();
 objectCount();
 const before = objectCount();
 startReplay(client, {...base.config, root: page, dom}, chunk => { kept.push(chunk); });
 setReplayConsent(client, true);
 const queued = client.bufferedRecords().length, during = objectCount() - before;
 expect(kept).toHaveLength(1);
 expect(queued).toBe(1);
 expect(during).toBeLessThan(500); // per-node objects would add 1,502
 const mid = objectCount();
 expect(kept[0]!.nodes).toHaveLength(1502);
 expect(objectCount() - mid).toBeGreaterThan(1500); // the same chunk's objects exist only once something reads them
});

test("every committed recorder session queues the same bytes through the production path as through the object path", () => {
 for (const name of SESSION_NAMES) {
  const chunks = recordSession(name).wire.map(wire => JSON.parse(wire) as ReplayChunk);
  const production = open();
  for (const chunk of chunks) {
   const rest: Record<string, unknown> = {...chunk}; delete rest.nodes;
   expect(production.captureReplay(rest, canonicalJSON(chunk.nodes)), name).toBe(true);
  }
  expect(texts(production), name).toEqual(objectPath(chunks));
 }
});
