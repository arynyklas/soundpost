// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// `captureReplay(chunk, nodesJson)`: the production browser path hands core the canonical JSON text of a chunk's nodes instead of node objects. Core must enforce the closed
// node schema on that text without making per-node objects, must never read `chunk.nodes`, and must queue the very bytes the object path queues.
import {test, expect} from "bun:test";
import {readFileSync, readdirSync} from "node:fs";
import {config} from "./fixture.ts";
import {Client} from "../src/client.ts";
import {nativeCanonical} from "../src/routing.ts";

type Chunk = Record<string, unknown> & {nodes: Record<string, unknown>[]};
const root = new URL("../../../fixtures/replays/recorder/", import.meta.url);
const goldens: {name: string; chunk: Chunk}[] = [];
for (const dir of ["session", "recovery", "append"]) for (const file of readdirSync(new URL(`${dir}/`, root)).filter(name => /^\d+\.json$/.test(name)).sort()) goldens.push({name: `${dir}/${file}`, chunk: JSON.parse(readFileSync(new URL(`${dir}/${file}`, root), "utf8")) as Chunk});
const base = goldens[0]!.chunk;
const fresh = (): Client => new Client({...config(), deploymentReplay: true});
/** The record text without its random event ID, so two clients' records compare byte for byte. */
const bytes = (client: Client): string[] => client.bufferedRecords().map(line => line.replace(/^\{"id":"[0-9a-f]{32}"/, '{"id":""'));
const withoutNodes = (chunk: Chunk): Record<string, unknown> => { const {nodes: _nodes, ...rest} = chunk; return rest; };
const TAGS = ["div", "span", "p", "button", "input", "section", "canvas", "masked"], CLASSES = ["", "masked"], TEXTS = ["", "[masked]"];
const node = (id: string, parent: string, tag = "div", cls = "", text = ""): Record<string, unknown> => ({id, parent, tag, class: cls, text});
/** What the recorder's own canonical writer produces for a node list: sorted keys, no whitespace. */
const canon = (nodes: unknown): string => nativeCanonical(nodes);

function both(chunk: Chunk): {object: string[]; text: string[]} {
 const a = fresh(), b = fresh();
 expect(a.captureReplay(chunk)).toBe(true);
 expect(b.captureReplay(withoutNodes(chunk), canon(chunk.nodes))).toBe(true);
 return {object: bytes(a), text: bytes(b)};
}

test("every committed golden chunk is queued with the same bytes through the nodes-text form as through the object form", () => {
 expect(goldens.length).toBeGreaterThanOrEqual(17);
 for (const {name, chunk} of goldens) {
  const {object, text} = both(chunk);
  expect(text, name).toEqual(object);
  expect(object[0]!.includes('"nodes":[]') === (chunk.nodes.length === 0), name).toBe(true);
 }
});

test("synthetic chunks: every tag, class and text combination and ids of every digit width queue the same bytes", () => {
 const nodes: Record<string, unknown>[] = [];
 for (const tag of TAGS) for (const cls of CLASSES) for (const text of TEXTS) nodes.push(node(String(nodes.length + 1), "0", tag, cls, text));
 for (let width = 1; width <= 20; width++) {
  const id = width === 20 ? "18446744073709551615" : "9".repeat(width), low = width === 1 ? "0" : "1" + "0".repeat(width - 1);
  nodes.push(node(id, low), node(low, id, "span", "masked", "[masked]"));
 }
 const {object, text} = both({...base, nodes});
 expect(text).toEqual(object);
 for (const count of [0, 1, 2000]) {
  const many = Array.from({length: count}, (_, i) => node(String(i + 1), i === 0 ? "0" : String(i)));
  const result = both({...base, nodes: many});
  expect(result.text).toEqual(result.object);
 }
});

test("the nodes-text form never reads chunk.nodes", () => {
 const client = fresh();
 const chunk = {...withoutNodes(base)};
 Object.defineProperty(chunk, "nodes", {enumerable: true, get() { throw Error("chunk.nodes was read"); }});
 expect(client.captureReplay(chunk, canon(base.nodes))).toBe(true);
 expect(bytes(client)).toEqual(bytes(((): Client => { const o = fresh(); o.captureReplay(base); return o; })()));
 expect(client.diagnostics().invalid_replay_record).toBeUndefined();
});

const one = node("7", "0", "p", "", "[masked]");
const text = canon([one]);
const smuggled: [string, string][] = [
 ["an extra field", canon([{...one, rect: {x: 1}}])],
 ["a missing field", canon([{id: "7", parent: "0", tag: "p", class: ""}])],
 ["a tag outside the enum", canon([{...one, tag: "html"}])],
 ["a class that is not the mask", canon([{...one, class: "SECRET-CLASS"}])],
 ["unmasked text", canon([{...one, text: "SECRET-TEXT"}])],
 ["a numeric id", '[{"class":"","id":7,"parent":"0","tag":"p","text":"[masked]"}]'],
 ["a leading-zero id", canon([{...one, id: "07"}])],
 ["a negative parent", canon([{...one, parent: "-1"}])],
 ["a uint64 overflow id", canon([{...one, id: "18446744073709551616"}])],
 ["a 21 digit id", canon([{...one, id: "1" + "0".repeat(20)}])],
 ["an empty id", canon([{...one, id: ""}])],
 ["junk after the array", text + "x"],
 ["a lowercase class", canon([{...one, class: "secret"}])], ["a one-letter class", canon([{...one, class: "x"}])], ["a one-letter text", canon([{...one, text: "x"}])], ["a one-letter tag", canon([{...one, tag: "x"}])],
 ["a second array after the array", text + ",[]"],
 ["a smuggled field after the array", text + ',"smuggled":"SECRET"'],
 ["text that closes the array early", '[{"class":"","id":"7","parent":"0","tag":"p","text":"[masked]"}],"events":[],"x":[{"class":"","id":"7","parent":"0","tag":"p","text":"[masked]"}]'],
 ["a node object closed early", '[{"class":"","id":"7","parent":"0","tag":"p","text":"[masked]"},"x":1}]'],
 ["leading whitespace", " " + text], ["trailing newline", text + "\n"], ["whitespace after a comma", canon([one, one]).replace("},{", "}, {")],
 ["non-canonical key order", '[{"id":"7","class":"","parent":"0","tag":"p","text":"[masked]"}]'],
 ["a duplicated key", '[{"class":"","class":"","id":"7","parent":"0","tag":"p","text":"[masked]"}]'],
 ["an escaped value", '[{"class":"","id":"7","parent":"0","tag":"\\u0070","text":"[masked]"}]'],
 ["an object instead of an array", canon(one)], ["a trailing comma", text.replace("]", ",]")], ["a null node", "[null]"], ["the empty string", ""],
 ["4097 nodes", canon(Array.from({length: 4097}, (_, i) => node(String(i + 1), "0")))],
];

test("the nodes-text form refuses every shape outside the closed schema, counted as invalid_replay_record, queueing nothing", () => {
 const client = fresh();
 let refused = 0;
 const good = canon(one);
 for (const [name, nodes] of smuggled) {
  // A single bad node is also placed first, last and twice beside a good one: the expression must refuse a bad node wherever it stands in the list.
  const inner = nodes.startsWith("[{") && nodes.endsWith("}]") && !nodes.includes("},{") ? nodes.slice(1, -1) : undefined;
  for (const text of inner === undefined ? [nodes] : [nodes, `[${good},${inner}]`, `[${inner},${good}]`, `[${inner},${inner}]`, `[${good},${inner},${good}]`]) {
   expect(client.captureReplay(withoutNodes(base), text), `${name}: ${text.slice(0, 80)}`).toBe(false);
   expect(client.diagnostics().invalid_replay_record, name).toBe(++refused);
  }
 }
 expect(client.bufferedRecords()).toEqual([]);
 expect(client.captureReplay(withoutNodes(base), text)).toBe(true);
 expect(client.captureReplay(withoutNodes(base), "[]")).toBe(true);
});

test("a record that is not a replay chunk shape is still refused with the nodes text given", () => {
 const client = fresh();
 expect(client.captureReplay({...withoutNodes(base), html: "<b>typed</b>"}, text)).toBe(false);
 expect(client.captureReplay({...withoutNodes(base), clock: null}, text)).toBe(false);
 expect(client.captureReplay({...withoutNodes(base), events: [{at_ns: "1", kind: "keypress", node: "1", x: 0, y: 0}]}, text)).toBe(false);
 expect(client.diagnostics().invalid_replay_record).toBe(3);
 const denied = new Client(config());
 expect(denied.captureReplay(withoutNodes(base), text)).toBe(false);
 expect(denied.diagnostics().policy_disabled).toBe(1);
});

test("the object form refuses the same shapes with the same loss reason", () => {
 const client = fresh();
 const objectForms: [string, unknown][] = [
  ["an extra field", [{...one, rect: {x: 1}}]], ["a tag outside the enum", [{...one, tag: "html"}]], ["unmasked text", [{...one, text: "SECRET"}]], ["a numeric id", [{...one, id: 7}]],
  ["a leading-zero id", [{...one, id: "07"}]], ["a uint64 overflow id", [{...one, id: "18446744073709551616"}]], ["a null node", [null]], ["not an array", one], ["absent", undefined],
  ["4097 nodes", Array.from({length: 4097}, (_, i) => node(String(i + 1), "0"))], ["an inherited field", [Object.create(one) as unknown]],
 ];
 let refused = 0;
 for (const [name, nodes] of objectForms) {
  expect(client.captureReplay({...withoutNodes(base), nodes}), name).toBe(false);
  expect(client.diagnostics().invalid_replay_record, name).toBe(++refused);
 }
 expect(client.bufferedRecords()).toEqual([]);
 expect(client.captureReplay({...withoutNodes(base), nodes: Array.from({length: 2000}, (_, i) => node(String(i + 1), "0"))})).toBe(true);
});

test("a stored record's full text (spool recovery) is validated as a whole, nodes included", () => {
 const source = fresh();
 source.captureReplay(base);
 const stored = source.bufferedRecords()[0]!;
 const target = (): {enqueue(text: string): boolean} => (fresh() as unknown as {delivery: {enqueue(text: string): boolean}}).delivery;
 expect(target().enqueue(stored)).toBe(true);
 expect(() => target().enqueue(stored.replace('"tag":"', '"tag":"x'))).toThrow();
 expect(() => target().enqueue(stored.replace(/"text":"(\[masked\])?"/, '"text":"SECRET"'))).toThrow();
 expect(() => target().enqueue(stored.replace(/"nodes":\[/, '"nodes":[{"class":"","id":"1","parent":"0","tag":"div","text":"","x":1},'))).toThrow();
 const crowded = base.nodes.length < 4096 ? stored.replace(/"nodes":\[/, '"nodes":[' + Array.from({length: 4096}, () => canon(one)).join(",") + ",") : stored;
 expect(() => target().enqueue(crowded)).toThrow();
});

test("the node bound is exactly 4096 in both forms: 4096 passes validation (the queue's own record size cap refuses it), 4097 is an invalid replay record", () => {
 for (const form of ["text", "object"] as const) {
  const client = fresh();
  const send = (count: number): boolean => {
   const nodes = Array.from({length: count}, (_, i) => node(String(i + 1), "0", "p", "", ""));
   return form === "text" ? client.captureReplay(withoutNodes(base), canon(nodes)) : client.captureReplay({...withoutNodes(base), nodes});
  };
  expect(send(4096), form).toBe(false);
  expect(client.diagnostics().record_too_large, form).toBe(1);
  expect(client.diagnostics().invalid_replay_record, form).toBeUndefined();
  expect(send(4097), form).toBe(false);
  expect(client.diagnostics().invalid_replay_record, form).toBe(1);
  expect(client.diagnostics().record_too_large, form).toBe(1);
 }
});
