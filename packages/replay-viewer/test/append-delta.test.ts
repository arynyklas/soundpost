// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 03.07-C7: the recorder records a pure append once (a `mutation` event on a node the viewer has never held, plus only the new
// nodes) instead of re-walking the parent. This is the proof that the viewer, unchanged, shows the identical tree: random page
// histories are recorded twice by the real recorder (child-list records understood = append deltas; not understood = the former
// re-walk of the record's target), both are replayed by the real viewer, and both must show exactly what a fresh checkpoint of the
// final page shows. The recorder's v1 chunks of the former shape (golden session/03, 06) stay in stream.test.ts.
import {expect, test} from "bun:test";
import {renderReplay, type ReplayItem} from "../src/render.ts";
import {createRecorder} from "../../browser/src/replay/recorder.ts";
import type {DomAccessors, ReplayChunk, ReplayConfig} from "../../browser/src/replay/types.ts";

interface F { t: number; name: string; kids: F[]; parent: F | null }
/** `next`: the record's `nextSibling` at the time of the change (null: at the end of the target's children); absent for a record that only names its target. */
interface Rec { target: F; added?: F[]; removed?: F[]; next?: F | null }
const el = (name: string, ...kids: F[]): F => { const out: F = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = out; return out; };
const txt = (): F => ({t: 3, name: "#text", kids: [], parent: null});

function accessors(understandChildList: boolean): DomAccessors {
 return {
  nodeType: n => (n as F).t, firstChild: n => (n as F).kids[0] ?? null, lastChild: n => (n as F).kids.at(-1) ?? null,
  nextSibling: n => { const p = (n as F).parent; return p === null ? null : p.kids[p.kids.indexOf(n as F) + 1] ?? null; },
  previousSibling: n => { const p = (n as F).parent; return p === null ? null : p.kids[p.kids.indexOf(n as F) - 1] ?? null; },
  parentNode: n => (n as F).parent, localName: n => (n as F).name, openShadowRoot: () => null, editable: () => false,
  recordKind: record => { const r = record as Rec; return !understandChildList || r.next === undefined ? "other" : r.next === null ? "tail" : "inside"; },
  mutationTarget: record => (record as Rec).target, eventTarget: () => null, clientX: () => 0, clientY: () => 0,
 };
}

interface Recording { readonly chunks: ReplayChunk[]; observe(records: readonly object[]): void }
function record(root: F, understandChildList: boolean, extra: Partial<ReplayConfig> = {}): Recording {
 let observe: ((records: readonly object[]) => void) | undefined;
 class Observer { constructor(callback: (records: readonly object[]) => void) { observe = callback; } observe(): void {} disconnect(): void {} }
 const chunks: ReplayChunk[] = [];
 let tick = 0;
 const config: ReplayConfig = {
  projectPolicy: true, deploymentOptIn: true, root, replayId: "11".repeat(16), sessionId: "22".repeat(16), capturePolicyRevision: "7", domain: {host: "33".repeat(16), boot: "44".repeat(16), runtime: "55".repeat(16)},
  clock: () => ({wall_ns: "1700000000000000000", mono_ns: String(5_000_000_000 + ++tick * 1000), uncertainty_ns: "1000"}), dom: accessors(understandChildList), observer: Observer,
  eventTarget: {addEventListener: () => {}, removeEventListener: () => {}}, timers: {set: () => 1, clear: () => {}}, ...extra,
 };
 createRecorder(config, chunk => { chunks.push(JSON.parse(JSON.stringify(chunk))); return "accepted"; }).setConsent(true);
 return {chunks, observe: records => observe!(records)};
}

// ---- The real viewer over a minimal DOM. ----
class FakeEl {
 readonly children: FakeEl[] = []; readonly attrs = new Map<string, string>(); text = ""; parent: FakeEl | null = null;
 constructor(readonly name: string, readonly doc: FakeDoc) {}
 get ownerDocument() { return this.doc; }
 setAttribute(name: string, value: string): void { this.attrs.set(name, String(value)); }
 append(...items: FakeEl[]): void { for (const item of items) { item.parent?.children.splice(item.parent.children.indexOf(item), 1); item.parent = this; this.children.push(item); } }
 replaceChildren(...items: FakeEl[]): void { for (const child of this.children) child.parent = null; this.children.length = 0; this.append(...items); }
 set textContent(value: string) { this.text = String(value); for (const child of this.children) child.parent = null; this.children.length = 0; }
 find(predicate: (el: FakeEl) => boolean): FakeEl[] { return [...(predicate(this) ? [this] : []), ...this.children.flatMap(child => child.find(predicate))]; }
}
class FakeDoc { createElement(name: string): FakeEl { return new FakeEl(name, this); } }
const encoder = new TextEncoder();
async function* items(chunks: readonly ReplayChunk[]): AsyncGenerator<ReplayItem> { for (const chunk of chunks) yield {kind: "chunk", bytes: encoder.encode(JSON.stringify(chunk))}; }
function summarize(el: FakeEl): string {
 const text = el.children.filter(child => child.attrs.has("data-masked")).map(child => child.text).join("");
 const kids = el.children.filter(child => child.attrs.has("data-tag")).map(summarize);
 return (el.attrs.get("data-tag") ?? "?") + (text === "" ? "" : ":" + text) + (kids.length > 0 ? "[" + kids.join(",") + "]" : "");
}
async function shown(chunks: readonly ReplayChunk[]): Promise<{tree: string; status: string}> {
 const container = new FakeEl("div", new FakeDoc());
 const handle = renderReplay(container as unknown as HTMLElement, items(chunks));
 await handle.done;
 const root = container.find(el => el.attrs.has("data-replay-root"))[0]!;
 const tree = root.find(el => el.attrs.has("data-replay-tree"))[0]!;
 return {tree: tree.children.filter(child => child.attrs.has("data-tag")).map(summarize).join("|"), status: handle.status()};
}

// ---- A deterministic page history: appends of small subtrees, insertions, removals, moves, text and attribute churn. ----
function prng(seed: number): () => number { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
const TAGS = ["div", "p", "span", "section", "button", "my-widget", "select", "input"];
function subtree(next: () => number, depth = 0): F {
 const node = el(TAGS[Math.floor(next() * TAGS.length)]!);
 const count = depth > 2 ? 0 : Math.floor(next() * 3);
 for (let i = 0; i < count; i++) { const child = next() < 0.3 ? txt() : subtree(next, depth + 1); child.parent = node; node.kids.push(child); }
 return node;
}
const elements = (node: F): F[] => [node, ...node.kids.flatMap(elements)].filter(candidate => candidate.t === 1);
const inside = (node: F, ancestor: F): boolean => { for (let up: F | null = node; up !== null; up = up.parent) if (up === ancestor) return true; return false; };

/** `tailOps` adds batches of operations that only touch the end of one element's children (appends, removals of the last child, re-appends of nodes just removed): every record is a tail record, the case the recorder answers from the page's children instead of the records' node lists. */
function history(seed: number, tailOps = false): {root: F; apply: () => Rec[]} {
 const next = prng(seed);
 const body = el("body", el("div", el("p"), txt()), el("section", el("span")));
 const root: F = {t: 9, name: "#document", kids: [el("html", body)], parent: null}; root.kids[0]!.parent = root;
 const apply = (): Rec[] => {
  // one batch of 1-5 DOM operations
  const records: Rec[] = [];
  const operations = 1 + Math.floor(next() * 5);
  const detach = (child: F): void => { const from = child.parent!, at = from.kids.indexOf(child), following = from.kids[at + 1] ?? null; from.kids.splice(at, 1); child.parent = null; records.push({target: from, added: [], removed: [child], next: following}); };
  const into = (parent: F, child: F, before?: F): void => {
   if (child.parent !== null) detach(child);
   child.parent = parent;
   if (before === undefined) parent.kids.push(child); else parent.kids.splice(parent.kids.indexOf(before), 0, child);
   records.push({target: parent, added: [child], removed: [], next: before ?? null});
  };
  for (let op = 0; op < operations; op++) {
   const all = elements(root.kids[0]!), pick = (): F => all[Math.floor(next() * all.length)]!;
   if (tailOps && next() < 0.4) {
    const parent = pick(), popped: F[] = [];
    for (let steps = 1 + Math.floor(next() * 6); steps > 0; steps--) {
     const roll = next();
     if (roll < 0.35 && parent.kids.length > 0) { const last = parent.kids.at(-1)!; detach(last); popped.push(last); }
     else if (roll < 0.7) into(parent, subtree(next));
     else if (popped.length > 0) into(parent, popped.splice(Math.floor(next() * popped.length), 1)[0]!);
     if (next() < 0.15 && parent.kids.length > 0 && parent.kids.at(-1)!.t === 1) records.push({target: parent.kids.at(-1)!});
    }
    continue;
   }
   const roll = next();
   if (roll < 0.5) { const fresh = subtree(next); into(pick(), fresh); if (next() < 0.5 && fresh.kids.length > 0) records.push({target: fresh.kids[0]!}); if (next() < 0.4) records.push({target: fresh}); }
   else if (roll < 0.62) { const parent = pick(); const fresh = subtree(next); into(parent, fresh, parent.kids[0]); }
   else if (roll < 0.74) { const victim = pick(); if (victim !== root.kids[0] && victim.parent !== null) detach(victim); }
   else if (roll < 0.84) { const mover = pick(), target = pick(); if (mover !== root.kids[0] && !inside(target, mover)) into(target, mover); }
   else if (roll < 0.92) { const target = pick(); records.push({target}); }
   else { const parent = pick(); const gone = subtree(next); into(parent, gone); detach(gone); }
  }
  return records;
 };
 return {root, apply};
}

const nodeTotal = (chunks: readonly ReplayChunk[]): number => chunks.slice(1).reduce((sum, chunk) => sum + (chunk.sequence === chunk.checkpoint_sequence ? 0 : chunk.nodes.length), 0);

test("append deltas and the former re-walk deltas show the viewer exactly what a fresh checkpoint of the final page shows (random histories)", async () => {
 let appendNodes = 0, rewalkNodes = 0, deltas = 0;
 for (let seed = 1; seed <= 40; seed++) {
  const page = history(seed);
  const appended = record(page.root, true), rewalked = record(page.root, false);
  for (let batch = 0; batch < 30; batch++) {
   const records = page.apply();
   appended.observe(records); rewalked.observe(records);
   if (batch % 10 === 9) {
    const fresh = record(page.root, true);
    const truth = await shown(fresh.chunks);
    expect([seed, batch, await shown(appended.chunks)]).toEqual([seed, batch, truth]);
    expect([seed, batch, await shown(rewalked.chunks)]).toEqual([seed, batch, truth]);
    expect(truth.status).toBe("ready");
   }
  }
  appendNodes += nodeTotal(appended.chunks); rewalkNodes += nodeTotal(rewalked.chunks);
  deltas += appended.chunks.filter(chunk => chunk.sequence !== chunk.checkpoint_sequence).length;
 }
 expect(deltas).toBeGreaterThan(100);
 expect(appendNodes).toBeLessThan(rewalkNodes); // the append path was taken and records less than the re-walk
});

test("histories of tail records (appends, removals of the last child, re-appends of nodes just removed, any order within a batch) show the viewer exactly what a fresh checkpoint shows: the recorder answers an append from the page's children, never from the records' node lists", async () => {
 let appendNodes = 0, rewalkNodes = 0, deltas = 0;
 for (let seed = 1; seed <= 60; seed++) {
  const page = history(seed, true);
  const appended = record(page.root, true), rewalked = record(page.root, false);
  for (let batch = 0; batch < 24; batch++) {
   const records = page.apply();
   appended.observe(records); rewalked.observe(records);
   if (batch % 3 === 2) {
    const truth = await shown(record(page.root, true).chunks);
    expect([seed, batch, await shown(appended.chunks)]).toEqual([seed, batch, truth]);
    expect([seed, batch, await shown(rewalked.chunks)]).toEqual([seed, batch, truth]);
    expect(truth.status).toBe("ready");
   }
  }
  appendNodes += nodeTotal(appended.chunks); rewalkNodes += nodeTotal(rewalked.chunks);
  deltas += appended.chunks.filter(chunk => chunk.sequence !== chunk.checkpoint_sequence).length;
 }
 expect(deltas).toBeGreaterThan(500);
 expect(appendNodes).toBeLessThan(rewalkNodes);
}, 60_000);
test("a late-started recording shows the banner and a supported start shows none (D100)", async () => {
 const banner = async (chunks: readonly ReplayChunk[]): Promise<string[]> => {
  const container = new FakeEl("div", new FakeDoc());
  const handle = renderReplay(container as unknown as HTMLElement, items(chunks));
  await handle.done;
  return container.find(el => el.attrs.get("data-kind") === "late-start").map(el => el.text);
 };
 const late = record(history(1).root, true, {lateStart: () => "document_ready_state"});
 expect(late.chunks[0]!.gap).toBe(true);
 expect(await banner(late.chunks)).toEqual(["Recording started after the page had loaded: pre-existing closed shadow roots may be unobservable."]);
 const supported = record(history(1).root, true, {lateStart: () => null});
 expect(supported.chunks[0]!.gap).toBe(false);
 expect(await banner(supported.chunks)).toEqual([]);
});
