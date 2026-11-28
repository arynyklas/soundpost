// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 03.07-C7 / 03.09-C9: a delta that only appends new nodes records those subtrees once instead of re-walking the whole parent.
// The wire format is unchanged (recorder_version "1"): a `mutation` event on a node the replay has never held deletes nothing in the
// viewer and the chunk's nodes are added, so the chunk plays on the existing viewer; anything else (removal, move, insertion before a
// known sibling, a widget that shows no children, an append the chunk cannot hold) is still the re-walk of the parent.
import {test, expect} from "bun:test";
import {createRecorder} from "../src/replay/recorder.ts";
import {MAX_MUTATION_ROOTS} from "../src/replay/policy.ts";
import type {DomAccessors, ReplayChunk, ReplayConfig} from "../src/replay/types.ts";

interface F { t: number; name: string; kids: F[]; parent: F | null; editable?: boolean; shadow?: F }
const el = (name: string, ...kids: F[]): F => { const out: F = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = out; return out; };
const txt = (): F => ({t: 3, name: "#text", kids: [], parent: null});
const comment = (): F => ({t: 8, name: "#comment", kids: [], parent: null});
const documentOf = (html: F): F => { const doc: F = {t: 9, name: "#document", kids: [html], parent: null}; html.parent = doc; return doc; };

/** `next`: the record's `nextSibling` (null: the change was at the end of the target's children); absent for a record that only names its target (attributes, character data). */
interface Rec { target: F; added?: F[]; removed?: F[]; next?: F | null }
const dom: DomAccessors = {
 nodeType: n => (n as F).t, firstChild: n => (n as F).kids[0] ?? null, lastChild: n => (n as F).kids.at(-1) ?? null,
 nextSibling: n => { const p = (n as F).parent; return p === null ? null : p.kids[p.kids.indexOf(n as F) + 1] ?? null; },
 previousSibling: n => { const p = (n as F).parent; return p === null ? null : p.kids[p.kids.indexOf(n as F) - 1] ?? null; },
 parentNode: n => (n as F).parent, localName: n => (n as F).name, openShadowRoot: n => (n as F).shadow ?? null, editable: n => (n as F).editable === true,
 recordKind: record => { const r = record as Rec; return r.next === undefined ? "other" : r.next === null ? "tail" : "inside"; },
 mutationTarget: record => (record as Rec).target, eventTarget: () => null, clientX: () => 0, clientY: () => 0,
};

/** What a MutationObserver reports for the DOM operation, applied to the fake page. */
function add(parent: F, child: F, before?: F): Rec {
 if (child.parent !== null) child.parent.kids.splice(child.parent.kids.indexOf(child), 1);
 child.parent = parent;
 if (before === undefined) parent.kids.push(child); else parent.kids.splice(parent.kids.indexOf(before), 0, child);
 return {target: parent, added: [child], removed: [], next: before ?? null};
}
function remove(child: F): Rec {
 const parent = child.parent!, at = parent.kids.indexOf(child), next = parent.kids[at + 1] ?? null;
 parent.kids.splice(at, 1); child.parent = null;
 return {target: parent, added: [], removed: [child], next};
}
const changed = (target: F): Rec => ({target});

function page(initial: F, extra: Partial<ReplayConfig> = {}) {
 let observe: ((records: readonly object[]) => void) | undefined;
 class Observer { constructor(callback: (records: readonly object[]) => void) { observe = callback; } observe(): void {} disconnect(): void {} }
 const chunks: ReplayChunk[] = [];
 let tick = 0;
 const timers: ReplayConfig["timers"] = {set: () => 1, clear: () => {}};
 const config: ReplayConfig = {
  projectPolicy: true, deploymentOptIn: true, root: documentOf(initial), replayId: "a".repeat(32), sessionId: "b".repeat(32), capturePolicyRevision: "1",
  domain: {host: "c".repeat(32), boot: "d".repeat(32), runtime: "e".repeat(32)}, clock: () => ({wall_ns: String(1_000_000 + ++tick), mono_ns: String(tick), uncertainty_ns: "0"}),
  dom, observer: Observer, timers, eventTarget: {addEventListener: () => {}, removeEventListener: () => {}}, ...extra,
 };
 const recorder = createRecorder(config, chunk => { chunks.push(JSON.parse(JSON.stringify(chunk))); return "accepted"; });
 recorder.setConsent(true);
 return {chunks, deliver: (...records: Rec[]) => observe!(records), recorder};
}
const idOf = (chunk: ReplayChunk, index: number): string => chunk.nodes[index]!.id;
const mutations = (chunk: ReplayChunk) => chunk.events.filter(event => event.kind === "mutation").map(event => event.node);

function list(count: number): {html: F; items: F; known: F[]} {
 const known = Array.from({length: count}, () => el("p", txt()));
 const items = el("div", ...known);
 return {html: el("section", items), items, known};
}

test("an element appended to a list the replay holds is recorded once: the delta carries the new subtrees only, under the list's id", () => {
 const {html, items, known} = list(50);
 const r = page(html);
 expect(r.chunks).toHaveLength(1);
 const checkpoint = r.chunks[0]!, listId = checkpoint.nodes.find(node => node.tag === "div")!.id;
 expect(checkpoint.nodes).toHaveLength(2 + 100); // section, div, 50 x (p + text)
 const first = el("p", txt()), second = el("span", txt());
 r.deliver(add(items, first), add(items, second));
 expect(r.chunks).toHaveLength(2);
 const delta = r.chunks[1]!;
 expect(delta.sequence).not.toBe(delta.checkpoint_sequence);
 expect(delta.nodes.map(node => node.tag)).toEqual(["p", "masked", "span", "masked"]);
 expect(delta.nodes[0]!.parent).toBe(listId);
 expect(delta.nodes[1]!.parent).toBe(idOf(delta, 0));
 expect(delta.nodes[2]!.parent).toBe(listId);
 for (const node of delta.nodes) expect(Number(node.id)).toBeGreaterThan(checkpoint.nodes.length); // fresh ids: nothing the replay holds is re-sent
 expect(mutations(delta)).toEqual([idOf(delta, 0)]); // one event on the first new node: it names no node the viewer holds, so nothing is deleted
 expect(delta.gap).toBe(false);
 expect(delta.loss).toBe(checkpoint.loss);
 void known;
});

test("records inside the new nodes (text rewrites, attribute churn, appends below them) are part of the new subtree, never a re-walk of the list", () => {
 const {html, items} = list(30);
 const r = page(html);
 const fresh = el("p", txt());
 const nested = el("span");
 r.deliver(add(items, fresh), changed(fresh.kids[0]!), changed(fresh), add(fresh, nested), changed(nested), add(nested, txt()));
 expect(r.chunks).toHaveLength(2);
 const delta = r.chunks[1]!;
 expect(delta.nodes.map(node => node.tag)).toEqual(["p", "masked", "span", "masked"]);
 expect(mutations(delta)).toHaveLength(1);
});

test("an insertion before a known sibling, a removal of a known node and a move of a known node are the re-walk of the parent: surviving ids stay, the removed node is gone", () => {
 for (const operation of ["insert", "remove", "move"] as const) {
  const {html, items, known} = list(5);
  const other = el("div", el("p", txt()));
  html.kids.push(other); other.parent = html;
  const r = page(html);
  const checkpoint = r.chunks[0]!, listId = checkpoint.nodes.find(node => node.tag === "div")!.id;
  const before = checkpoint.nodes.filter(node => node.parent === listId).map(node => node.id);
  if (operation === "insert") r.deliver(add(items, el("p", txt()), known[2]));
  else if (operation === "remove") r.deliver(remove(known[1]!));
  else { const moved = other.kids[0]!; const from = remove(moved); r.deliver(add(items, moved), from); }
  expect(r.chunks).toHaveLength(2);
  const delta = r.chunks[1]!;
  expect(mutations(delta)).toContain(listId);
  const after = delta.nodes.filter(node => node.parent === listId).map(node => node.id);
  expect(after).toHaveLength(operation === "remove" ? 4 : 6);
  if (operation === "remove") expect(after).toEqual(before.filter((_, index) => index !== 1));
  else expect(after.filter(id => before.includes(id))).toHaveLength(5);
 }
});

test("a node added and removed in one batch changes nothing the replay shows: no chunk", () => {
 const {html, items} = list(10);
 const r = page(html);
 const fleeting = el("p", txt());
 r.deliver(add(items, fleeting), changed(fleeting.kids[0]!), remove(fleeting));
 expect(r.chunks).toHaveLength(1);
});

test("a scripted element, a comment and an element recorded together: only what the replay shows is sent, in document order", () => {
 const {html, items} = list(3);
 const r = page(html);
 const script = el("script", txt()), note = comment(), shown = el("span");
 r.deliver(add(items, script), add(items, shown), add(items, note));
 expect(r.chunks).toHaveLength(2);
 expect(r.chunks[1]!.nodes.map(node => node.tag)).toEqual(["span"]);
});

test("new nodes are shown in document order even when they were recorded in another order: an insertion before a node of the same batch is a record that is not at the end of the list, so the list is re-read", () => {
 const {html, items} = list(3);
 const r = page(html);
 const later = el("span"), earlier = el("p");
 r.deliver(add(items, later), add(items, earlier, later));
 const delta = r.chunks[1]!, listId = r.chunks[0]!.nodes.find(node => node.tag === "div")!.id;
 expect(mutations(delta)).toEqual([listId]);
 const shown = delta.nodes.filter(node => node.parent === listId);
 expect(shown.map(node => node.tag)).toEqual(["p", "p", "p", "p", "span"]); // the three known children, then the two new ones in document order
 expect(Number(shown[3]!.id)).toBeLessThan(Number(shown[4]!.id));
});

test("a new node that does not end the list, because an element the replay never showed sits after it, is the re-walk of the list (never a wrong order)", () => {
 const known = el("p", txt()), hidden = comment();
 const items = el("div", known, hidden), html = el("section", items);
 const r = page(html);
 const first = el("span"), last = el("p");
 r.deliver(add(items, first, hidden), add(items, last));
 const delta = r.chunks[1]!, listId = r.chunks[0]!.nodes.find(node => node.tag === "div")!.id;
 expect(mutations(delta)).toEqual([listId]);
 expect(delta.nodes.filter(node => node.parent === listId).map(node => node.tag)).toEqual(["p", "span", "p"]);
});

test("a parent that shows no children (widget, editable, input) is re-read as itself: the new child is never recorded under it", () => {
 for (const name of ["select", "input", "iframe"]) {
  const widget = el(name), html = el("section", widget);
  const r = page(html);
  r.deliver(add(widget, el("p", txt())));
  const delta = r.chunks[1]!;
  expect(delta.nodes).toHaveLength(1);
  expect(delta.nodes[0]!.id).toBe(r.chunks[0]!.nodes.find(node => node.parent !== "0")!.id);
  expect(delta.nodes.every(node => node.tag === "masked" || node.tag === "input")).toBe(true);
 }
 const editable = el("div"); editable.editable = true;
 const r = page(el("section", editable));
 r.deliver(add(editable, el("p", txt())));
 expect(r.chunks[1]!.nodes).toHaveLength(1);
});

test("a change below a node the replay shows as one opaque placeholder is the re-walk of the placeholder, not a new subtree", () => {
 const option = el("option", txt()), select = el("select", option), html = el("section", select);
 const r = page(html);
 r.deliver(changed(option.kids[0]!));
 const delta = r.chunks[1]!;
 expect(delta.nodes).toHaveLength(1);
 expect(delta.nodes[0]).toMatchObject({tag: "masked", class: "masked"});
});

test("an append the chunk cannot hold becomes the re-walk of the parent, which collapses it into a declared gap instead of a chunk the server refuses", () => {
 const {html, items} = list(5);
 const r = page(html);
 const batch = Array.from({length: 5000}, () => el("p"));
 for (const child of batch) { child.parent = items; items.kids.push(child); }
 r.deliver({target: items, added: batch, removed: [], next: null});
 const delta = r.chunks.at(-1)!;
 expect(r.chunks.length).toBeGreaterThanOrEqual(2);
 expect(delta.nodes.length).toBeLessThanOrEqual(4096);
 expect(delta.gap).toBe(true);
 expect(Number(delta.loss)).toBeGreaterThan(0);
});

test("appends to more lists than a delta may name are one full checkpoint, as before", () => {
 const lists = Array.from({length: MAX_MUTATION_ROOTS + 1}, () => el("div", el("p")));
 const html = el("section", ...lists);
 const r = page(html);
 r.deliver(...lists.map(parent => add(parent, el("p"))));
 const last = r.chunks.at(-1)!;
 expect(last.sequence).toBe(last.checkpoint_sequence);
});

test("a long run of appends is a run of small deltas: no checkpoint beyond the first, and each chunk is as small as what was added", () => {
 const {html, items} = list(400);
 const r = page(html);
 for (let batch = 0; batch < 40; batch++) r.deliver(add(items, el("p", txt())), add(items, el("span", txt())));
 expect(r.chunks).toHaveLength(41);
 expect(r.chunks.filter(chunk => chunk.sequence === chunk.checkpoint_sequence)).toHaveLength(1);
 for (const chunk of r.chunks.slice(1)) expect(chunk.nodes).toHaveLength(4);
});

test("a record the platform cannot describe (not a child-list record) is the re-walk of its target, as before", () => {
 const {html, items} = list(5);
 const r = page(html);
 r.deliver(changed(items));
 const delta = r.chunks[1]!;
 expect(delta.nodes).toHaveLength(11);
});

test("a node the replay holds that now sits inside a region it shows no children of is not sent again at the root of the replay", () => {
 const {html, known} = list(3);
 const widget = el("select");
 html.kids.push(widget); widget.parent = html;
 const r = page(html);
 const hidden = el("div");
 const moved = known[1]!;
 const left = remove(moved);
 hidden.kids.push(moved); moved.parent = hidden; // <select><div><p/></div></select>: the div never was in the replay, the p still is
 r.deliver(left, add(widget, hidden));
 const first = r.chunks.length;
 r.deliver(changed(moved));
 expect(r.chunks).toHaveLength(first); // nothing the replay shows changed: no chunk, and above all no node under the root "0"
 for (const chunk of r.chunks.slice(1)) expect(chunk.nodes.filter(node => node.parent === "0")).toHaveLength(0);
});

test("a change to a node directly under an open shadow root, whose host the platform accessors do not name, is a full checkpoint", () => {
 const inner = el("p"), shadow: F = {t: 11, name: "#shadow-root", kids: [inner], parent: null};
 inner.parent = shadow;
 const host = el("div"); host.shadow = shadow;
 const r = page(el("section", host));
 r.deliver(changed(inner));
 const last = r.chunks.at(-1)!;
 expect(r.chunks).toHaveLength(2);
 expect(last.sequence).toBe(last.checkpoint_sequence);
});

// Firefox reports `parent.replaceChildren(...)` as ONE record whose `nextSibling` is null, however the children were rearranged: a tail record that is not an append.
test("a replaceChildren batch (one record, nextSibling null) that inserts before or reorders the held children is the re-walk of the parent, never an append or nothing", () => {
 for (const shape of ["new first", "reorder", "new first and reorder", "new in the middle"] as const) {
  const {html, items, known} = list(5);
  const r = page(html);
  const checkpoint = r.chunks[0]!, listId = checkpoint.nodes.find(node => node.tag === "div")!.id;
  const before = checkpoint.nodes.filter(node => node.parent === listId).map(node => node.id);
  const fresh = el("span", txt());
  const order = shape === "new first" ? [fresh, ...known] : shape === "reorder" ? [known[1]!, known[0]!, ...known.slice(2)] : shape === "new first and reorder" ? [fresh, known[3]!, known[0]!, known[1]!, known[2]!, known[4]!] : [known[0]!, known[1]!, fresh, known[2]!, known[3]!, known[4]!];
  const old = [...items.kids];
  items.kids = order; for (const kid of order) kid.parent = items;
  r.deliver({target: items, added: order, removed: old, next: null});
  expect(r.chunks, shape).toHaveLength(2);
  const delta = r.chunks[1]!;
  expect(mutations(delta), shape).toContain(listId);
  const after = delta.nodes.filter(node => node.parent === listId).map(node => node.id);
  const expected = order.map(kid => kid === fresh ? "fresh" : before[known.indexOf(kid)]!);
  expect(after.map(id => before.includes(id) ? id : "fresh"), shape).toEqual(expected);
 }
});

test("a custom element is re-walked, never appended to: while it had no children it may have been recorded as an inferred closed shadow host", () => {
 const card = el("x-card"), html = el("section", card);
 const r = page(html);
 const cardId = r.chunks[0]!.nodes.find(node => node.tag === "masked")!.id;
 r.deliver(add(card, el("p", txt())));
 expect(r.chunks).toHaveLength(2);
 const delta = r.chunks[1]!;
 expect(delta.sequence).not.toBe(delta.checkpoint_sequence);
 expect(delta.nodes.map(node => node.tag)).toEqual(["masked", "p", "masked"]);
 expect(delta.nodes[0]!.id).toBe(cardId); // the host itself is sent again, now with its child
});
test("a late start is recorded: the first checkpoint is gap-marked and lateStart() names the reason; a supported start is neither (D100)", () => {
 const late = page(el("section", el("p")), {lateStart: () => "document_ready_state"});
 expect(late.chunks[0]!.gap).toBe(true);
 expect(late.recorder.lateStart()).toBe("document_ready_state");
 const supported = page(el("section", el("p")), {lateStart: () => null});
 expect(supported.chunks[0]!.gap).toBe(false);
 expect(supported.recorder.lateStart()).toBeNull();
 const thrown = page(el("section"), {lateStart: () => { throw Error("probe"); }});
 expect(thrown.recorder.lateStart()).toBe("probe_failed"); // an unknown start is never claimed supported
 expect(thrown.chunks[0]!.gap).toBe(true);
});

test("no page node stays referenced between callbacks: the batch scratch, the trailing-node run included, is empty after an append batch", () => {
 const {html, items} = list(5);
 const r = page(html);
 r.deliver(add(items, el("p", txt())), add(items, el("span", txt())));
 expect(r.chunks).toHaveLength(2);
 const scratch = r.recorder as unknown as Record<string, {length?: number; size?: number}>;
 for (const name of ["run", "rewalkNodes", "rewalkIds", "groups", "below", "appended", "fresh", "seen", "rewalk"]) {
  const held = scratch[name];
  expect(held, name).toBeDefined();
  expect(held!.length ?? held!.size, name).toBe(0);
 }
});
