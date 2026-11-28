// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// A MutationRecord's addedNodes and removedNodes make the platform create a NodeList wrapper per record (about 960 per 400-node batch, most of what the observer
// callback still allocated in Firefox, where those collections were charged to the p95). The recorder asks a record only for its type, target and nextSibling and
// reads the target's own children at the end of the batch. Driven here through the real platform accessors (`captureDomAccessors`) over a fake platform whose
// record and list getters count every read.
import {test, expect} from "bun:test";
import {createRecorder} from "../src/replay/recorder.ts";
import {captureDomAccessors} from "../src/replay/tree.ts";
import type {ReplayChunk, ReplayConfig} from "../src/replay/types.ts";

const reads = {added: 0, removed: 0, length: 0};
class PNode {
 parent: PNode | null = null; kids: PNode[] = [];
 constructor(readonly kind: number, readonly tag: string) {}
 get nodeType() { return this.kind; } get parentNode() { return this.parent; } get firstChild() { return this.kids[0] ?? null; } get lastChild() { return this.kids.at(-1) ?? null; }
 get previousSibling() { return this.parent === null ? null : this.parent.kids[this.parent.kids.indexOf(this) - 1] ?? null; }
 get nextSibling() { return this.parent === null ? null : this.parent.kids[this.parent.kids.indexOf(this) + 1] ?? null; }
}
class PElement extends PNode { get localName() { return this.tag; } get shadowRoot() { return null; } }
class PList { constructor(readonly items: PNode[]) { items.forEach((item, at) => { Object.defineProperty(this, at, {value: item}); }); } get length() { reads.length++; return this.items.length; } }
class PRecord {
 constructor(readonly t: string, readonly node: PNode, readonly following: PNode | null = null, readonly added: PNode[] = [], readonly removed: PNode[] = []) {}
 get target() { return this.node; } get type() { return this.t; } get nextSibling() { return this.following; }
 get addedNodes() { reads.added++; return new PList(this.added); } get removedNodes() { reads.removed++; return new PList(this.removed); }
}
class PEvent { get target() { return null; } get clientX() { return 0; } get clientY() { return 0; } }
const platform = {Node: PNode, Element: PElement, MouseEvent: PEvent, Event: PEvent, MutationRecord: PRecord, NodeList: PList};

const el = (tag: string, ...kids: PNode[]): PElement => { const out = new PElement(1, tag); for (const kid of kids) { kid.parent = out; out.kids.push(kid); } return out; };
const text = (): PNode => new PNode(3, "#text");
function append(parent: PNode, child: PNode): PRecord { child.parent = parent; parent.kids.push(child); return new PRecord("childList", parent, null, [child]); }
function insertBefore(parent: PNode, child: PNode, before: PNode): PRecord { child.parent = parent; parent.kids.splice(parent.kids.indexOf(before), 0, child); return new PRecord("childList", parent, before, [child]); }
function removeChild(child: PNode): PRecord { const parent = child.parent!, at = parent.kids.indexOf(child), following = parent.kids[at + 1] ?? null; parent.kids.splice(at, 1); child.parent = null; return new PRecord("childList", parent, following, [], [child]); }

function page() {
 const items = el("div", el("p", text()), el("p", text()), el("p", text()));
 const document = new PNode(9, "#document"), html = el("section", items);
 html.parent = document; document.kids.push(html);
 let observe: ((records: readonly object[]) => void) | undefined;
 class Observer { constructor(callback: (records: readonly object[]) => void) { observe = callback; } observe(): void {} disconnect(): void {} }
 const chunks: ReplayChunk[] = [];
 let tick = 0;
 const config: ReplayConfig = {
  projectPolicy: true, deploymentOptIn: true, root: document, replayId: "a".repeat(32), sessionId: "b".repeat(32), capturePolicyRevision: "1",
  domain: {host: "c".repeat(32), boot: "d".repeat(32), runtime: "e".repeat(32)}, clock: () => ({wall_ns: String(1_000_000 + ++tick), mono_ns: String(tick), uncertainty_ns: "0"}),
  dom: captureDomAccessors(platform), observer: Observer, timers: {set: () => 1, clear: () => {}}, eventTarget: {addEventListener: () => {}, removeEventListener: () => {}},
 };
 createRecorder(config, chunk => { chunks.push(JSON.parse(JSON.stringify(chunk))); return "accepted"; }).setConsent(true);
 return {items, chunks, deliver: (...records: PRecord[]) => observe!(records)};
}

test("a batch of appends, a removal of the last child and a re-read of the list never reads a record's addedNodes or removedNodes, and the chunks are the ones they were", () => {
 reads.added = reads.removed = reads.length = 0;
 const {items, chunks, deliver} = page();
 const listId = chunks[0]!.nodes.find(node => node.tag === "div")!.id;
 // 40 appends in one batch: one delta with only the new subtrees, under the list's id.
 const records: PRecord[] = [];
 for (let i = 0; i < 40; i++) { const child = el(i % 2 ? "p" : "span", text()); records.push(append(items, child)); }
 deliver(...records);
 expect(chunks).toHaveLength(2);
 expect(chunks[1]!.nodes).toHaveLength(80);
 expect(chunks[1]!.nodes.filter(node => node.parent === listId)).toHaveLength(40);
 expect(chunks[1]!.events.filter(event => event.kind === "mutation")).toHaveLength(1);
 // Removing the last child is the list re-read; appending after it again is an append on the re-read list.
 deliver(removeChild(items.kids.at(-1)!));
 expect(chunks).toHaveLength(3);
 expect(chunks[2]!.events.filter(event => event.kind === "mutation").map(event => event.node)).toEqual([listId]);
 expect(chunks[2]!.nodes.filter(node => node.parent === listId)).toHaveLength(42);
 deliver(append(items, el("p", text())));
 expect(chunks).toHaveLength(4);
 expect(chunks[3]!.nodes).toHaveLength(2);
 // An insertion before a child is a record with a following sibling: the list is read again.
 deliver(insertBefore(items, el("span"), items.kids[1]!));
 expect(chunks).toHaveLength(5);
 expect(chunks[4]!.events.filter(event => event.kind === "mutation").map(event => event.node)).toEqual([listId]);
 expect(reads).toEqual({added: 0, removed: 0, length: 0});
});

test("recordKind reads only the platform's own type and nextSibling: tail, inside and other, and a page-planted trap on a record never runs", () => {
 const dom = captureDomAccessors(platform);
 const parent = el("div", el("p")), child = parent.kids[0]!;
 expect(dom.recordKind(new PRecord("childList", parent))).toBe("tail");
 expect(dom.recordKind(new PRecord("childList", parent, child))).toBe("inside");
 expect(dom.recordKind(new PRecord("attributes", parent))).toBe("other");
 expect(dom.recordKind(new PRecord("characterData", child))).toBe("other");
 const trapped = new PRecord("childList", parent);
 for (const name of ["type", "nextSibling", "addedNodes", "removedNodes"]) Object.defineProperty(trapped, name, {get() { throw Error("planted " + name); }});
 expect(dom.recordKind(trapped)).toBe("tail");
 // A platform without the getters answers "other": the target is re-read whole, as for any record the recorder cannot describe.
 const bare = captureDomAccessors({Node: PNode, Element: PElement, MouseEvent: PEvent, Event: PEvent, MutationRecord: class { get target() { return null; } }});
 expect(bare.recordKind(new PRecord("childList", parent))).toBe("other");
 expect(reads).toEqual({added: 0, removed: 0, length: 0});
});
