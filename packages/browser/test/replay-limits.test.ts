// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The server admits at most 65536 chunks and 1024 checkpoints per replay (internal/replays MaxSequence, MaxCheckpoints) and refuses
// the rest; a refused chunk would poison its whole ingest batch. The recorder therefore ends capture at its budget instead of emitting
// anything outside the server's closed schema.
import {test, expect} from "bun:test";
import {createRecorder} from "../src/replay/recorder.ts";
import {MAX_CHECKPOINTS, MAX_SEQUENCE, canonicalJSON, sha256ChunkHex, sha256Hex} from "../src/replay/policy.ts";
import {createHash} from "node:crypto";
import type {ReplayChunk} from "../src/replay/types.ts";
import {CHECKPOINT_MS, FLUSH_MS, scriptedPage} from "./recorded-session.ts";

function recording() {
 const stage = scriptedPage();
 const chunks: ReplayChunk[] = [];
 const recorder = createRecorder({...stage.config, projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(chunk); return "accepted"; });
 recorder.setConsent(true);
 return {stage, chunks, recorder};
}

test("the constants mirror the server's ceilings", () => {
 expect(MAX_SEQUENCE).toBe(65536);
 expect(MAX_CHECKPOINTS).toBe(1024);
});

test("capture ends after the 1024th checkpoint and never resumes", () => {
 const {stage, chunks, recorder} = recording();
 for (let i = 0; i < MAX_CHECKPOINTS + 20; i++) stage.fire(CHECKPOINT_MS);
 expect(chunks).toHaveLength(MAX_CHECKPOINTS);
 expect(chunks.every(chunk => chunk.sequence === chunk.checkpoint_sequence)).toBe(true);
 expect(chunks.at(-1)!.sequence).toBe(String(MAX_CHECKPOINTS));
 stage.pointer("button", 1, 1); stage.fire(FLUSH_MS); stage.grow();
 recorder.setConsent(false); recorder.setConsent(true);
 expect(chunks).toHaveLength(MAX_CHECKPOINTS);
});

test("capture ends after the 65536th chunk and never resumes", () => {
 const {stage, chunks, recorder} = recording();
 for (let i = 0; i < MAX_SEQUENCE + 20; i++) { stage.pointer("html", i, i); stage.fire(FLUSH_MS); }
 expect(chunks).toHaveLength(MAX_SEQUENCE);
 expect(chunks.at(-1)!.sequence).toBe(String(MAX_SEQUENCE));
 recorder.setConsent(false); recorder.setConsent(true);
 stage.pointer("html", 1, 1); stage.fire(FLUSH_MS);
 expect(chunks).toHaveLength(MAX_SEQUENCE);
}, 60_000); // 65,556 real flushes: 8-11 s on Linux bun 1.3.14, past bun's 5 s default.

// ---- Running total over the live tree (03.07-W2): a delta may not push the ids allocated since the last checkpoint past MAX_NODES. ----
import {MAX_NODES} from "../src/replay/policy.ts";
import type {DomAccessors} from "../src/replay/types.ts";

test("mutation churn never allocates past the node cap: a fresh checkpoint recounts the live tree, with no gap", () => {
 const {stage, chunks} = recording();
 for (let i = 0; i < 400; i++) stage.churn(100); // every call replaces the section's paragraphs with 100 new ones (a re-read keeps the ids of nodes it still holds, so only new nodes count): 40,000 ids without a recount
 const ids = chunks.flatMap(chunk => chunk.nodes.map(node => Number(node.id)));
 expect(Math.max(...ids)).toBeLessThanOrEqual(MAX_NODES);
 expect(chunks.filter(chunk => chunk.sequence === chunk.checkpoint_sequence).length).toBeGreaterThan(1);
 expect(chunks.some(chunk => chunk.gap)).toBe(false);
});

interface Fake { t: number; name: string; kids: Fake[]; parent: Fake | null }
const fake = (name: string, ...kids: Fake[]): Fake => { const out: Fake = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = out; return out; };
function wideDom(): DomAccessors {
 return {
  nodeType: n => (n as Fake).t, firstChild: n => (n as Fake).kids[0] ?? null,
  nextSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) + 1] ?? null; },
  lastChild: n => (n as Fake).kids.at(-1) ?? null,
  previousSibling: n => { const parent = (n as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(n as Fake) - 1] ?? null; },
  parentNode: n => (n as Fake).parent, localName: n => (n as Fake).name, openShadowRoot: () => null, editable: () => false,
  mutationTarget: record => (record as {target: object}).target, recordKind: () => "other", eventTarget: () => null, clientX: () => 0, clientY: () => 0,
 };
}

test("a live tree that outgrows the cap through a delta is recounted: opaque placeholder plus an extra loss, never a silent over-cap delta", () => {
 // `bulk` holds the siblings that a delta on `host` does not re-read; at 20 nodes below the cap the first checkpoint walk is complete
 // (its only loss is the 4096-node chunk fit), and 200 more nodes under `host` push the live tree over the cap.
 const bulk = fake("div"); const host = fake("div");
 for (let i = 0; i < MAX_NODES - 120; i++) { const p = fake("p"); p.parent = bulk; bulk.kids.push(p); }
 const html = fake("html", fake("body", bulk, host));
 const document: Fake = {t: 9, name: "#document", kids: [html], parent: null}; html.parent = document;
 const base = scriptedPage();
 let observe: ((records: readonly object[]) => void) | undefined;
 class Observer { constructor(callback: (records: readonly object[]) => void) { observe = callback; } observe(): void {} disconnect(): void {} }
 const chunks: ReplayChunk[] = [];
 const recorder = createRecorder({...base.config, root: document, dom: wideDom(), observer: Observer, projectPolicy: true, deploymentOptIn: true}, chunk => { chunks.push(chunk); return "accepted"; });
 recorder.setConsent(true);
 expect(chunks).toHaveLength(1);
 expect(chunks[0]!.loss).toBe("1"); // chunk fit only: the walk reached no cap
 for (let i = 0; i < 200; i++) { const q = fake("span"); q.parent = host; host.kids.push(q); }
 observe!([{target: host}]);
 const last = chunks.at(-1)!;
 expect(chunks).toHaveLength(2);
 expect(last.sequence).toBe(last.checkpoint_sequence); // the over-cap delta was replaced by a complete recount, not emitted
 expect(last.loss).toBe("3"); // + the walk's own cap overflow and the chunk fit
 expect(last.gap).toBe(true);
 expect(Math.max(...last.nodes.map(node => Number(node.id)))).toBeLessThanOrEqual(MAX_NODES);
}, 60_000);

// ---- Closed shadow roots (03.07-W1): recognised at attachShadow time while a recorder is active, opaque in the replay tree. ----
import {captureDomAccessors, newWalkState, walk} from "../src/replay/tree.ts";
import {NodeTable} from "../src/replay/nodes.ts";

class PNode {
 parent: PNode | null = null; kids: PNode[] = [];
 get nodeType() { return 1; } get parentNode() { return this.parent; } get firstChild() { return this.kids[0] ?? null; }
 get lastChild() { return this.kids.at(-1) ?? null; } get previousSibling() { return this.parent === null ? null : this.parent.kids[this.parent.kids.indexOf(this) - 1] ?? null; }
 get nextSibling() { return this.parent === null ? null : this.parent.kids[this.parent.kids.indexOf(this) + 1] ?? null; }
 add(kid: PNode): PNode { kid.parent = this; this.kids.push(kid); return kid; }
}
class PElement extends PNode {
 private root: object | null = null; constructor(private readonly tag: string) { super(); }
 get localName() { return this.tag; } get shadowRoot() { return this.root; }
 // The platform reads the init dictionary itself; `mode: "closed"` hides the root from shadowRoot.
 attachShadow(init: {mode: string}): object { if (this.root !== null || this.attached) throw new TypeError("already attached"); this.attached = true; const made = {}; if (init.mode === "open") this.root = made; return made; }
 private attached = false;
 // What the platform answers about upgrade state and layout; a test sets them per element.
 defined = true; box = 0; layoutReads = 0;
 matches(selector: string): boolean { return selector === ":defined" && this.defined; }
 get offsetWidth() { this.layoutReads++; return this.box; } get offsetHeight() { this.layoutReads++; return this.box; }
}
class PRecord { get target() { return null; } }
class PEvent { get target() { return null; } get clientX() { return 0; } get clientY() { return 0; } }
const platform = () => ({Node: PNode, Element: PElement, MouseEvent: PEvent, Event: PEvent, MutationRecord: PRecord});

test("a closed host attached while capture is active is recognised; open hosts and plain elements are not", () => {
 const dom = captureDomAccessors(platform());
 const closed = new PElement("div"), open = new PElement("div"), plain = new PElement("div");
 closed.attachShadow({mode: "closed"}); open.attachShadow({mode: "open"});
 expect([dom.closedShadow!(closed), dom.closedShadow!(open), dom.closedShadow!(plain)]).toEqual([true, false, false]);
 dom.release!();
});

test("the attachShadow wrapper never reads the init dictionary again and forwards results and exceptions unchanged", () => {
 const dom = captureDomAccessors(platform());
 let reads = 0;
 const init = {get mode() { reads++; return "closed"; }};
 const host = new PElement("div"), returned = host.attachShadow(init);
 expect(reads).toBe(1); // the platform's own single read; the recorder added none
 expect(typeof returned).toBe("object");
 expect(() => host.attachShadow({mode: "closed"})).toThrow(TypeError); // platform exception, unchanged
 expect(dom.closedShadow!(host)).toBe(true);
 dom.release!();
});

test("release restores the platform method; a page that wrapped it in between keeps its wrapper and the hook goes inert", () => {
 const original = Object.getOwnPropertyDescriptor(PElement.prototype, "attachShadow")!.value;
 const first = captureDomAccessors(platform());
 expect(Object.getOwnPropertyDescriptor(PElement.prototype, "attachShadow")!.value).not.toBe(original);
 first.release!();
 expect(Object.getOwnPropertyDescriptor(PElement.prototype, "attachShadow")!.value).toBe(original);
 const second = captureDomAccessors(platform());
 const ours = Object.getOwnPropertyDescriptor(PElement.prototype, "attachShadow")!.value as (...args: unknown[]) => unknown;
 const pageWrapper = function (this: unknown, ...args: unknown[]) { return Reflect.apply(ours, this, args); };
 Object.defineProperty(PElement.prototype, "attachShadow", {value: pageWrapper, writable: true, configurable: true});
 second.release!();
 expect(Object.getOwnPropertyDescriptor(PElement.prototype, "attachShadow")!.value).toBe(pageWrapper); // not clobbered
 const late = new PElement("div"); late.attachShadow({mode: "closed"});
 expect(second.closedShadow!(late)).toBe(false); // inert after release
 Object.defineProperty(PElement.prototype, "attachShadow", {value: original, writable: true, configurable: true});
});

test("walk emits a closed-shadow host as one opaque node and never its light children", () => {
 const dom = captureDomAccessors(platform());
 const root = new PElement("div"), host = new PElement("div") , light = new PElement("p");
 root.add(host); host.add(light);
 host.attachShadow({mode: "closed"});
 const state = newWalkState(new WeakMap(), (() => { let n = 0; return () => ++n; })());
 walk(dom, root, 0, state);
 expect(state.nodes.toArray().map(node => [node.tag, node.class])).toEqual([["div", ""], ["masked", "masked"]]);
 dom.release!();
});

// ---- A closed root made BEFORE capture started cannot be proven; it is inferred from platform answers only, never from content. ----
const preexisting = (name: string, set: (element: PElement) => void = () => {}): PElement => {
 const element = new PElement(name); element.box = 20;
 element.attachShadow({mode: "closed"}); // before captureDomAccessors installed the attachShadow hook: the recorder never saw this call
 set(element);
 return element;
};

test("a pre-existing closed host is recognised from the platform's own answers: an upgraded custom element, null shadowRoot, no light child, a layout box", () => {
 const widget = preexisting("x-widget");
 const dom = captureDomAccessors(platform());
 expect(dom.closedShadow!(widget, "x-widget")).toBe(true);
 expect(dom.closedShadow!(widget)).toBe(true); // the name is optional
 dom.release!();
});

test("the inference never fires without all of its facts: plain tags, light children, undefined or boxless or reserved names and open roots stay ordinary elements", () => {
 const plain = preexisting("div"), withChild = preexisting("x-widget", e => e.add(new PElement("p"))), undefinedName = preexisting("x-widget", e => { e.defined = false; });
 const boxless = preexisting("x-widget", e => { e.box = 0; }), reserved = preexisting("font-face"), open = new PElement("x-widget"); open.box = 20; open.attachShadow({mode: "open"});
 const none = new PElement("x-widget"); none.box = 20; // a custom element that never had a shadow root and renders through CSS: indistinguishable, so it is marked (the documented false positive)
 const dom = captureDomAccessors(platform());
 expect([plain, withChild, undefinedName, boxless, reserved, open].map(e => dom.closedShadow!(e))).toEqual([false, false, false, false, false, false]);
 expect(dom.closedShadow!(none)).toBe(true);
 dom.release!();
});

test("the inference reads only platform accessors: page-planted traps on the element never run", () => {
 const widget = preexisting("x-widget");
 let traps = 0;
 for (const name of ["matches", "offsetWidth", "offsetHeight", "shadowRoot", "firstChild"]) Object.defineProperty(widget, name, {configurable: true, get() { traps++; throw Error("TRAP " + name); }});
 const dom = captureDomAccessors(platform());
 expect(dom.closedShadow!(widget, "x-widget")).toBe(true);
 expect(traps).toBe(0);
 dom.release!();
});

test("walk emits a pre-existing closed host as the closed-shadow mark (opaque with the constant mask), distinct from every other opaque node, and walks a custom element that has light children", () => {
 const root = new PElement("div"), host = new PElement("x-widget"), withChild = new PElement("x-card"), light = new PElement("p"), frame = new PElement("iframe");
 host.box = 20; host.attachShadow({mode: "closed"}); withChild.box = 20; withChild.attachShadow({mode: "closed"});
 root.add(host); root.add(withChild); withChild.add(light); root.add(frame);
 const dom = captureDomAccessors(platform());
 const state = newWalkState(new WeakMap(), (() => { let n = 0; return () => ++n; })());
 walk(dom, root, 0, state);
 expect(state.nodes.toArray().map(node => [node.tag, node.class, node.text])).toEqual([["div", "", ""], ["masked", "masked", "[masked]"], ["masked", "", ""], ["p", "", ""], ["masked", "masked", ""]]);
 dom.release!();
});

test("layout is read only for an empty, upgraded custom element: plain tags, custom elements with children or not upgraded, and open hosts never cost a box read", () => {
 const root = new PElement("section"), plain = new PElement("div"), para = new PElement("p"), withChild = new PElement("x-card"), notUpgraded = new PElement("x-later"), open = new PElement("x-open"), empty = new PElement("x-empty");
 for (const element of [plain, para, withChild, notUpgraded, open, empty]) element.box = 20;
 withChild.add(new PElement("p")); notUpgraded.defined = false; open.attachShadow({mode: "open"});
 for (const element of [plain, para, withChild, notUpgraded, empty]) root.add(element);
 const dom = captureDomAccessors(platform());
 walk(dom, root, 0, newWalkState(new WeakMap(), (() => { let n = 0; return () => ++n; })()));
 expect(dom.closedShadow!(open)).toBe(false); // an open host answers shadowRoot, so no box is read
 expect([plain, para, withChild, notUpgraded, open].map(element => element.layoutReads)).toEqual([0, 0, 0, 0, 0]);
 expect(empty.layoutReads).toBeGreaterThan(0); // the one element the inference has to ask
 dom.release!();
});

// ---- The chain hash is the recorder's dominant per-batch cost (03.09-W3); the optimized block loop must stay byte-exact. ----
test("sha256Hex equals the platform SHA-256 across every padding boundary and multi-block, non-ASCII and large inputs", () => {
 const lengths = [0, 1, 3, 54, 55, 56, 57, 63, 64, 65, 118, 119, 120, 121, 127, 128, 129, 1000, 65537];
 for (const length of lengths) {
  const ascii = "a".repeat(length), mixed = Array.from({length}, (_, i) => String.fromCodePoint(0x61 + (i * 7919) % 0x2f00)).join("");
  for (const text of [ascii, mixed, "\u2028\u{1f600}" + ascii]) expect(sha256Hex(text)).toBe(createHash("sha256").update(text, "utf8").digest("hex"));
 }
 expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});
test("sha256ChunkHex hashes exactly the text sha256Hex would for the same nodes, across padding boundaries and a buffer that must grow", () => {
 for (const count of [0, 1, 2, 3, 7, 40, 1000, 5000]) {
  const nodes = Array.from({length: count}, (_, i) => ({id: String(i + 1), parent: String(i % 5), tag: (["div", "masked", "input"] as const)[i % 3]!, class: i % 7 === 0 ? "masked" as const : "" as const, text: i % 2 === 0 ? "[masked]" as const : "" as const}));
  const pre = '{"a":"é"', post = ',"z":"ü"}';
  const text = pre + canonicalJSON(nodes) + post;
  expect(sha256ChunkHex(pre, NodeTable.of(nodes), post)).toBe(sha256Hex(text));
 }
});
