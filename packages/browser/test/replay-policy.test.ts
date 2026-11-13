// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test, expect} from "bun:test";
import {createHash} from "node:crypto";
import {init} from "../src/index.ts";
import {createRecorder} from "../src/replay/recorder.ts";
import {ReplayStream} from "../src/replay/stream.ts";
import {captureDomAccessors, fitSubtrees} from "../src/replay/tree.ts";
import {MAX_NODES, canonicalJSON, quantize, sha256Hex} from "../src/replay/policy.ts";
import type {ReplayChunk, ReplayConfig, ReplayEventTargetLike, ReplayNode, ReplayTimers} from "../src/replay/types.ts";
import {config as coreConfig} from "../../core/test/fixture.ts";

// ---- Fake DOM. Source strings live only behind prototype getters that count every read. ----
const reads = {value: 0, data: 0, attributes: 0, text: 0, html: 0, layout: 0, traps: 0};
class FRect { constructor(private readonly r: number[]) {} get x() { return this.r[0]!; } get y() { return this.r[1]!; } get width() { return this.r[2]!; } get height() { return this.r[3]!; } }
class FNode {
 parent: FNode | null = null; children: FNode[] = []; readonly nodeKind: number;
 constructor(kind: number) { this.nodeKind = kind; }
 get nodeType() { return this.nodeKind; }
 get parentNode() { return this.parent; }
 get firstChild() { return this.children[0] ?? null; }
 get nextSibling() { const i = this.parent?.children.indexOf(this) ?? -1; return i < 0 ? null : this.parent!.children[i + 1] ?? null; }
 get textContent() { reads.text++; return "x"; }
 get nodeValue() { reads.data++; return "x"; }
 append(child: FNode): FNode { child.parent = this; this.children.push(child); return child; }
}
class FText extends FNode { constructor(readonly secret: string) { super(3); } get data() { reads.data++; return this.secret; } }
class FElement extends FNode {
 shadow: FShadow | null = null; editableFlag = false; closed = false; secretAttrs: Record<string, string> = {}; secretValue = "";
 constructor(readonly name: string) { super(1); }
 get localName() { return this.name; }
 get shadowRoot() { return this.shadow; }
 get value() { reads.value++; return this.secretValue; }
 get id() { reads.attributes++; return this.secretAttrs.id ?? ""; }
 get className() { reads.attributes++; return this.secretAttrs.class ?? ""; }
 get attributes() { reads.attributes++; return this.secretAttrs; }
 get innerHTML() { reads.html++; return "x"; }
 get outerHTML() { reads.html++; return "x"; }
 getBoundingClientRect() { reads.layout++; return new FRect([13, 4, 100000, -99999]); }
}
// isContentEditable lives on HTMLElement only: calling its getter on an SVG element throws, as in real browsers.
class FHtml extends FElement { get isContentEditable() { if (!(this instanceof FHtml)) throw new TypeError("Illegal invocation"); return this.editableFlag; } }
class FShadow extends FNode { constructor() { super(11); } }
class FComment extends FNode { constructor() { super(8); } }
class FRecord { constructor(private readonly t: FNode | null) {} get target() { return this.t; } }
class FEvent { constructor(private readonly t: FNode | null, private readonly cx: number, private readonly cy: number) {} get target() { return this.t; } get clientX() { return this.cx; } get clientY() { return this.cy; } }
class FStyle { constructor(readonly display: string) {} getPropertyValue(name: string) { reads.layout++; return name === "display" ? this.display : "visible"; } }
const globals = {Node: FNode, Element: FElement, HTMLElement: FHtml, MouseEvent: FEvent, Event: FEvent, MutationRecord: FRecord, DOMRectReadOnly: FRect, CSSStyleDeclaration: FStyle, getComputedStyle: (element: object) => { reads.layout++; return new FStyle((element as FElement).name === "span" ? "inline" : "block"); }};
const dom = captureDomAccessors(globals);

function el(name: string, ...children: FNode[]): FHtml { const e = name === "svg" || name === "text" ? (new FElement(name) as FHtml) : new FHtml(name); for (const c of children) e.append(c); return e; }
const text = (secret: string) => new FText(secret);

class FObserver {
 static instances: FObserver[] = [];
 targets: object[] = []; disconnected = false;
 constructor(readonly callback: (records: readonly object[]) => void) { FObserver.instances.push(this); }
 observe(target: object) { this.targets.push(target); }
 disconnect() { this.disconnected = true; }
}
class FTarget implements ReplayEventTargetLike {
 handlers = new Map<string, (event: object) => void>();
 addEventListener(type: string, listener: (event: object) => void) { this.handlers.set(type, listener); }
 removeEventListener(type: string) { this.handlers.delete(type); }
}
class FTimers implements ReplayTimers {
 queue: {at: number; cb: () => void; id: number}[] = []; now = 0; next = 1;
 set(cb: () => void, ms: number) { const id = this.next++; this.queue.push({at: this.now + ms, cb, id}); return id; }
 clear(handle: unknown) { this.queue = this.queue.filter(item => item.id !== handle); }
 advance(ms: number) { const end = this.now + ms; for (;;) { const due = this.queue.filter(item => item.at <= end).sort((a, b) => a.at - b.at)[0]; if (!due) break; this.queue = this.queue.filter(item => item !== due); this.now = due.at; due.cb(); } this.now = end; }
}
interface Rig { chunks: ReplayChunk[]; target: FTarget; timers: FTimers; revoked: number; observer(): FObserver; recorder: ReturnType<typeof createRecorder>; config: ReplayConfig; result: {value: "accepted" | "rejected"} }
function rig(root: FNode, overrides: Partial<ReplayConfig> = {}, flags: {project?: boolean; deployment?: boolean} = {}): Rig {
 FObserver.instances = [];
 const chunks: ReplayChunk[] = [], target = new FTarget(), timers = new FTimers(), result = {value: "accepted" as "accepted" | "rejected"};
 let tick = 0, revoked = 0;
 const config: ReplayConfig = {
  projectPolicy: flags.project ?? true, deploymentOptIn: flags.deployment ?? true, root, replayId: "a".repeat(32), sessionId: "b".repeat(32), capturePolicyRevision: "1",
  domain: {host: "c".repeat(32), boot: "d".repeat(32), runtime: "e".repeat(32)}, clock: () => ({wall_ns: String(1000000 + ++tick), mono_ns: String(tick), uncertainty_ns: "0"}),
  dom, observer: FObserver, eventTarget: target, viewport: () => ({w: 1001, h: 799, x: 0, y: 77}), timers, onRevoked: () => { revoked++; }, ...overrides,
 };
 const rec = createRecorder(config, chunk => { if (result.value === "accepted") chunks.push(chunk); return result.value; });
 const view: Rig = {chunks, target, timers, get revoked() { return revoked; }, observer: () => FObserver.instances.at(-1)!, recorder: rec, config, result};
 return view;
}
const allNodes = (chunks: readonly ReplayChunk[]): ReplayNode[] => chunks.flatMap(c => [...c.nodes]);
const NODE_KEYS = ["class", "id", "parent", "tag", "text"];
const TAGS = ["div", "span", "p", "button", "input", "section", "canvas", "masked"];

function canaryTree() {
 const secrets = ["S3CR3T-A", "S3CR3T-LONGER-VALUE-B", "canary-id-xyzzy-12345", "class-secret-q", "data-secret-url(https://evil.test/p.png)", "pseudo-::before-content", "clipboard-canary-0", "console-canary-1111111", "svg-text-secret-abcdefghij", "contenteditable-secret-zz"];
 const inputs = ["text", "password", "email", "number", "search", "tel", "url", "date", "range", "hidden", "checkbox", "radio", "file"].map((type, i) => { const input = el("input"); input.secretValue = secrets[i % secrets.length]! + type; input.secretAttrs = {type, id: secrets[2]!, class: secrets[3]!, "data-x": secrets[4]!}; return input; });
 const editable = el("div", text(secrets[9]!)); editable.editableFlag = true;
 const svg = el("svg", el("text", text(secrets[8]!)));
 const area = el("textarea", text(secrets[1]!));
 const frame = el("iframe", text("framed-secret"));
 const canvas = el("canvas"); const video = el("video", el("source"));
 const shadow = new FShadow(); shadow.append(el("p", text("open-shadow-secret"))); const host = el("div", text("light-secret")); host.shadow = shadow;
 const closedHost = el("div", text("closed-secret")); closedHost.closed = true;
 const body = el("body", text(secrets[0]!), el("p", text(secrets[1]!)), ...inputs, editable, svg, area, frame, canvas, video, host, closedHost, el("script", text("script-secret")), el("style", text("style-secret")), new FComment());
 return {root: el("html", el("head", el("title", text("title-secret"))), body), secrets: [...secrets, "framed-secret", "open-shadow-secret", "light-secret", "closed-secret", "script-secret", "style-secret", "title-secret", "http", "evil.test"], closedHost};
}

test("capture stays off unless project policy AND deployment opt-in AND consent are all strictly true", () => {
 for (const project of [true, false]) for (const deployment of [true, false]) for (const consent of [true, false, undefined as unknown as boolean, "true" as unknown as boolean]) {
  const {root} = canaryTree(), r = rig(root, {}, {project, deployment});
  r.recorder.setConsent(consent);
  const on = project && deployment && consent === true;
  expect(FObserver.instances.length).toBe(on ? 1 : 0);
  expect(r.chunks.length > 0).toBe(on);
  expect(r.target.handlers.size).toBe(on ? 3 : 0);
  if (!on) expect(reads).toMatchObject({value: 0});
  r.recorder.close();
 }
});

test("pre-buffer canaries: mask constant, no raw field, nothing read, opaque subtrees, identical open shadow rules", () => {
 for (const key of Object.keys(reads) as (keyof typeof reads)[]) reads[key] = 0;
 const {root, secrets, closedHost} = canaryTree(), r = rig(root, {dom: {...dom, closedShadow: e => (e as FElement).closed}});
 r.recorder.setConsent(true);
 const nodes = allNodes(r.chunks), wire = JSON.stringify(r.chunks);
 for (const secret of secrets) expect(wire).not.toContain(secret);
 expect(reads).toEqual({value: 0, data: 0, attributes: 0, text: 0, html: 0, layout: 0, traps: 0});
 for (const n of nodes) { expect(Object.keys(n).sort()).toEqual(NODE_KEYS); expect(["", "[masked]"]).toContain(n.text); expect(["", "masked"]).toContain(n.class); expect(TAGS).toContain(n.tag); }
 const texts = nodes.filter(n => n.text === "[masked]");
 expect(texts.length).toBeGreaterThan(13);
 expect(new Set(texts.filter(n => n.tag === "masked").map(n => JSON.stringify({...n, id: "", parent: ""}))).size).toBe(1);
 const inputsOut = nodes.filter(n => n.tag === "input");
 expect(inputsOut).toHaveLength(13);
 expect(new Set(inputsOut.map(n => JSON.stringify({...n, id: "", parent: ""}))).size).toBe(1);
 const opaque = nodes.filter(n => n.class === "masked");
 // editable, textarea, iframe, video, closed shadow host, plus nothing else
 expect(opaque).toHaveLength(5);
 for (const o of opaque) expect(nodes.some(n => n.parent === o.id)).toBe(false);
 // open shadow content and its light DOM are walked under the same masking rules
 const hostId = String(nodes.find(n => n.tag === "div" && nodes.some(c => c.parent === n.id && c.tag === "p" && nodes.some(t => t.parent === c.id && t.text === "[masked]")))?.id);
 expect(hostId).not.toBe("undefined");
 expect(r.observer().targets.length).toBe(2); // root + open shadow root only
 void closedHost;
 // skipped elements never appear and tags outside the server's closed vocabulary are the generic "masked" structural tag
 expect(nodes.filter(n => ["html", "body", "head", "title", "script", "style", "svg", "img"].includes(n.tag))).toHaveLength(0);
 expect(nodes.every(n => n.tag === "masked" || /^[a-z0-9]+$/.test(n.tag))).toBe(true);
 // registered listeners cannot observe keys, input, clipboard, console
 expect([...r.target.handlers.keys()].sort()).toEqual(["pointerdown", "resize", "scroll"]);
});

test("getter traps planted on source nodes never execute", () => {
 const child = el("span", text("trap-secret")), root = el("div", child);
 for (const node of [root, child]) for (const name of ["nodeType", "firstChild", "nextSibling", "parentNode", "localName", "shadowRoot", "isContentEditable", "textContent", "value", "attributes"]) Object.defineProperty(node, name, {get() { reads.traps++; throw Error("trap"); }, configurable: true});
 Object.defineProperty(child, "getBoundingClientRect", {value() { reads.traps++; throw Error("trap"); }});
 reads.traps = 0;
 const r = rig(root); r.recorder.setConsent(true);
 expect(reads.traps).toBe(0);
 expect(allNodes(r.chunks).map(n => n.tag)).toEqual(["div", "span", "masked"]);
});

test("pointer coordinates quantize to 8px and clamp to ±32768, and no geometry or style is ever read", () => {
 expect([quantize(13.4), quantize(3), quantize(4), quantize(-4), quantize(100000), quantize(-99999), quantize(Number.NaN), quantize(Infinity), quantize(32764), quantize(0.2)]).toEqual([16, 0, 8, 0, 32768, -32768, 0, 0, 32768, 0]);
 const root = el("div");
 const r = rig(root); r.recorder.setConsent(true);
 expect(reads.layout).toBe(0);
 const button = el("button"); root.append(button);
 r.target.handlers.get("pointerdown")!(new FEvent(root, 203, 999999));
 r.target.handlers.get("scroll")!(new FEvent(null, 0, 0));
 r.target.handlers.get("resize")!(new FEvent(null, 0, 0));
 r.timers.advance(1000);
 const events = r.chunks.at(-1)!.events;
 expect(events.map(e => [e.kind, e.node, e.x, e.y])).toEqual([["pointer", r.chunks[0]!.nodes[0]!.id, 200, 32768], ["scroll", "0", 0, 80], ["resize", "0", 1000, 800]]);
});

test("20,000 node walk cap: overflow is still ONE bounded gap-marked checkpoint, never a fragmented format, and the chain stays hash-chained", () => {
 const root = el("div"); for (let i = 0; i < MAX_NODES + 5000; i++) root.append(el("span", text("overflow-secret")));
 const r = rig(root); r.recorder.setConsent(true);
 expect(r.chunks).toHaveLength(1);
 const first = r.chunks[0]!;
 expect(first.nodes.length).toBeLessThanOrEqual(4096);
 expect(JSON.stringify(first).length).toBeLessThanOrEqual(131072);
 expect(first.gap).toBe(true);
 expect(first.events.map(e => e.kind)).toEqual(["checkpoint", "gap"]);
 expect(Number(first.loss)).toBeGreaterThan(0);
 expect(JSON.stringify(r.chunks)).not.toContain("overflow-secret");
 expect(first.checkpoint_sequence).toBe("1");
 expect(first.checkpoint_hash).toBe(first.previous_hash);
 r.target.handlers.get("pointerdown")!(new FEvent(root, 8, 8));
 r.timers.advance(1000);
 let previous = "0".repeat(64);
 r.chunks.forEach((chunk, i) => {
  expect(chunk.sequence).toBe(String(i + 1));
  expect(chunk.previous_hash).toBe(previous);
  expect(chunk.checkpoint_sequence).toBe("1");
  previous = createHash("sha256").update(canonicalJSON(chunk)).digest("hex");
 });
 expect(r.chunks.length).toBe(2);
 expect(r.chunks[1]!.checkpoint_hash).toBe(createHash("sha256").update(canonicalJSON(first)).digest("hex"));
 expect(sha256Hex("abc")).toBe(createHash("sha256").update("abc").digest("hex"));
 expect(sha256Hex("a".repeat(1000))).toBe(createHash("sha256").update("a".repeat(1000)).digest("hex"));
});

function pageOfSections(count: number): {root: FHtml; sections: FHtml[]} {
 const sections = Array.from({length: count}, (_, i) => el("section", el("p", text("section-secret-" + i), el("span", text("x")))));
 return {root: el("div", ...sections), sections};
}

test("oversized checkpoint: whole low-priority tail subtrees become opaque placeholders in ONE chunk, truncation is reported, nothing is silently cut", () => {
 const {root, sections} = pageOfSections(600);
 const r = rig(root); r.recorder.setConsent(true);
 expect(r.chunks).toHaveLength(1);
 const chunk = r.chunks[0]!;
 expect(chunk.nodes.length).toBeLessThanOrEqual(4096);
 expect(JSON.stringify(chunk).length).toBeLessThanOrEqual(131072);
 expect(chunk.gap).toBe(true);
 expect(chunk.events.map(e => e.kind)).toEqual(["checkpoint", "gap"]);
 expect(chunk.loss).toBe("1");
 const ids = new Set(chunk.nodes.map(n => n.id));
 for (const n of chunk.nodes) expect(n.parent === "0" || ids.has(n.parent)).toBe(true);
 const rootId = chunk.nodes[0]!.id, top = chunk.nodes.filter(n => n.parent === rootId);
 expect(top).toHaveLength(sections.length);
 const placeholders = top.map((n, i) => [n, i] as const).filter(([n]) => n.class === "masked");
 expect(placeholders.length).toBeGreaterThan(0);
 for (const [placeholder] of placeholders) { expect(placeholder).toMatchObject({tag: "masked", class: "masked", text: ""}); expect(chunk.nodes.some(n => n.parent === placeholder.id)).toBe(false); }
 // Lowest priority is the tail: the head of the page is intact, the end of the page is collapsed, and the split is contiguous.
 const firstPlaceholder = placeholders[0]![1];
 expect(firstPlaceholder).toBeGreaterThan(50);
 expect(top.slice(0, firstPlaceholder).every(n => n.class === "" && n.tag === "section")).toBe(true);
 expect(top.slice(firstPlaceholder).every(n => n.class === "masked")).toBe(true);
 expect(chunk.nodes.some(n => n.parent === top[0]!.id && n.tag === "p")).toBe(true);
 expect(JSON.stringify(chunk)).not.toContain("section-secret");
});

test("deltas under a placeholdered subtree are suppressed until a new complete checkpoint includes it", () => {
 const {root, sections} = pageOfSections(600);
 const r = rig(root); r.recorder.setConsent(true);
 const observer = r.observer(), base = r.chunks.length;
 const chunk = r.chunks[0]!, rootId = chunk.nodes[0]!.id, top = chunk.nodes.filter(n => n.parent === rootId);
 expect(top[599]!.class).toBe("masked");
 // Inside the collapsed tail: content changed, and a brand new node added. Neither may produce a delta (it would re-expose the subtree).
 const hidden = sections[599]!;
 hidden.children[0]!.append(text("late-secret"));
 observer.callback([new FRecord(hidden.children[0]!)]);
 const added = el("p", text("brand-new-secret")); hidden.append(added);
 observer.callback([new FRecord(added)]);
 expect(r.chunks).toHaveLength(base);
 // The retained head still produces ordinary deltas.
 sections[0]!.children[0]!.append(text("head-secret"));
 observer.callback([new FRecord(sections[0]!.children[0]!)]);
 expect(r.chunks).toHaveLength(base + 1);
 expect(r.chunks.at(-1)!.events.map(e => e.kind)).toEqual(["mutation"]);
 expect(r.chunks.at(-1)!.gap).toBe(false);
 // The page shrinks so the whole snapshot fits; the next periodic checkpoint is complete and includes the formerly collapsed section.
 root.children = [...sections.slice(0, 100), hidden];
 r.timers.advance(30000);
 const resnap = r.chunks.at(-1)!;
 expect(resnap.checkpoint_sequence).toBe(resnap.sequence);
 expect(resnap.nodes.some(n => n.class === "masked")).toBe(false);
 expect(resnap.nodes.length).toBe(1 + 100 * 5 + 1 + 8); // root, 100 head sections (one gained a text node), the hidden section with its 3 added nodes
 const after = r.chunks.length;
 observer.callback([new FRecord(hidden.children[0]!)]);
 expect(r.chunks).toHaveLength(after + 1);
 expect(r.chunks.at(-1)!.events.map(e => e.kind)).toEqual(["mutation"]);
 for (const secret of ["late-secret", "brand-new-secret", "head-secret", "section-secret"]) expect(JSON.stringify(r.chunks)).not.toContain(secret);
});

test("fitSubtrees collapses the lowest-priority (latest, deepest) whole subtrees first and keeps the head of the page", () => {
 const node = (id: string, parent: string): ReplayNode => ({id, parent, tag: "div", class: "", text: ""});
 const nodes = [node("1", "0"), node("2", "1"), node("3", "2"), node("4", "1"), node("5", "4"), node("6", "4"), node("7", "1"), node("8", "7")];
 const unchanged = fitSubtrees(nodes, 8, 1_000_000);
 expect(unchanged.truncated).toBe(false);
 expect(unchanged.nodes).toBe(nodes);
 const fitted = fitSubtrees(nodes, 6, 1_000_000);
 expect(fitted.truncated).toBe(true);
 expect(fitted.nodes.map(n => [n.id, n.parent, n.tag, n.class])).toEqual([["1", "0", "div", ""], ["2", "1", "div", ""], ["3", "2", "div", ""], ["4", "1", "masked", "masked"], ["7", "1", "masked", "masked"]]);
 expect([...fitted.suppressed].sort()).toEqual([4, 5, 6, 7, 8]);
 const byBytes = fitSubtrees(nodes, 100, JSON.stringify(node("1", "0")).length * 6);
 expect(byBytes.nodes.length).toBeLessThan(8);
 expect(JSON.stringify(byBytes.nodes[0]!.id)).toBe("\"1\"");
 // A single root that still cannot fit collapses to itself; the result is never larger than asked for when a root placeholder fits.
 expect(fitSubtrees(nodes, 1, 1_000_000).nodes).toHaveLength(1);
});

test("mutation bursts extract masked structure synchronously, never raw text or removed nodes", () => {
 const secret = text("mutated-secret-value-0123456789"), p = el("p", secret), root = el("div", p);
 const r = rig(root); r.recorder.setConsent(true);
 const base = r.chunks.length, observer = r.observer();
 expect(observer.targets).toEqual([root]);
 // text change inside p: replacement subtree of p keeps p's id; new text node gets a masked node
 const pId = r.chunks[0]!.nodes.find(n => n.tag === "p")!.id;
 p.children = []; p.append(text("another-secret-longer-than-before"));
 observer.callback([new FRecord(secret)]);
 const mutation = r.chunks.at(-1)!;
 expect(r.chunks.length).toBe(base + 1);
 expect(mutation.events.map(e => [e.kind, e.node])).toEqual([["mutation", pId]]);
 expect(mutation.nodes.map(n => [n.id === pId, n.tag, n.text])).toEqual([[true, "p", ""], [false, "masked", "[masked]"]]);
 expect(mutation.nodes[0]!.parent).toBe(r.chunks[0]!.nodes[0]!.id);
 expect(mutation.checkpoint_sequence).toBe("1");
 // burst > 512 records => full resnapshot marked as a gap, still masked
 observer.callback(Array.from({length: 600}, () => new FRecord(p)));
 const resnap = r.chunks.at(-1)!;
 expect(resnap.checkpoint_sequence).toBe(resnap.sequence);
 expect(resnap.gap).toBe(true);
 // unknown target (detached node) forces a resnapshot instead of guessing
 observer.callback([new FRecord(el("div"))]);
 expect(r.chunks.at(-1)!.checkpoint_sequence).toBe(r.chunks.at(-1)!.sequence);
 for (const secretText of ["mutated-secret-value-0123456789", "another-secret-longer-than-before"]) expect(JSON.stringify(r.chunks)).not.toContain(secretText);
});

test("mutation inside an opaque widget yields only the opaque node, no content", () => {
 const inner = text("typed-secret-in-editable"), editable = el("div", inner); editable.editableFlag = true;
 const root = el("div", editable), r = rig(root); r.recorder.setConsent(true);
 const edId = r.chunks[0]!.nodes.find(n => n.class === "masked")!.id;
 r.observer().callback([new FRecord(inner)]);
 const m = r.chunks.at(-1)!;
 expect(m.events.map(e => e.node)).toEqual([edId]);
 expect(m.nodes).toHaveLength(1);
 expect(m.nodes[0]).toMatchObject({id: edId, class: "masked", text: ""});
 expect(JSON.stringify(r.chunks)).not.toContain("typed-secret");
});

test("setConsent(false) disconnects at once, destroys pending replay state, keeps ACKed chunks, resumes only with a gap checkpoint", () => {
 const root = el("div", el("p", text("x"))), r = rig(root); r.recorder.setConsent(true);
 const observer = r.observer(), acked = r.chunks.length;
 r.target.handlers.get("pointerdown")!(new FEvent(root, 8, 8));
 expect(r.timers.queue.length).toBeGreaterThan(0);
 const staleRecord = [new FRecord(root)], stalePointer = r.target.handlers.get("pointerdown")!;
 r.recorder.setConsent(false);
 expect(observer.disconnected).toBe(true);
 expect(r.target.handlers.size).toBe(0);
 expect(r.timers.queue).toHaveLength(0);
 expect(r.revoked).toBe(1);
 r.timers.advance(120000);
 observer.callback(staleRecord); stalePointer(new FEvent(root, 8, 8));
 expect(r.chunks).toHaveLength(acked); // nothing sent after revoke, pending pointer event destroyed
 r.recorder.setConsent(true);
 const resumed = r.chunks.at(-1)!;
 expect(resumed.gap).toBe(true);
 expect(resumed.checkpoint_sequence).toBe(resumed.sequence);
 expect(resumed.sequence).toBe(String(acked + 1));
 expect(FObserver.instances).toHaveLength(2);
 r.target.handlers.get("pointerdown")!(new FEvent(root, 64, 64));
 r.timers.advance(1000);
 expect(r.chunks.slice(acked).flatMap(c => c.events).filter(e => e.kind === "pointer").map(e => [e.x, e.y])).toEqual([[64, 64]]); // pre-revoke pointer (8,8) destroyed, not replayed
 r.recorder.close();
 r.recorder.setConsent(true);
 expect(FObserver.instances).toHaveLength(2);
});

test("a rejected chunk is counted, flagged, and followed by a gap-marked checkpoint", () => {
 const r = rig(el("div", el("p"))); r.result.value = "rejected"; r.recorder.setConsent(true);
 expect(r.chunks).toHaveLength(0);
 r.result.value = "accepted"; r.timers.advance(1000);
 const chunk = r.chunks.at(-1)!;
 expect(chunk.gap).toBe(true); expect(Number(chunk.loss)).toBeGreaterThan(0); expect(chunk.checkpoint_sequence).toBe(chunk.sequence);
});

test("30-second checkpoint timer", () => {
 const r = rig(el("div")); r.recorder.setConsent(true);
 r.timers.advance(30000);
 const checkpoints = r.chunks.filter(c => c.checkpoint_sequence === c.sequence);
 expect(checkpoints).toHaveLength(2);
 expect(checkpoints[1]!.gap).toBe(false);
});

test("ReplayStream is a bounded single-consumer AsyncIterable that rejects instead of dropping and clears on revoke", async () => {
 const stream = new ReplayStream(2), root = el("div", el("p")), r = rig(root, {onRevoked: () => stream.clear()});
 const chunk = (n: number) => ({...({} as ReplayChunk), sequence: String(n)});
 expect(stream.push(chunk(1))).toBe("accepted"); expect(stream.push(chunk(2))).toBe("accepted"); expect(stream.push(chunk(3))).toBe("rejected");
 const iterator = stream[Symbol.asyncIterator]();
 expect((await iterator.next()).value.sequence).toBe("1");
 stream.clear(); expect(stream.pending).toBe(0);
 const waiting = iterator.next(); stream.push(chunk(9)); expect((await waiting).value.sequence).toBe("9");
 stream.close(); expect((await iterator.next()).done).toBe(true); expect(stream.push(chunk(10))).toBe("rejected");
 const live = new ReplayStream(); const rr = rig(root, {onRevoked: () => live.clear()}, {}); void r; void rr;
 const wired = createRecorder({...rr.config, onRevoked: () => live.clear()}, live.push); wired.setConsent(true);
 expect(live.pending).toBeGreaterThan(0); wired.setConsent(false); expect(live.pending).toBe(0);
});

test("client.setReplayConsent delegates under policy, and revocation leaves non-replay queue entries intact", async () => {
 const allowed = init({...coreConfig(), deploymentReplay: true}), denied = init(coreConfig());
 try {
  for (const [client, expectCapture] of [[allowed, true], [denied, false]] as const) {
   const r = {chunks: [] as ReplayChunk[]}; FObserver.instances = [];
   const {root} = canaryTree();
   const recorder = client.startReplay({root, replayId: "a".repeat(32), sessionId: "b".repeat(32), capturePolicyRevision: "1", domain: {host: "c".repeat(32), boot: "d".repeat(32), runtime: "e".repeat(32)}, clock: () => ({wall_ns: "1", mono_ns: "1", uncertainty_ns: "0"}), dom, observer: FObserver, eventTarget: new FTarget()}, chunk => { r.chunks.push(chunk); });
   expect(recorder).toBeDefined();
   client.captureException(Error("CANARY_BEFORE"));
   const before = client.bufferedRecords().length;
   client.setReplayConsent(true);
   expect(r.chunks.length > 0).toBe(expectCapture);
   client.setReplayConsent(false);
   client.captureException(Error("CANARY_AFTER"));
   expect(client.bufferedRecords().length).toBe(before + 1);
   expect(client.bufferedRecords().join("")).not.toContain("CANARY");
   if (expectCapture) { expect(FObserver.instances[0]!.disconnected).toBe(true); expect(() => client.startReplay({} as never, () => "accepted")).toThrow(); }
  }
 } finally { await allowed.close(); await denied.close(); }
});
