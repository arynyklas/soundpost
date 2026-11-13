// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {describe, expect, test} from "bun:test";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {REPLAY_PROTOCOL_LIMITS, ReplayDecodeError, breakChain, canonicalJSON, decodeChunk, initialChainState, sha256Hex, verifyChain, type ChainDecision, type ReplayChainState, type ReplayChunk} from "../src/decode.ts";
import {renderReplay, renderTree, type ReplayItem, type ReplayStatus} from "../src/render.ts";
import {createRecorder} from "../../browser/src/replay/recorder.ts";
import {canonicalJSON as recorderCanonicalJSON} from "../../browser/src/replay/policy.ts";
import type {DomAccessors, ReplayChunk as RecorderChunk, ReplayConfig} from "../../browser/src/replay/types.ts";

// ---- Shared cross-language vectors: every hash and verdict was produced by the real Go validator. ----
interface VectorChunk {wire?: string; synth?: {base: string; nodes: number; shape: "masked" | "plain"}; go: {verdict: "valid" | "invalid" | "unsupported" | "too_large"; hash: string | null; canonical_bytes: number | null}}
interface Scenario {name: string; steps: {chunk: string; expect: string; reason?: string}[]; final_applied: string[]; final_continuous: boolean}
const vectors = JSON.parse(readFileSync(new URL("../../../fixtures/sdk/replay/chain-vectors.json", import.meta.url), "utf8")) as {max_chunk_bytes: number; chunks: Record<string, VectorChunk>; scenarios: Scenario[]};
const encoder = new TextEncoder();
/** Expands a synthetic oversized vector exactly as vectors_test.go describes it. */
function wireOf(name: string): string {
 const entry = vectors.chunks[name];
 if (entry === undefined) throw Error("missing vector " + name);
 if (entry.wire !== undefined) return entry.wire;
 const synth = entry.synth!;
 const base = JSON.parse(vectors.chunks[synth.base]!.wire!) as Record<string, unknown>;
 const nodes: unknown[] = [];
 for (let i = 1; i <= synth.nodes; i++) {
  nodes.push(synth.shape === "masked"
   ? (i === 1 ? {class: "", id: "1", parent: "0", tag: "div", text: ""} : {class: "masked", id: String(i), parent: "1", tag: "masked", text: "[masked]"})
   : {class: "", id: String(i), parent: "0", tag: "div", text: ""});
 }
 return JSON.stringify({...base, nodes});
}
const bytesOf = (name: string): Uint8Array => encoder.encode(wireOf(name));
const decode = (name: string): ReplayChunk => decodeChunk(bytesOf(name), REPLAY_PROTOCOL_LIMITS);
function code(run: () => unknown): string {
 try { run(); } catch (error) { if (error instanceof ReplayDecodeError) return error.code; throw error; }
 return "none";
}

describe("cross-language closed format (vectors produced by the real Go validator)", () => {
 test("every vector chunk gets the verdict Go gave it and every valid chunk the exact Go hash", () => {
  const names = Object.keys(vectors.chunks);
  expect(names.length).toBeGreaterThan(30);
  for (const name of names) {
   const entry = vectors.chunks[name]!;
   const result = code(() => { const chunk = decode(name); expect(chunk.hash).toBe(entry.go.hash!); });
   switch (entry.go.verdict) {
    case "valid": expect([name, result]).toEqual([name, "none"]); break;
    case "unsupported": expect([name, result]).toEqual([name, "unsupported_version"]); break;
    case "too_large": expect([name, result]).toEqual([name, "too_large"]); break;
    case "invalid": expect([name, ["invalid", "malformed"].includes(result)]).toEqual([name, true]); break;
   }
  }
 });
 test("canonical JSON of a Go chunk is byte-identical to Go's canonical form, in viewer and recorder", () => {
  for (const name of ["c1", "d2", "d3", "d4", "c5", "c8", "g6", "d4_null_nodes"]) {
   const wire = wireOf(name);
   expect(canonicalJSON(JSON.parse(wire))).toBe(wire);
   expect(recorderCanonicalJSON(JSON.parse(wire))).toBe(wire);
   expect(decode(name).hash).toBe(createHash("sha256").update(wire).digest("hex"));
   expect(vectors.chunks[name]!.go.canonical_bytes).toBe(encoder.encode(wire).length);
  }
 });
 test("wire key order and whitespace do not change the hash", () => {
  expect(decode("c1_pretty_reordered").hash).toBe(decode("c1").hash);
 });
 test("counters above 2^53 and negative-zero coordinates hash as Go hashes them", () => {
  const big = decode("c1_big_counters");
  expect(big.loss).toBe("18446744073709551615");
  expect(big.clock.mono_ns).toBe("9007199254740993");
  expect(big.hash).toBe(vectors.chunks["c1_big_counters"]!.go.hash!);
  expect(decode("c1_negative_zero_coordinate").hash).toBe(vectors.chunks["c1_negative_zero_coordinate"]!.go.hash!);
 });
 test("sha256 agrees with node:crypto across padding boundaries", () => {
  for (const length of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 1000]) {
   const data = new Uint8Array(length).map((_, index) => (index * 31 + 7) & 255);
   expect(sha256Hex(data)).toBe(createHash("sha256").update(data).digest("hex"));
  }
 });
 test("limits can only narrow the protocol, never widen it", () => {
  const c1 = bytesOf("c1");
  expect(code(() => decodeChunk(c1, {...REPLAY_PROTOCOL_LIMITS, maxChunkBytes: 100}))).toBe("too_large");
  expect(code(() => decodeChunk(c1, {...REPLAY_PROTOCOL_LIMITS, maxNodes: 2}))).toBe("too_large");
  expect(code(() => decodeChunk(c1, {...REPLAY_PROTOCOL_LIMITS, maxEvents: 0}))).toBe("too_large");
  expect(code(() => decodeChunk(c1, {...REPLAY_PROTOCOL_LIMITS, maxChunkBytes: 131073}))).toBe("limits");
  expect(code(() => decodeChunk(c1, {...REPLAY_PROTOCOL_LIMITS, maxNodes: 4097}))).toBe("limits");
  expect(code(() => decodeChunk(c1, {...REPLAY_PROTOCOL_LIMITS, maxChunkBytes: 1.5}))).toBe("limits");
 });
 test("decode failures never echo chunk content", () => {
  for (const name of ["c1_text_secret", "c1_class_secret", "c1_unknown_field_html", "c1_node_rect", "c1_tag_img"]) {
   try { decode(name); throw Error("accepted " + name); } catch (error) {
    expect(error).toBeInstanceOf(ReplayDecodeError);
    expect(String((error as Error).message)).not.toMatch(/hunter2|btn-primary|<b>|rect|img/);
   }
  }
 });
 test("non-JSON and non-object input is malformed, never a thrown crash", () => {
  for (const text of ["", "null", "[]", "42", "\"x\"", "{", "{\"a\":1,}", "\u0000"]) expect(code(() => decodeChunk(encoder.encode(text), REPLAY_PROTOCOL_LIMITS))).toBe("malformed");
  expect(code(() => decodeChunk(Uint8Array.of(0xff, 0xfe, 0x7b, 0x7d), REPLAY_PROTOCOL_LIMITS))).toBe("malformed");
  // Lone surrogate escapes and over-deep nesting are refused as Go's ValidateJSON refuses them.
  for (const lone of ["\\ud800", "\\udc00", "\\ud800\\u0041"]) expect(code(() => decodeChunk(encoder.encode(wireOf("c1").replace("\"tag\":\"div\"", `"tag":"${lone}"`)), REPLAY_PROTOCOL_LIMITS))).toBe("malformed");
  expect(code(() => decodeChunk(encoder.encode("[".repeat(200) + "]".repeat(200)), REPLAY_PROTOCOL_LIMITS))).toBe("malformed");
 });
 // Deliberate, documented strictness beyond Go (Go's decoder is case-insensitive and zero-fills missing fields); canonical server output is never affected.
 test("keys are case-exact and every field must be present", () => {
  const refused = (wire: string): string => code(() => decodeChunk(encoder.encode(wire), REPLAY_PROTOCOL_LIMITS));
  const c1 = wireOf("c1");
  expect(refused(c1.replace("\"gap\"", "\"Gap\""))).toBe("invalid");
  expect(refused(c1.replace("\"loss\":\"0\",", ""))).toBe("invalid");
  expect(refused(c1.replace(",\"text\":\"\"}", "}"))).toBe("invalid");
  expect(refused(c1.replace(/"nodes":\[.*?\],"previous_hash"/, "\"nodes\":\"x\",\"previous_hash\""))).toBe("invalid");
  expect(refused(c1.replace("\"recorder_version\":\"1\"", "\"recorder_version\":1"))).toBe("invalid");
 });
 test("keys that collide with Object.prototype cannot reach or pollute the decoded chunk", () => {
  const poisoned = wireOf("c1").replace("{\"capture_policy_revision\"", "{\"__proto__\":{\"polluted\":true},\"capture_policy_revision\"");
  expect(code(() => decodeChunk(encoder.encode(poisoned), REPLAY_PROTOCOL_LIMITS))).toBe("invalid");
  expect(Reflect.get(Object.prototype, "polluted")).toBeUndefined();
 });
 test("the 128 KiB cap is exact: 131072 bytes decode, 131073 do not", () => {
  const c1 = wireOf("c1");
  const padded = (size: number): Uint8Array => encoder.encode(c1 + " ".repeat(size - encoder.encode(c1).length));
  expect(padded(131072).length).toBe(131072);
  expect(decodeChunk(padded(131072), REPLAY_PROTOCOL_LIMITS).hash).toBe(decode("c1").hash);
  expect(code(() => decodeChunk(padded(131073), REPLAY_PROTOCOL_LIMITS))).toBe("too_large");
 });
});

// ---- Chain decisions. ----
function run(steps: {chunk: string}[], state: ReplayChainState = initialChainState()): {decisions: ChainDecision[]; state: ReplayChainState} {
 const decisions: ChainDecision[] = [];
 for (const step of steps) {
  const decision = verifyChain(decode(step.chunk), state);
  decisions.push(decision); state = decision.state;
 }
 return {decisions, state};
}
const reasonOf = (decision: ChainDecision): string | undefined => {
 switch (decision.kind) {
  case "apply": return undefined;
  case "checkpoint": return decision.gap?.reason;
  case "gap": return decision.gap.reason;
  case "reject": return decision.reason;
 }
};

describe("chain verification", () => {
 for (const scenario of vectors.scenarios) {
  test(scenario.name, () => {
   const {decisions, state} = run(scenario.steps);
   expect(decisions.map((decision, index) => [scenario.steps[index]!.chunk, decision.kind, reasonOf(decision)])).toEqual(scenario.steps.map(step => [step.chunk, step.expect, step.reason]));
   // Applied sequences are exactly the ones whose content may be shown; a broken chain is never reported continuous.
   const applied = scenario.steps.flatMap((step, index) => (["apply", "checkpoint"].includes(decisions[index]!.kind) ? [decode(step.chunk).sequence] : []));
   expect(applied).toEqual(scenario.final_applied);
   expect(state.broken === null).toBe(scenario.final_continuous);
  });
 }
 test("a chunk whose previous hash is altered is not applied and a later honest delta still cannot apply", () => {
  const {decisions} = run([{chunk: "c1"}, {chunk: "d2"}, {chunk: "d3_altered_previous"}, {chunk: "d4"}]);
  expect(decisions.map(decision => decision.kind)).toEqual(["checkpoint", "apply", "reject", "gap"]);
 });
 test("verifyChain never mutates the state it is given", () => {
  const first = verifyChain(decode("c1"), initialChainState());
  const frozen = JSON.stringify(first.state);
  verifyChain(decode("d2"), first.state);
  verifyChain(decode("d4"), first.state);
  verifyChain(decode("d3_altered_previous"), first.state);
  expect(JSON.stringify(first.state)).toBe(frozen);
 });
 test("a duplicate leaves the state untouched so it can never double-apply", () => {
  const before = run([{chunk: "c1"}, {chunk: "d2"}]).state;
  const duplicate = verifyChain(decode("d2"), before);
  expect(duplicate.kind).toBe("reject");
  expect(duplicate.state).toEqual(before);
 });
 test("the gap a decision reports spans the sequences that were not applied", () => {
  const {decisions} = run([{chunk: "c1"}, {chunk: "d2"}, {chunk: "c8"}]);
  const resume = decisions[2]!;
  expect(resume.kind).toBe("checkpoint");
  if (resume.kind === "checkpoint") expect(resume.gap).toEqual({reason: "missing_chunk", from: "3", through: "7"});
 });
 test("host-declared breaks (undecodable chunk, unsupported version) stop deltas until the next checkpoint", () => {
  const afterBreak = breakChain(run([{chunk: "c1"}, {chunk: "d2"}]).state, "invalid_chunk");
  expect(verifyChain(decode("d3"), afterBreak).kind).toBe("gap");
  expect(verifyChain(decode("c5"), afterBreak).kind).toBe("checkpoint");
  expect(breakChain(afterBreak, "recorder_version").broken).toBe("invalid_chunk");
 });
});

// ---- Real recorder output against the same hash and format. ----
interface Fake {t: number; name: string; kids: Fake[]; parent: Fake | null}
function fake(name: string, ...kids: Fake[]): Fake { const node: Fake = {t: 1, name, kids, parent: null}; for (const kid of kids) kid.parent = node; return node; }
function recordReal(): RecorderChunk[] {
 const html = fake("div", fake("p"), fake("section", fake("button")));
 const root = {t: 9, name: "#document", kids: [html], parent: null as Fake | null} as Fake;
 html.parent = root;
 const dom: DomAccessors = {
  nodeType: node => (node as Fake).t, firstChild: node => (node as Fake).kids[0] ?? null,
  nextSibling: node => { const parent = (node as Fake).parent; return parent === null ? null : parent.kids[parent.kids.indexOf(node as Fake) + 1] ?? null; },
  parentNode: node => (node as Fake).parent, localName: node => (node as Fake).name, openShadowRoot: () => null, editable: () => false,
  mutationTarget: record => (record as {target: object}).target, eventTarget: event => (event as {target: object}).target,
  clientX: event => (event as {x: number}).x, clientY: event => (event as {y: number}).y,
 };
 let observe: ((records: readonly object[]) => void) | undefined;
 class Observer { constructor(callback: (records: readonly object[]) => void) { observe = callback; } observe(): void {} disconnect(): void {} }
 const listeners = new Map<string, (event: object) => void>();
 const timers: (() => void)[] = [];
 let tick = 0;
 const config: ReplayConfig = {
  projectPolicy: true, deploymentOptIn: true, root, replayId: "11".repeat(16), sessionId: "22".repeat(16), capturePolicyRevision: "7", domain: {host: "33".repeat(16), boot: "44".repeat(16), runtime: "55".repeat(16)},
  clock: () => ({wall_ns: "1700000000000000000", mono_ns: String(5_000_000_000 + ++tick * 1000), uncertainty_ns: "1000"}), dom, observer: Observer,
  eventTarget: {addEventListener: (type, listener) => { listeners.set(type, listener); }, removeEventListener: () => {}},
  timers: {set: callback => { timers.push(callback); return timers.length; }, clear: () => {}},
 };
 const chunks: RecorderChunk[] = [];
 const recorder = createRecorder(config, chunk => { chunks.push(JSON.parse(JSON.stringify(chunk))); return "accepted"; });
 recorder.setConsent(true);
 listeners.get("pointerdown")!({target: html, x: 123, y: 45});
 for (const callback of timers.splice(0)) callback();
 const section = html.kids[1]!;
 section.kids.push(fake("p")); section.kids[1]!.parent = section;
 observe!([{target: section}]);
 return chunks;
}

describe("real recorder output", () => {
 test("the recorder's own hash chain is the same SHA-256 over canonical JSON that Go computes", () => {
  const chunks = recordReal();
  expect(chunks.length).toBeGreaterThanOrEqual(3);
  expect(chunks[0]!.previous_hash).toBe("0".repeat(64));
  for (let index = 1; index < chunks.length; index++) {
   const previous = chunks[index - 1]!;
   expect(chunks[index]!.previous_hash).toBe(sha256Hex(encoder.encode(canonicalJSON(previous))));
   expect(chunks[index]!.previous_hash).toBe(createHash("sha256").update(recorderCanonicalJSON(previous)).digest("hex"));
  }
  expect(chunks[0]!.checkpoint_hash).toBe(chunks[0]!.previous_hash);
  expect(chunks[1]!.checkpoint_hash).toBe(sha256Hex(encoder.encode(canonicalJSON(chunks[0]))));
 });
 test("key order of the emitted object does not matter: shuffled keys give the same chain hash", () => {
  const chunk = recordReal()[0]!;
  const shuffled = Object.fromEntries(Object.entries(chunk).reverse());
  expect(canonicalJSON(shuffled)).toBe(canonicalJSON(chunk));
  expect(Object.keys(shuffled).join()).not.toBe(Object.keys(chunk).join());
 });
 // The recorder emits exactly the server's closed schema (D2), so the viewer's strict decode accepts its own chunks unchanged,
 // and the golden chunks of fixtures/replays/recorder (the ones Go's validator and chain reader consume) chain end to end.
 test("the recorder's own chunks decode strictly and the golden recorder fixtures verify as one continuous chain", () => {
  for (const chunk of recordReal()) expect(code(() => decodeChunk(encoder.encode(JSON.stringify(chunk)), REPLAY_PROTOCOL_LIMITS))).toBe("none");
  const root = new URL("../../../fixtures/replays/recorder/session/", import.meta.url);
  const manifest = JSON.parse(readFileSync(new URL("manifest.json", root), "utf8")) as {chunks: string[]};
  let state = initialChainState();
  const kinds = manifest.chunks.map(name => {
   const decision = verifyChain(decodeChunk(readFileSync(new URL(name, root)), REPLAY_PROTOCOL_LIMITS), state);
   state = decision.state;
   return decision.kind;
  });
  expect(kinds).toEqual(["checkpoint", "apply", "apply", "apply", "checkpoint", "apply"]);
 });
});

// ---- Renderer against a recording fake DOM: every operation is observed. ----
interface Op {kind: "create" | "attr" | "text" | "html" | "other"; a: string; b?: string}
class FakeEl {
 readonly children: FakeEl[] = []; readonly attrs = new Map<string, string>(); text = ""; parent: FakeEl | null = null;
 constructor(readonly name: string, readonly doc: FakeDoc) {}
 get ownerDocument() { return this.doc; }
 get childNodes() { return this.children; }
 setAttribute(name: string, value: string): void { this.doc.ops.push({kind: "attr", a: name, b: value}); this.attrs.set(name, String(value)); }
 getAttribute(name: string): string | null { return this.attrs.get(name) ?? null; }
 append(...items: FakeEl[]): void { for (const item of items) { item.parent?.children.splice(item.parent.children.indexOf(item), 1); item.parent = this; this.children.push(item); } }
 appendChild(item: FakeEl): FakeEl { this.append(item); return item; }
 replaceChildren(...items: FakeEl[]): void { for (const child of this.children) child.parent = null; this.children.length = 0; this.append(...items); }
 remove(): void { this.parent?.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; }
 set textContent(value: string) { this.doc.ops.push({kind: "text", a: this.name, b: String(value)}); this.text = String(value); for (const child of this.children) child.parent = null; this.children.length = 0; }
 get textContent(): string { return this.text + this.children.map(child => child.textContent).join(""); }
 set innerHTML(value: string) { this.doc.ops.push({kind: "html", a: "innerHTML", b: String(value)}); }
 set outerHTML(value: string) { this.doc.ops.push({kind: "html", a: "outerHTML", b: String(value)}); }
 insertAdjacentHTML(): void { this.doc.ops.push({kind: "html", a: "insertAdjacentHTML"}); }
 setAttributeNS(): void { this.doc.ops.push({kind: "other", a: "setAttributeNS"}); }
 get style(): never { this.doc.ops.push({kind: "other", a: "style"}); throw Error("style access"); }
 addEventListener(): void { this.doc.ops.push({kind: "other", a: "addEventListener"}); }
 find(predicate: (el: FakeEl) => boolean): FakeEl[] { return [...(predicate(this) ? [this] : []), ...this.children.flatMap(child => child.find(predicate))]; }
}
class FakeDoc {
 readonly ops: Op[] = [];
 createElement(name: string): FakeEl { this.ops.push({kind: "create", a: name}); return new FakeEl(name, this); }
 createElementNS(): never { this.ops.push({kind: "other", a: "createElementNS"}); throw Error("namespace element"); }
 createTextNode(): never { this.ops.push({kind: "other", a: "createTextNode"}); throw Error("text node"); }
}
const ELEMENT_NAMES = new Set(["div", "span", "p", "section", "ol", "li", "header"]);
const ATTRIBUTE_NAMES = new Set(["data-replay-root", "data-state", "data-replay-tree", "data-replay-timeline", "data-replay-interactions", "data-replay-status", "data-tag", "data-opaque", "data-kind", "data-masked", "role", "aria-live", "inert", "data-sequence"]);

function mount(): {container: FakeEl; doc: FakeDoc} {
 const doc = new FakeDoc();
 return {container: new FakeEl("div", doc), doc};
}
const chunkItems = (...names: string[]): ReplayItem[] => names.map(name => ({kind: "chunk", bytes: bytesOf(name)}));
async function* gen(items: ReplayItem[]): AsyncGenerator<ReplayItem> { for (const item of items) yield item; }
/** A stream whose reads and returns are observable. */
function spied(items: ReplayItem[], thenHang = false): {stream: AsyncIterable<ReplayItem>; reads: () => number; returned: () => boolean} {
 let index = 0, reads = 0, returned = false;
 const iterator: AsyncIterator<ReplayItem> = {
  next: () => { reads++; const item = items[index++]; return item !== undefined ? Promise.resolve({done: false, value: item}) : thenHang ? new Promise<IteratorResult<ReplayItem>>(() => {}) : Promise.resolve({done: true, value: undefined}); },
  return: () => { returned = true; return Promise.resolve({done: true, value: undefined}); },
 };
 return {stream: {[Symbol.asyncIterator]: () => iterator}, reads: () => reads, returned: () => returned};
}
const rootOf = (container: FakeEl): FakeEl => container.find(el => el.attrs.has("data-replay-root"))[0]!;
function view(container: FakeEl): {state: string | null; tree: string; timeline: string[]; interactions: string[]; gaps: string[]} {
 const root = rootOf(container);
 const summarize = (el: FakeEl): string => {
  const own = el.attrs.get("data-tag") ?? "?";
  const text = el.children.filter(child => child.attrs.has("data-masked")).map(child => child.text).join("");
  const kids = el.children.filter(child => child.attrs.has("data-tag")).map(summarize);
  return own + (text === "" ? "" : ":" + text) + (kids.length > 0 ? "[" + kids.join(",") + "]" : "");
 };
 const tree = root.find(el => el.attrs.has("data-replay-tree"))[0];
 const roots = tree === undefined ? [] : tree.children.filter(child => child.attrs.has("data-tag"));
 const items = (selector: string) => root.find(el => el.attrs.has(selector))[0]?.children.map(child => child.textContent) ?? [];
 const timeline = root.find(el => el.attrs.has("data-replay-timeline"))[0];
 return {
  state: root.attrs.get("data-state") ?? null, tree: roots.map(summarize).join("|"), timeline: items("data-replay-timeline"), interactions: items("data-replay-interactions"),
  gaps: timeline === undefined ? [] : timeline.children.filter(child => child.attrs.get("data-kind") === "gap").map(child => child.textContent),
 };
}
const statusLog = (handle: {status(): ReplayStatus}): ReplayStatus => handle.status();
/** Lets every already-resolved stream read and the renderer's coalesced flush run. */
const settle = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 5));

describe("renderer", () => {
 test("no delta is applied before its checkpoint: deltas alone show a gap and an empty tree", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("d2", "d3")));
  await handle.done;
  expect(statusLog(handle)).toBe("gap");
  const shown = view(container);
  expect(shown.tree).toBe("");
  expect(shown.interactions).toEqual([]);
  expect(shown.gaps.length).toBe(1);
 });
 test("reconstructs the masked tree and interaction order across checkpoint and deltas", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2", "d3", "d4")));
  await handle.done;
  expect(handle.status()).toBe("ready");
  const shown = view(container);
  expect(shown.state).toBe("ready");
  expect(shown.tree).toBe("div[p[span:[masked],button:[masked]]]");
  expect(shown.interactions).toEqual(["pointer 64,-8", "mutation 0,0", "scroll 0,480", "resize 1280,720"]);
  expect(shown.gaps).toEqual([]);
 });
 test("a missing chunk is an explicit gap and a valid next checkpoint resumes with the gap still visible", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2", "d4", "c5", "d6")));
  await handle.done;
  const shown = view(container);
  expect(handle.status()).toBe("ready");
  expect(shown.gaps.length).toBe(1);
  expect(shown.gaps[0]).toContain("3");
  expect(shown.gaps[0]).toContain("4");
  expect(shown.gaps[0]).toContain("missing_chunk");
  expect(shown.tree).toBe("section[canvas:[opaque]]");
  // d4's resize never applied; the pre-gap pointer and the post-resume pointer both show, in order.
  expect(shown.interactions).toEqual(["pointer 64,-8", "pointer 8,8"]);
 });
 test("while the gap is open the status is gap and nothing after it applies", async () => {
  const {container} = mount();
  const source = spied(chunkItems("c1", "d2", "d4", "d3_altered_previous"), true);
  const handle = renderReplay(container as unknown as HTMLElement, source.stream);
  await settle();
  expect(handle.status()).toBe("gap");
  expect(view(container).state).toBe("gap");
  expect(view(container).interactions).toEqual(["pointer 64,-8"]);
  handle.close();
 });
 test("duplicates do not double-apply", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2", "d2", "d2", "d3", "c1")));
  await handle.done;
  expect(view(container).interactions).toEqual(["pointer 64,-8", "mutation 0,0", "scroll 0,480"]);
  expect(view(container).timeline.filter(line => line.startsWith("checkpoint")).length).toBe(1);
 });
 test("an altered previous hash is not applied", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2", "d3_altered_previous")));
  await handle.done;
  expect(handle.status()).toBe("gap");
  expect(view(container).interactions).toEqual(["pointer 64,-8"]);
  expect(view(container).gaps).toEqual(["gap 3 hash_mismatch"]);
 });
 test("truncated, unknown-version and oversized chunks never apply; unsupported is reported and a checkpoint recovers", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2", "c1_truncated", "d3", "c1_oversized")));
  await handle.done;
  expect(handle.status()).toBe("gap");
  expect(view(container).interactions).toEqual(["pointer 64,-8"]);
  const second = mount();
  const unsupported = renderReplay(second.container as unknown as HTMLElement, gen(chunkItems("c1_version_2")));
  await unsupported.done;
  expect(unsupported.status()).toBe("unsupported");
  const third = mount();
  const recovered = renderReplay(third.container as unknown as HTMLElement, gen(chunkItems("c1_version_soundpost1", "c1", "d2")));
  await recovered.done;
  expect(recovered.status()).toBe("ready");
  expect(view(third.container).interactions).toEqual(["pointer 64,-8"]);
 });
 test("host-declared gaps and unsupported items surface and block deltas until a checkpoint", async () => {
  const {container} = mount();
  const items: ReplayItem[] = [...chunkItems("c1"), {kind: "gap", reason: "missing_chunk", from: "2", through: "3"}, ...chunkItems("d4")];
  const handle = renderReplay(container as unknown as HTMLElement, gen(items));
  await handle.done;
  expect(handle.status()).toBe("gap");
  expect(view(container).gaps.length).toBe(1);
  expect(view(container).interactions).toEqual([]);
 });
 test("seek renders the state at a sequence, rejects bad input, and landing inside a gap reports the gap", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2", "d3", "d4", "c8", "d9")));
  await handle.done;
  expect(handle.status()).toBe("ready");
  await handle.seek("2");
  expect(view(container).interactions).toEqual(["pointer 64,-8"]);
  expect(view(container).tree).toBe("div[p[span:[masked]]]");
  expect(handle.status()).toBe("ready");
  await handle.seek("5");
  expect(handle.status()).toBe("gap");
  expect(view(container).state).toBe("gap");
  await handle.seek("8");
  expect(handle.status()).toBe("ready");
  expect(view(container).tree).toBe("div[input:[masked]]");
  await handle.seek("9");
  expect(view(container).interactions).toEqual(["pointer 64,-8", "mutation 0,0", "scroll 0,480", "resize 1280,720", "pointer 24,24"]);
  for (const bad of ["", "01", "-1", "1.5", "1e2", " 1", "abc", "18446744073709551616", "0"]) await expect(handle.seek(bad)).rejects.toThrow();
  handle.close();
 });
 test("seek rounds a target past the tip down to the latest applied state", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1", "d2")));
  await handle.done;
  await handle.seek("500");
  expect(view(container).interactions).toEqual(["pointer 64,-8"]);
  expect(handle.status()).toBe("ready");
 });
 test("malicious tag, class, text, URL and script payloads are refused and produce only fixed first-party operations", async () => {
  const hostile = ["c1_tag_img", "c1_tag_html", "c1_text_secret", "c1_class_secret", "c1_unknown_field_html", "c1_node_rect", "c1_node_pres"];
  const {container, doc} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen([...chunkItems("c1"), ...chunkItems(...hostile), ...chunkItems("d2")]));
  await handle.done;
  const html = doc.ops.filter(op => op.kind === "html" || op.kind === "other");
  expect(html).toEqual([]);
  expect(doc.ops.filter(op => op.kind === "create").map(op => op.a).filter(name => !ELEMENT_NAMES.has(name))).toEqual([]);
  expect(doc.ops.filter(op => op.kind === "attr").every(op => ATTRIBUTE_NAMES.has(op.a))).toBe(true);
  const written = doc.ops.map(op => op.b ?? "").join("\n");
  for (const secret of ["hunter2", "btn-primary", "<b>", "img", "html"]) expect(written).not.toContain(secret);
  expect(handle.status()).toBe("gap");
 });
 test("even if decoding were bypassed, the tree builder maps stream strings only through constants", () => {
  const doc = new FakeDoc();
  const evil = [
   {id: "1", parent: "0", tag: "img src=x onerror=alert(1)", class: "\"><script>1</script>", text: "<img src=//evil.test/x>"},
   {id: "2", parent: "1", tag: "script", class: "masked", text: "javascript:fetch('//evil.test')"},
   {id: "3", parent: "1", tag: "a", class: "", text: "[masked]"},
   {id: "4", parent: "3", tag: "iframe", class: "", text: ""},
   {id: "5", parent: "4", tag: "input", class: "", text: "[masked]"},
   {id: "6", parent: "6", tag: "div", class: "", text: ""},
   {id: "7", parent: "8", tag: "div", class: "", text: ""},
   {id: "8", parent: "7", tag: "div", class: "", text: ""},
   {id: "9", parent: "2", tag: "div", class: "", text: "[masked]"}, // a child of an opaque node is never shown
  ];
  const root = renderTree(doc as unknown as Document, evil) as unknown as FakeEl;
  expect(root.attrs.has("data-replay-tree")).toBe(true);
  expect(doc.ops.filter(op => op.kind === "html" || op.kind === "other")).toEqual([]);
  for (const op of doc.ops.filter(op => op.kind === "create")) expect(ELEMENT_NAMES.has(op.a)).toBe(true);
  for (const op of doc.ops.filter(op => op.kind === "attr")) expect(ATTRIBUTE_NAMES.has(op.a)).toBe(true);
  const allowedText = new Set(["[masked]", "[opaque]"]);
  for (const op of doc.ops.filter(op => op.kind === "text")) expect(allowedText.has(op.b!)).toBe(true);
  for (const op of doc.ops.filter(op => op.kind === "attr" && op.a === "data-tag")) expect(["div", "span", "p", "button", "input", "section", "canvas", "masked"]).toContain(op.b!);
  const written = doc.ops.map(op => op.b ?? "").join("\n");
  for (const marker of ["onerror", "script", "evil.test", "javascript", "iframe", "src="]) expect(written).not.toContain(marker);
  // Cyclic and orphaned parents are unreachable from the root and never rendered or looped on.
  expect(root.find(el => el.attrs.has("data-tag")).length).toBe(5);
 });
 test("revocation stops reading, clears the DOM and every retained chunk, and later items are never applied", async () => {
  const {container} = mount();
  const source = spied([...chunkItems("c1", "d2"), {kind: "revoke", reason: "authority_revoked"}, ...chunkItems("d3")]);
  const handle = renderReplay(container as unknown as HTMLElement, source.stream);
  await handle.done;
  expect(handle.status()).toBe("error");
  expect(source.returned()).toBe(true);
  expect(source.reads()).toBe(3);
  expect(handle.retained()).toEqual({chunks: 0, nodes: 0});
  expect(container.children.map(child => child.textContent).join("")).not.toContain("masked");
  expect(container.find(el => el.attrs.has("data-tag")).length).toBe(0);
  await expect(handle.seek("1")).rejects.toThrow();
 });
 test("deletion and an erroring host stream end the same way", async () => {
  const deleted = mount();
  const first = renderReplay(deleted.container as unknown as HTMLElement, gen([...chunkItems("c1", "d2"), {kind: "revoke", reason: "deleted"}]));
  await first.done;
  expect(first.status()).toBe("error");
  expect(first.retained()).toEqual({chunks: 0, nodes: 0});
  expect(deleted.container.find(el => el.attrs.has("data-tag")).length).toBe(0);
  const thrown = mount();
  async function* failing(): AsyncGenerator<ReplayItem> { yield* chunkItems("c1", "d2"); throw Error("permission denied for scope"); }
  const second = renderReplay(thrown.container as unknown as HTMLElement, failing());
  await second.done;
  expect(second.status()).toBe("error");
  expect(second.retained()).toEqual({chunks: 0, nodes: 0});
  expect(thrown.container.find(el => el.attrs.has("data-tag")).length).toBe(0);
  const explicit = mount();
  const third = renderReplay(explicit.container as unknown as HTMLElement, gen([...chunkItems("c1"), {kind: "error"}]));
  await third.done;
  expect(third.status()).toBe("error");
 });
 test("close stops reading and leaves no content or retained cache", async () => {
  const {container} = mount();
  const source = spied(chunkItems("c1", "d2"), true);
  const handle = renderReplay(container as unknown as HTMLElement, source.stream);
  await settle();
  expect(handle.retained().chunks).toBe(2);
  handle.close();
  expect(source.returned()).toBe(true);
  expect(handle.retained()).toEqual({chunks: 0, nodes: 0});
  expect(container.children.length).toBe(0);
  handle.close();
  await expect(handle.seek("1")).rejects.toThrow();
 });
 test("a pinned seek position that retention later drops falls back to the live tip instead of showing nothing", async () => {
  const {container} = mount();
  const queue: ReplayItem[] = [];
  let waiting: ((result: IteratorResult<ReplayItem>) => void) | undefined;
  const push = (item: ReplayItem): void => { if (waiting !== undefined) { const resolve = waiting; waiting = undefined; resolve({done: false, value: item}); } else queue.push(item); };
  const stream: AsyncIterable<ReplayItem> = {[Symbol.asyncIterator]: () => ({
   next: () => { const item = queue.shift(); return item !== undefined ? Promise.resolve({done: false, value: item}) : new Promise<IteratorResult<ReplayItem>>(resolve => { waiting = resolve; }); },
   return: () => Promise.resolve({done: true, value: undefined}),
  })};
  const handle = renderReplay(container as unknown as HTMLElement, stream, {maxRetainedNodes: 4});
  for (const item of chunkItems("c1", "d2", "d3", "d4")) push(item);
  await settle();
  await handle.seek("2");
  expect(view(container).interactions).toEqual(["pointer 64,-8"]);
  for (const item of chunkItems("c5")) push(item); // a second checkpoint group makes the first one droppable
  await settle();
  expect(handle.retained().nodes).toBeLessThanOrEqual(4);
  expect(view(container).tree).toBe("section[canvas:[opaque]]");
  expect(handle.status()).toBe("ready");
  handle.close();
 });
 test("retained history is bounded: old dependency groups are dropped and seeking there is refused", async () => {
  const {container} = mount();
  const items: ReplayItem[] = chunkItems("c1", "d2", "d3", "d4", "c5", "d6");
  const handle = renderReplay(container as unknown as HTMLElement, gen(items), {maxRetainedNodes: 4});
  await handle.done;
  expect(handle.retained().nodes).toBeLessThanOrEqual(4);
  await expect(handle.seek("1")).rejects.toThrow();
  await handle.seek("5");
  expect(view(container).tree).toBe("section[canvas:[opaque]]");
 });
 test("a model that grows past the node cap stops with an error rather than rendering unbounded content", async () => {
  const {container} = mount();
  const handle = renderReplay(container as unknown as HTMLElement, gen(chunkItems("c1")), {maxModelNodes: 2});
  await handle.done;
  expect(handle.status()).toBe("error");
  expect(handle.retained()).toEqual({chunks: 0, nodes: 0});
 });
 test("an item of unknown kind, or not an object at all, ends the view like a revocation", async () => {
  for (const bad of [{kind: "bogus"}, null, "chunk", 7, {bytes: bytesOf("c1")}]) {
   const {container} = mount();
   const handle = renderReplay(container as unknown as HTMLElement, gen([...chunkItems("c1"), bad as unknown as ReplayItem, ...chunkItems("d2")]));
   await handle.done;
   expect(handle.status()).toBe("error");
   expect(handle.retained()).toEqual({chunks: 0, nodes: 0});
   expect(container.find(el => el.attrs.has("data-tag")).length).toBe(0);
  }
 });
 test("a chunk item whose bytes are not a Uint8Array, or a malformed host gap, ends the view", async () => {
  for (const bad of [{kind: "chunk", bytes: "<img src=x>"}, {kind: "chunk"}, {kind: "gap", reason: "nope", from: "1", through: "2"}, {kind: "gap", reason: "missing_chunk", from: "3", through: "2"}, {kind: "gap", reason: "missing_chunk", from: "0", through: "2"}, {kind: "gap", reason: "missing_chunk", from: "1", through: "18446744073709551616"}]) {
   const {container} = mount();
   const handle = renderReplay(container as unknown as HTMLElement, gen([...chunkItems("c1"), bad as unknown as ReplayItem]));
   await handle.done;
   expect(handle.status()).toBe("error");
  }
 });
});
