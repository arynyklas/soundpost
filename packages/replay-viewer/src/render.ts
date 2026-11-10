// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

/*
 * Inert replay renderer. It consumes only a scope-authorized stream of items, validates every chunk with
 * decodeChunk/verifyChain, and builds a fixed set of first-party elements: element names, attribute names and
 * every attribute value or text it writes come from constants in this file. A string from the stream is only ever
 * used as a lookup key into those constants (or as an exact-match test), never concatenated into markup, an
 * attribute, a URL or a style, and nothing here uses innerHTML. The tree it shows has no links, forms, media,
 * handlers or captured text: a text/input node is the constant mask and an opaque node is a constant label.
 *
 * It must run inside a sandboxed iframe (VIEWER_SANDBOX, no allow-same-origin) under VIEWER_CSP: the hosting page
 * supplies chunks by postMessage (attachFrameBridge) and the frame can neither fetch nor navigate.
 */
import {GAP_REASONS, REPLAY_PROTOCOL_LIMITS, ReplayDecodeError, breakChain, decodeChunk, initialChainState, sha256, verifyChain, type ChainGap, type GapReason, type ReplayChainState, type ReplayChunk, type ReplayEvent, type ReplayLimits, type ReplayNode, type ReplayTag} from "./decode.ts";

export type ReplayStatus = "loading" | "ready" | "gap" | "unsupported" | "error";

/** One item from the authorized host stream. The host maps the Go ReplayStream events onto these. */
export type ReplayItem =
 | {readonly kind: "chunk"; readonly bytes: Uint8Array}
 | {readonly kind: "gap"; readonly reason: GapReason; readonly from: string; readonly through: string}
 | {readonly kind: "unsupported"}
 | {readonly kind: "revoke"; readonly reason: "authority_revoked" | "deleted"}
 | {readonly kind: "error"};
export type ReplayStream = AsyncIterable<ReplayItem>;

export interface ReplayOptions {
 readonly limits?: ReplayLimits;
 /** Most history (chunk nodes) kept for seeking; the oldest complete checkpoint groups are dropped first. */
 readonly maxRetainedNodes?: number;
 /** Most nodes in the reconstructed tree; beyond it the view stops with an error. */
 readonly maxModelNodes?: number;
 readonly onStatus?: (status: ReplayStatus) => void;
}
export interface ReplayRetained { readonly chunks: number; readonly nodes: number }
export interface ReplayViewHandle {
 /** Shows the state at a chunk sequence (decimal string). A sequence at or past the newest follows the live tip. */
 seek(sequence: string): Promise<void>;
 /** Stops reading, clears the DOM and every retained chunk. Idempotent. */
 close(): void;
 status(): ReplayStatus;
 /** What the renderer itself still holds; always zero after close or a revoke/deletion/error. */
 retained(): ReplayRetained;
 /** Settles when the stream ended, or the view was closed or stopped. */
 readonly done: Promise<void>;
}

const DEFAULT_MAX_RETAINED_NODES = 200_000;
const DEFAULT_MAX_MODEL_NODES = 100_000;
const MAX_RENDER_DEPTH = 256;
const MAX_LIST = 1000;
const MAX_UINT64 = (1n << 64n) - 1n;

const MASK_TEXT = "[masked]";
const OPAQUE_TEXT = "[opaque]";
const STATUS_TEXT: Readonly<Record<ReplayStatus, string>> = {loading: "Loading replay", ready: "Replay ready", gap: "History gap", unsupported: "Unsupported recorder version", error: "Replay unavailable"};
/** Stream tag to element name; anything else is the generic opaque block. Interactive elements are never created. */
const TAG_ELEMENT: Readonly<Record<ReplayTag, "div" | "span" | "p" | "section">> = {div: "div", span: "span", p: "p", button: "div", input: "div", section: "section", canvas: "div", masked: "div"};
const TAG_NAMES: readonly ReplayTag[] = ["div", "span", "p", "button", "input", "section", "canvas", "masked"];
const SHOWN_EVENTS: readonly string[] = ["pointer", "scroll", "resize", "mutation"];

/** A node as the tree builder accepts it: untrusted strings, used only as lookup keys. */
export interface TreeInput { readonly id: string; readonly parent: string; readonly tag: string; readonly class: string; readonly text: string }

function elementWith(doc: Document, name: "div" | "span" | "p" | "section" | "ol" | "li", attributes: readonly (readonly [string, string])[] = []): HTMLElement {
 const element = doc.createElement(name);
 for (const [key, value] of attributes) element.setAttribute(key, value);
 return element;
}

/**
 * Builds the inert tree for `nodes` (parent "0" = root). Cycles, orphans, self-parents and duplicates are
 * unreachable and never rendered; opaque nodes show a constant label and never their children; depth is bounded.
 */
export function renderTree(doc: Document, nodes: Iterable<TreeInput>): HTMLElement {
 const root = elementWith(doc, "div", [["data-replay-tree", ""], ["inert", ""]]);
 const children = new Map<string, TreeInput[]>();
 for (const node of nodes) {
  const siblings = children.get(node.parent);
  if (siblings === undefined) children.set(node.parent, [node]); else siblings.push(node);
 }
 const visited = new Set<string>();
 const stack: {readonly parent: string; readonly host: HTMLElement; readonly depth: number}[] = [{parent: "0", host: root, depth: 0}];
 for (let frame = stack.pop(); frame !== undefined; frame = stack.pop()) {
  for (const node of children.get(frame.parent) ?? []) {
   if (visited.has(node.id)) continue;
   visited.add(node.id);
   const tag: ReplayTag = TAG_NAMES.find(name => name === node.tag) ?? "masked";
   const element = elementWith(doc, TAG_ELEMENT[tag], [["data-tag", tag]]);
   const opaque = node.class === "masked";
   if (opaque || node.text === MASK_TEXT) {
    const label = elementWith(doc, "span", [["data-masked", ""]]);
    label.textContent = opaque ? OPAQUE_TEXT : MASK_TEXT;
    if (opaque) element.setAttribute("data-opaque", "1");
    element.append(label);
   }
   frame.host.append(element);
   if (!opaque && frame.depth < MAX_RENDER_DEPTH) stack.push({parent: node.id, host: element, depth: frame.depth + 1});
  }
 }
 return root;
}

type Model = Map<string, ReplayNode>;
type Entry =
 | {readonly kind: "checkpoint" | "delta"; readonly seq: bigint; readonly nodes: readonly ReplayNode[]; readonly events: readonly ReplayEvent[]}
 | {readonly kind: "gap"; readonly from: bigint; through: bigint; readonly reason: GapReason};
const startOf = (entry: Entry): bigint => (entry.kind === "gap" ? entry.from : entry.seq);
const endOf = (entry: Entry): bigint => (entry.kind === "gap" ? entry.through : entry.seq);

function applyDelta(model: Model, nodes: readonly ReplayNode[], events: readonly ReplayEvent[]): void {
 const mutated = events.filter(event => event.kind === "mutation").map(event => event.node);
 if (mutated.length > 0) {
  // A mutation re-walks the subtree under its node: the old descendants go, the chunk carries the new ones.
  const children = new Map<string, string[]>();
  for (const node of model.values()) { const siblings = children.get(node.parent); if (siblings === undefined) children.set(node.parent, [node.id]); else siblings.push(node.id); }
  const stack = [...mutated];
  for (let id = stack.pop(); id !== undefined; id = stack.pop()) {
   for (const child of children.get(id) ?? []) { stack.push(child); model.delete(child); }
  }
 }
 for (const node of nodes) model.set(node.id, node);
}

class ReplayView implements ReplayViewHandle {
 readonly done: Promise<void>;
 private resolveDone!: () => void;
 private readonly doc: Document;
 private readonly limits: ReplayLimits;
 private readonly maxRetained: number;
 private readonly maxModel: number;
 private readonly onStatus: ((status: ReplayStatus) => void) | undefined;
 private iterator: AsyncIterator<ReplayItem> | undefined;
 private terminal = false;
 private chain: ReplayChainState = initialChainState();
 private entries: Entry[] = [];
 private openGap: (Entry & {kind: "gap"}) | null = null;
 private model: Model = new Map();
 private unsupportedOpen = false;
 private cursor: bigint | null = null;
 private retainedNodes = 0;
 private timer: ReturnType<typeof setTimeout> | undefined;
 private lastStatus: ReplayStatus | undefined;

 constructor(private readonly container: HTMLElement, stream: ReplayStream, options: ReplayOptions) {
  this.doc = container.ownerDocument;
  this.limits = options.limits ?? REPLAY_PROTOCOL_LIMITS;
  this.maxRetained = options.maxRetainedNodes ?? DEFAULT_MAX_RETAINED_NODES;
  this.maxModel = options.maxModelNodes ?? DEFAULT_MAX_MODEL_NODES;
  this.onStatus = options.onStatus;
  this.done = new Promise<void>(resolve => { this.resolveDone = resolve; });
  this.flush();
  void this.pump(stream);
 }

 status(): ReplayStatus {
  if (this.terminal) return "error";
  if (this.cursor === null) {
   if (this.chain.broken !== null) return this.unsupportedOpen ? "unsupported" : "gap";
   return this.chain.head === null ? "loading" : "ready";
  }
  return this.fold(this.cursor).inGap ? "gap" : "ready";
 }
 retained(): ReplayRetained { return {chunks: this.entries.filter(entry => entry.kind !== "gap").length, nodes: this.retainedNodes}; }

 seek(sequence: string): Promise<void> {
  if (this.terminal) return Promise.reject(new Error("replay view is closed"));
  if (typeof sequence !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/.test(sequence)) return Promise.reject(new TypeError("invalid replay sequence"));
  const target = BigInt(sequence);
  if (target < 1n || target > MAX_UINT64) return Promise.reject(new TypeError("invalid replay sequence"));
  const first = this.entries[0], last = this.entries[this.entries.length - 1];
  if (first === undefined || last === undefined || target < startOf(first)) return Promise.reject(new RangeError("replay sequence is not retained"));
  this.cursor = target >= endOf(last) ? null : target;
  this.flush();
  return Promise.resolve();
 }

 close(): void { this.stop(true); }

 /** Ends the view: stop reading the host stream, drop every retained chunk and node, clear the DOM. */
 private stop(silent: boolean): void {
  if (this.terminal) return;
  this.terminal = true;
  if (this.timer !== undefined) { clearTimeout(this.timer); this.timer = undefined; }
  const iterator = this.iterator;
  this.iterator = undefined;
  try { void Promise.resolve(iterator?.return?.()).catch(() => undefined); } catch { /* the host stream is already gone */ }
  this.entries = []; this.openGap = null; this.model = new Map(); this.retainedNodes = 0; this.chain = initialChainState(); this.cursor = null;
  if (silent) this.container.replaceChildren();
  else this.container.replaceChildren(this.shell("error"));
  this.emit();
  this.resolveDone();
 }

 private async pump(stream: ReplayStream): Promise<void> {
  try {
   const iterator = stream[Symbol.asyncIterator]();
   this.iterator = iterator;
   while (!this.terminal) {
    const result = await iterator.next();
    if (this.terminal || result.done === true) break;
    this.handle(result.value);
   }
  } catch {
   // A host error (permission, revocation, deletion, transport) is never retried or continued here.
   this.stop(false);
  }
  if (!this.terminal) { this.flushNow(); this.resolveDone(); }
 }

 private handle(item: ReplayItem): void {
  const kind: unknown = typeof item === "object" && item !== null ? Reflect.get(item, "kind") : undefined;
  if (kind === "chunk") {
   const bytes: unknown = Reflect.get(item, "bytes");
   if (!(bytes instanceof Uint8Array)) return this.stop(false);
   return this.chunk(bytes);
  }
  if (kind === "gap") {
   const reason: unknown = Reflect.get(item, "reason"), from: unknown = Reflect.get(item, "from"), through: unknown = Reflect.get(item, "through");
   const decimal = /^[1-9][0-9]{0,19}$/;
   if (typeof reason !== "string" || !(GAP_REASONS as readonly string[]).includes(reason) || typeof from !== "string" || typeof through !== "string" || !decimal.test(from) || !decimal.test(through) || BigInt(from) > BigInt(through) || BigInt(through) > MAX_UINT64) return this.stop(false);
   this.chain = breakChain(this.chain, reason as GapReason);
   this.addGap({reason: reason as GapReason, from, through});
   return this.schedule();
  }
  if (kind === "unsupported") { this.unsupported(); return this.schedule(); }
  this.stop(false); // revoke, deletion, error and anything unrecognized all end the view the same way
 }

 private nextExpected(): string { return this.chain.seen === null ? "1" : String(BigInt(this.chain.seen.sequence) + 1n); }
 private unsupported(): void {
  this.chain = breakChain(this.chain, "recorder_version");
  this.unsupportedOpen = true;
  const at = this.nextExpected();
  this.addGap({reason: "recorder_version", from: at, through: at});
 }

 private chunk(bytes: Uint8Array): void {
  let decoded: ReplayChunk;
  try { decoded = decodeChunk(bytes, this.limits); } catch (error) {
   if (!(error instanceof ReplayDecodeError)) throw error;
   if (error.code === "unsupported_version") this.unsupported();
   else { this.chain = breakChain(this.chain, "invalid_chunk"); const at = this.nextExpected(); this.addGap({reason: "invalid_chunk", from: at, through: at}); }
   return this.schedule();
  }
  const decision = verifyChain(decoded, this.chain);
  this.chain = decision.state;
  switch (decision.kind) {
   case "apply":
    this.entries.push({kind: "delta", seq: BigInt(decoded.sequence), nodes: decoded.nodes, events: decoded.events});
    this.retainedNodes += decoded.nodes.length;
    applyDelta(this.model, decoded.nodes, decoded.events);
    break;
   case "checkpoint":
    if (decision.gap !== null) this.addGap(decision.gap);
    this.openGap = null; this.unsupportedOpen = false;
    this.entries.push({kind: "checkpoint", seq: BigInt(decoded.sequence), nodes: decoded.nodes, events: decoded.events});
    this.retainedNodes += decoded.nodes.length;
    this.model = new Map(decoded.nodes.map(node => [node.id, node]));
    break;
   case "gap": this.addGap(decision.gap); break;
   case "reject": if (decision.gap !== null) this.addGap(decision.gap); break;
  }
  if (this.model.size > this.maxModel) return this.stop(false);
  this.trim();
  this.schedule();
 }

 private addGap(gap: ChainGap): void {
  const from = BigInt(gap.from), through = BigInt(gap.through);
  if (this.openGap !== null) { if (through > this.openGap.through) this.openGap.through = through; return; }
  const entry = {kind: "gap" as const, from, through, reason: gap.reason};
  this.entries.push(entry);
  this.openGap = entry;
 }

 /** Drops the oldest complete checkpoint groups until the retained history fits; the live group is never dropped. */
 private trim(): void {
  while (this.retainedNodes > this.maxRetained) {
   const boundary = this.entries.findIndex((entry, index) => index > 0 && entry.kind === "checkpoint");
   if (boundary < 0) return;
   for (const dropped of this.entries.splice(0, boundary)) if (dropped.kind !== "gap") this.retainedNodes -= dropped.nodes.length;
  }
  const first = this.entries[0];
  if (this.cursor !== null && first !== undefined && this.cursor < startOf(first)) this.cursor = null;
 }

 /** State at a sequence: fold from the nearest checkpoint; landing in or after an unresolved gap reports it. */
 private fold(cursor: bigint): {model: Model; entries: Entry[]; inGap: boolean} {
  const visible = this.entries.filter(entry => startOf(entry) <= cursor);
  let model: Model = new Map(), inGap = false;
  for (const entry of visible) {
   if (entry.kind === "gap") inGap = true;
   else if (entry.kind === "checkpoint") { model = new Map(entry.nodes.map(node => [node.id, node])); inGap = false; }
   else applyDelta(model, entry.nodes, entry.events);
  }
  return {model, entries: visible, inGap};
 }

 private schedule(): void {
  if (this.terminal || this.timer !== undefined) return;
  this.timer = setTimeout(() => { this.timer = undefined; this.flush(); }, 0);
 }
 private flushNow(): void {
  if (this.timer !== undefined) { clearTimeout(this.timer); this.timer = undefined; }
  this.flush();
 }

 private shell(status: ReplayStatus): HTMLElement {
  const root = elementWith(this.doc, "div", [["data-replay-root", ""], ["data-state", status]]);
  const header = elementWith(this.doc, "div", [["data-replay-status", ""], ["role", "status"]]);
  header.textContent = STATUS_TEXT[status];
  root.append(header);
  return root;
 }

 private emit(): void {
  const status = this.status();
  if (status === this.lastStatus) return;
  this.lastStatus = status;
  try { this.onStatus?.(status); } catch { /* a status listener cannot break rendering */ }
 }

 private flush(): void {
  if (this.terminal) return;
  const status = this.status();
  const shown = this.cursor === null ? {model: this.model, entries: this.entries} : this.fold(this.cursor);
  const root = this.shell(status);
  const timeline = elementWith(this.doc, "ol", [["data-replay-timeline", ""]]);
  const interactions = elementWith(this.doc, "ol", [["data-replay-interactions", ""]]);
  const lines: HTMLElement[] = [], moves: HTMLElement[] = [];
  for (const entry of shown.entries) {
   if (entry.kind === "gap") {
    const item = elementWith(this.doc, "li", [["data-kind", "gap"]]);
    item.textContent = `gap ${entry.from === entry.through ? String(entry.from) : `${entry.from}-${entry.through}`} ${entry.reason}`;
    lines.push(item);
    continue;
   }
   const item = elementWith(this.doc, "li", [["data-kind", entry.kind], ["data-sequence", String(entry.seq)]]);
   item.textContent = `${entry.kind} ${entry.seq}`;
   lines.push(item);
   for (const event of entry.events) {
    if (!SHOWN_EVENTS.includes(event.kind)) continue;
    const move = elementWith(this.doc, "li", [["data-kind", event.kind]]);
    move.textContent = `${event.kind} ${event.x},${event.y}`;
    moves.push(move);
   }
  }
  timeline.append(...lines.slice(-MAX_LIST));
  interactions.append(...moves.slice(-MAX_LIST));
  root.append(renderTree(this.doc, shown.model.values()), timeline, interactions);
  this.container.replaceChildren(root);
  this.emit();
 }
}

/** Starts rendering an authorized stream into `container`. The container's children are replaced. */
export function renderReplay(container: HTMLElement, stream: ReplayStream, options: ReplayOptions = {}): ReplayViewHandle {
 return new ReplayView(container, stream, options);
}

// ---------------------------------------------------------------------------------------------
// Sandboxed frame hosting.

/** The iframe sandbox attribute: scripts only. Never allow-same-origin, allow-top-navigation, allow-forms or allow-popups. */
export const VIEWER_SANDBOX = "allow-scripts";
/** Static stylesheet of the viewer frame; element presentation is chosen by constant data-tag/data-state values only. */
export const VIEWER_STYLE = [
 "body{margin:0;font:12px/1.4 system-ui,sans-serif;color:#222;background:#fff}",
 "[data-replay-root]{padding:8px}",
 "[data-replay-status]{font-weight:600;margin-bottom:8px}",
 "[data-state=gap] [data-replay-status]{color:#8a4b00}[data-state=error] [data-replay-status],[data-state=unsupported] [data-replay-status]{color:#a00}",
 "[data-state=gap] [data-replay-tree]{opacity:.55}",
 "[data-replay-tree]{border:1px solid #ccc;padding:4px;min-height:24px;pointer-events:none;user-select:none}",
 "[data-replay-tree] div,[data-replay-tree] p,[data-replay-tree] section{margin:2px 0 2px 8px;padding:2px;border-left:1px dotted #aaa}",
 "[data-tag=button]{border:1px solid #666;border-radius:3px;display:inline-block}[data-tag=input]{border:1px solid #666;background:#f3f3f3;min-width:48px}",
 "[data-tag=canvas],[data-opaque]{background:repeating-linear-gradient(45deg,#ddd,#ddd 4px,#eee 4px,#eee 8px);min-height:16px}",
 "[data-masked]{color:#666}",
 "ol{margin:8px 0;padding-left:20px}[data-kind=gap]{color:#8a4b00;font-weight:600}",
].join("\n");

const BASE_CSP = "default-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; frame-src 'none'";
const base64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
/** CSP source expression for exactly this text, e.g. `'sha256-…'`, so only the static viewer script and style run. */
export function cspHash(text: string): string { return `'sha256-${base64(sha256(new TextEncoder().encode(text)))}'`; }
/** The no-network policy plus exactly one allowed script and one allowed style, by hash. No other source of anything. */
export function viewerCsp(scriptSource: string, styleSource: string = VIEWER_STYLE): string {
 return `${BASE_CSP}; script-src ${cspHash(scriptSource)}; style-src ${cspHash(styleSource)}; form-action 'none'; base-uri 'none'`;
}

/** Message envelope the hosting page posts to the frame: `{soundpost: "replay", item}`. */
const BRIDGE_TAG = "replay";
const MAX_BRIDGE_CHUNKS = 256;
const MAX_BRIDGE_ITEMS = 1024;

/**
 * Connects a frame's window to renderReplay. Only messages from the parent window are read; each is rebuilt into a
 * fresh closed ReplayItem (unknown fields are dropped). A flood of chunks is dropped, never reordered: the missing
 * sequences show up as a visible gap. Control items are never dropped; too many of them ends the view.
 */
export function attachFrameBridge(frame: Window, container: HTMLElement, options: ReplayOptions = {}): ReplayViewHandle {
 const queue: ReplayItem[] = [];
 let waiting: ((result: IteratorResult<ReplayItem>) => void) | undefined;
 let chunks = 0, ended = false;
 const finish = (): void => { ended = true; queue.length = 0; frame.removeEventListener("message", listener); const resolve = waiting; waiting = undefined; resolve?.({done: true, value: undefined}); };
 const push = (item: ReplayItem): void => {
  if (item.kind === "chunk") { if (chunks >= MAX_BRIDGE_CHUNKS) return; chunks++; }
  else if (queue.length >= MAX_BRIDGE_ITEMS) { queue.length = 0; queue.push({kind: "error"}); }
  const resolve = waiting;
  if (resolve !== undefined) { waiting = undefined; if (item.kind === "chunk") chunks--; resolve({done: false, value: item}); } else queue.push(item);
 };
 const listener = (event: MessageEvent): void => {
  if (event.source !== frame.parent || ended) return;
  const data: unknown = event.data;
  if (typeof data !== "object" || data === null || Reflect.get(data, "soundpost") !== BRIDGE_TAG) return;
  const item: unknown = Reflect.get(data, "item");
  if (typeof item !== "object" || item === null) return;
  const kind: unknown = Reflect.get(item, "kind");
  if (kind === "chunk") {
   const bytes: unknown = Reflect.get(item, "bytes");
   if (bytes instanceof ArrayBuffer) push({kind: "chunk", bytes: new Uint8Array(bytes)});
   else if (bytes instanceof Uint8Array) push({kind: "chunk", bytes: new Uint8Array(bytes)});
  } else if (kind === "gap") push({kind: "gap", reason: Reflect.get(item, "reason") as GapReason, from: String(Reflect.get(item, "from")), through: String(Reflect.get(item, "through"))});
  else if (kind === "unsupported") push({kind: "unsupported"});
  else if (kind === "revoke") push({kind: "revoke", reason: Reflect.get(item, "reason") === "deleted" ? "deleted" : "authority_revoked"});
  else push({kind: "error"});
 };
 const stream: ReplayStream = {
  [Symbol.asyncIterator]: () => ({
   next: (): Promise<IteratorResult<ReplayItem>> => {
    const item = queue.shift();
    if (item !== undefined) { if (item.kind === "chunk") chunks--; return Promise.resolve({done: false, value: item}); }
    if (ended) return Promise.resolve({done: true, value: undefined});
    return new Promise(resolve => { waiting = resolve; });
   },
   return: (): Promise<IteratorResult<ReplayItem>> => { finish(); return Promise.resolve({done: true, value: undefined}); },
  }),
 };
 frame.addEventListener("message", listener);
 const handle = renderReplay(container, stream, options);
 void handle.done.then(finish);
 return handle;
}
