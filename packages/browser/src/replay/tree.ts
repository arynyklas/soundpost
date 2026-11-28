// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {DomAccessors} from "./types.ts";
import {MAX_DEPTH, MAX_NODES, isCustomElementName, isOpaqueWidget, isSkipped} from "./policy.ts";
import {MARK_CLOSED, MARK_INPUT, MARK_OPAQUE, MARK_TEXT, NodeTable, tagCode} from "./nodes.ts";
import {Links} from "./links.ts";

type Proto = {readonly prototype: object};
export interface DomGlobals {
 readonly Node: Proto; readonly Element: Proto; readonly HTMLElement?: Proto; readonly MouseEvent?: Proto; readonly Event?: Proto; readonly MutationRecord?: Proto;
}
type Read = (self: object) => unknown;
const NO_ARGS: readonly unknown[] = Object.freeze([]);
function getter(proto: object | undefined, name: string): Read | undefined {
 const fn = proto === undefined ? undefined : Object.getOwnPropertyDescriptor(proto, name)?.get;
 return fn === undefined ? undefined : (self: object) => Reflect.apply(fn, self, NO_ARGS);
}
function required(proto: object | undefined, name: string): Read {
 const read = getter(proto, name);
 if (read === undefined) throw Error("replay_dom_accessor_missing");
 return read;
}
/** A platform method captured once (`Element.prototype.matches`), called with one argument and no page-visible indirection. */
function method(proto: object | undefined, name: string): ((self: object, arg: string) => unknown) | undefined {
 const fn = proto === undefined ? undefined : Object.getOwnPropertyDescriptor(proto, name)?.value;
 return typeof fn === "function" ? (self: object, arg: string) => Reflect.apply(fn, self, [arg]) : undefined;
}
/**
 * Closed shadow roots are invisible to page script (`shadowRoot` is null), so they can only be recognised when they are
 * created: while a recorder is active, `Element.prototype.attachShadow` is wrapped so a call that returned a root for a host
 * whose own platform `shadowRoot` getter answers null marks that host closed. The init dictionary is never read (the platform reads
 * it once itself; a second read could run page getters or Proxy traps). The wrapper forwards the receiver, arguments, result and any
 * exception unchanged. A closed root created BEFORE the wrapper was installed (page script that ran before replay started) cannot be
 * proven: its host answers `shadowRoot === null` like any element. Those hosts are recognised by inference only, never by content
 * (see `inferClosedHost`); anything the inference cannot see is walked as an ordinary element (see packages/browser/README.md).
 */
function watchClosedShadows(elementProto: object, shadow: Read): {readonly closedShadow: (element: object) => boolean; readonly release: () => void} {
 const closed = new WeakSet<object>();
 const none = {closedShadow: () => false, release: () => {}};
 const descriptor = Object.getOwnPropertyDescriptor(elementProto, "attachShadow");
 const original = descriptor?.value;
 if (descriptor === undefined || typeof original !== "function" || descriptor.writable !== true) return none;
 let live = true;
 const wrapper = function attachShadow(this: unknown, ...args: unknown[]): unknown {
  const root = Reflect.apply(original, this, args);
  if (live && typeof this === "object" && this !== null && typeof root === "object" && root !== null) {
   try { if (shadow(this) === null) closed.add(this); } catch { /* host is not a platform element: nothing to record */ }
  }
  return root;
 };
 Object.defineProperty(elementProto, "attachShadow", {...descriptor, value: wrapper});
 return {
  closedShadow: element => closed.has(element),
  release: () => {
   live = false;
   // Restore only when nobody wrapped the wrapper; otherwise it stays installed but inert.
   if (Object.getOwnPropertyDescriptor(elementProto, "attachShadow")?.value === wrapper) Object.defineProperty(elementProto, "attachShadow", descriptor);
  },
 };
}
const asObject = (value: unknown): object | null => (typeof value === "object" && value !== null ? value : null);
const asNumber = (value: unknown): number => (typeof value === "number" ? value : 0);

/**
 * Captures platform getters once so own-property or per-instance getter traps planted by page script
 * never execute during traversal. Every result is type-checked at the edge.
 */
export function captureDomAccessors(g: DomGlobals): DomAccessors {
 const nodeP = g.Node.prototype, elementP = g.Element.prototype, htmlP = g.HTMLElement?.prototype ?? elementP;
 const nodeType = required(nodeP, "nodeType"), first = required(nodeP, "firstChild"), next = required(nodeP, "nextSibling"), parent = required(nodeP, "parentNode");
 const localName = required(elementP, "localName"), shadow = required(elementP, "shadowRoot"), editable = getter(htmlP, "isContentEditable");
 const closedShadows = watchClosedShadows(elementP, shadow);
 const target = required(g.MutationRecord?.prototype, "target"), eventTarget = required(g.Event?.prototype, "target");
 const recordType = getter(g.MutationRecord?.prototype, "type"), recordNext = getter(g.MutationRecord?.prototype, "nextSibling");
 const last = required(nodeP, "lastChild"), previous = required(nodeP, "previousSibling");
 const clientX = required(g.MouseEvent?.prototype, "clientX"), clientY = required(g.MouseEvent?.prototype, "clientY");
 const matches = method(elementP, "matches"), offsetWidth = getter(htmlP, "offsetWidth"), offsetHeight = getter(htmlP, "offsetHeight");
 const lower = (element: object): string => { const name = localName(element); return typeof name === "string" ? name.toLowerCase() : ""; };
 /**
  * A closed root made before capture started cannot be proven, only inferred from what the platform shows without reading content: an upgraded
  * (`:defined`) autonomous custom element, the elements whose own code attaches closed roots, whose `shadowRoot` is null, that has no light-DOM
  * child and still occupies a layout box, is rendering something the page cannot read. Elements the inference cannot name (a plain `div`
  * host, a host with light children, a box of zero size) are walked as ordinary elements; that residual is a platform limit.
  */
 const inferClosedHost = (element: object, name: string): boolean => {
  if (!isCustomElementName(name) || matches === undefined || offsetWidth === undefined || offsetHeight === undefined) return false;
  try {
   if (shadow(element) !== null || first(element) !== null) return false;
   return matches(element, ":defined") === true && (asNumber(offsetWidth(element)) > 0 || asNumber(offsetHeight(element)) > 0);
  } catch { return false; }
 };
 return {
  nodeType: node => asNumber(nodeType(node)),
  firstChild: node => asObject(first(node)),
  nextSibling: node => asObject(next(node)),
  lastChild: node => asObject(last(node)),
  previousSibling: node => asObject(previous(node)),
  parentNode: node => asObject(parent(node)),
  localName: lower,
  openShadowRoot: element => asObject(shadow(element)),
  closedShadow: (element, name) => closedShadows.closedShadow(element) || inferClosedHost(element, name ?? lower(element)),
  release: closedShadows.release,
  // The HTMLElement getter throws "Illegal invocation" on SVG/MathML elements, which cannot be contenteditable.
  editable: element => { try { return editable?.(element) === true; } catch { return false; } },
  mutationTarget: record => asObject(target(record)),
  recordKind: record => {
   if (recordType === undefined || recordNext === undefined || recordType(record) !== "childList") return "other";
   return recordNext(record) === null ? "tail" : "inside";
  },
  eventTarget: event => asObject(eventTarget(event)),
  clientX: event => asNumber(clientX(event)),
  clientY: event => asNumber(clientY(event)),
 };
}

export interface WalkState {
 /** The nodes walked so far; the recorder passes its one reused table. */
 readonly nodes: NodeTable;
 /** The order of the children the walk records, written as it goes (see Links): the recorder's append check reads it. */
 links: Links;
 ids: WeakMap<object, number>;
 readonly allocate: () => number;
 readonly onOpenShadow?: (root: object) => void;
 overflow: boolean;
 /** Most nodes this walk may emit: MAX_NODES minus the nodes already allocated since the last checkpoint (the running total of the live tree). */
 limit: number;
 /** Number of siblings skipped because of the node cap or depth limit. */
 truncated: number;
 steps: number;
}
export function newWalkState(ids: WeakMap<object, number>, allocate: () => number, onOpenShadow?: (root: object) => void, limit: number = MAX_NODES, nodes: NodeTable = new NodeTable(), links: Links = new Links()): WalkState {
 return {nodes, links, ids, allocate, ...(onOpenShadow === undefined ? {} : {onOpenShadow}), overflow: false, limit, truncated: 0, steps: 0};
}
/** Readies a state for another walk: no nodes, no overflow, the id map and node limit of that walk. No object or array is allocated. */
export function resetWalkState(state: WalkState, ids: WeakMap<object, number>, limit: number = MAX_NODES): void {
 state.nodes.clear(); state.ids = ids; state.overflow = false; state.limit = limit; state.truncated = 0; state.steps = 0;
}

/** A node the replay already holds keeps its id when it is walked again (a re-walked subtree is the same nodes, so churn does not use the id space up); a new node gets a fresh id. */
function emit(state: WalkState, source: object, parent: number, mark: number, id: number | undefined): number {
 const known = id === undefined ? state.ids.get(source) : undefined;
 const assigned = id ?? known ?? state.allocate();
 if (assigned !== known) state.ids.set(source, assigned);
 state.nodes.add(assigned, parent, mark);
 state.links.open(assigned);
 return assigned;
}

/**
 * Directly records owned nodes from the live DOM, as numbers (id, parent id, mark) in the state's table. Text and input values are never read: a text node
 * or input is a constant mask. Subtrees that cannot be masked structurally become one opaque node.
 *
 * The walk is an explicit stack of the child lists still to visit (not recursion), so it can stop after any number of nodes and be resumed: `run(budget)`. The recorder
 * walks a batch in one go; the walk of an id-space checkpoint is run in bounded slices between tasks (see `Recorder.considerPrepare`). Order, ids and decisions are those of the
 * former recursive walk. Every container's children are visited with the id of the node they are shown under (`owner`) and at their depth (`level`).
 */
export class Walker {
 private dom!: DomAccessors;
 private state!: WalkState;
 /** One frame per child list being walked: the next child to visit (null: done), the id its children hang under and their depth. */
 private readonly cursor: Array<object | null> = [];
 private readonly owner: number[] = [];
 private readonly level: number[] = [];
 private height = 0;

 /** Starts a walk of `source` under `parentId`: visits `source` itself; its descendants follow in `run`. */
 begin(dom: DomAccessors, source: object, parentId: number, state: WalkState, depth = 0, forcedId?: number): void {
  this.abandon();
  this.dom = dom; this.state = state;
  this.visit(source, parentId, depth, forcedId);
 }
 /** Visits descendants until `budget` more nodes were emitted (checked between siblings, so a slice may overshoot by one subtree's first node) or the walk is complete; true when complete. */
 run(budget: number): boolean {
  const state = this.state, dom = this.dom, nodes = state.nodes, links = state.links, stop = nodes.length + budget;
  while (this.height > 0) {
   const top = this.height - 1, child = this.cursor[top] ?? null;
   if (child === null) { this.height = top; continue; }
   if (state.overflow) { state.truncated++; this.cursor[top] = null; this.height = top; continue; }
   if (nodes.length >= stop) return false;
   this.cursor[top] = dom.nextSibling(child);
   const before = nodes.length, parentId = this.owner[top]!;
   this.visit(child, parentId, this.level[top]!, undefined);
   if (nodes.length > before) links.link(parentId, nodes.ids[before]!);
  }
  return true;
 }
 /** Drops a walk that will not be finished: no page node stays referenced. */
 abandon(): void {
  for (let at = 0; at < this.height; at++) this.cursor[at] = null;
  this.height = 0;
 }

 private push(container: object, ownerId: number, depth: number): void {
  const first = this.dom.firstChild(container);
  if (first === null) return;
  const at = this.height++;
  this.cursor[at] = first; this.owner[at] = ownerId; this.level[at] = depth;
 }
 private visit(source: object, parentId: number, depth: number, forcedId: number | undefined): void {
  const state = this.state, dom = this.dom;
  if (state.overflow || ++state.steps > MAX_NODES * 4) { state.overflow = true; return; }
  const type = dom.nodeType(source);
  if (type === 9 || type === 11) { this.push(source, parentId, depth); return; }
  if (type !== 1 && type !== 3) return;
  if (state.nodes.length >= state.limit - 1) {
   // Last slot: one opaque placeholder stands for everything not retained; nothing further is walked.
   state.overflow = true;
   emit(state, source, parentId, MARK_OPAQUE, forcedId);
   return;
  }
  if (type === 3) { emit(state, source, parentId, MARK_TEXT, forcedId); return; }
  const name = dom.localName(source);
  if (isSkipped(name)) return;
  if (depth >= MAX_DEPTH || isOpaqueWidget(name) || dom.editable(source)) {
   emit(state, source, parentId, MARK_OPAQUE, forcedId);
   return;
  }
  if (dom.closedShadow?.(source, name) === true) {
   // The closed shadow host's recorded reason, inside the server's closed node vocabulary (D2): an opaque node (class "masked") whose text is the
   // constant mask, the one opaque shape no other cause produces (frames, widgets, editable regions, overflow and truncation are opaque with empty text).
   emit(state, source, parentId, MARK_CLOSED, forcedId);
   return;
  }
  const input = name === "input";
  const id = emit(state, source, parentId, input ? MARK_INPUT : tagCode(name), forcedId);
  if (input) return;
  const root = dom.openShadowRoot(source);
  // The light children are pushed first so the open shadow root's children, which come first in the replay, are visited first.
  this.push(source, id, depth + 1);
  if (root !== null) { state.onOpenShadow?.(root); this.push(root, id, depth + 1); }
 }
}
const shared = new Walker();
/** Walks `source` and everything below it in one go (the recorder's walks outside a sliced checkpoint). */
export function walk(dom: DomAccessors, source: object, parentId: number, state: WalkState, depth = 0, forcedId?: number): void {
 shared.begin(dom, source, parentId, state, depth, forcedId);
 shared.run(Infinity);
}

export interface FitResult {
 /** True when whole subtrees were replaced by opaque placeholders to fit. */
 readonly truncated: boolean;
 /** Local ids of every placeholder and every node it replaced; deltas under them are suppressed until the next complete checkpoint. */
 readonly suppressed: readonly number[];
}
const NOT_TRUNCATED: FitResult = {truncated: false, suppressed: []};
/**
 * Makes one emission fit one chunk without ever truncating a chunk silently or inventing a fragmented-checkpoint
 * format: whole sanitized subtrees are replaced by bounded opaque placeholders (same id and parent,
 * tag and class "masked", empty text) until `maxNodes` and `maxBytes` hold. Priority is explicit: later in document
 * order and deeper means lower priority, so the tail of the page is collapsed first, smallest subtrees first, and
 * the head of the page is kept as long as possible. The table is in walk (pre-order) order and keeps it. It is edited in place.
 * A flat run of thousands of siblings cannot shrink except by collapsing their parent, which is what happens.
 */
export function fitSubtrees(table: NodeTable, maxNodes: number, maxBytes: number): FitResult {
 const count = table.length;
 let totalNodes = count, totalBytes = table.bytes;
 if (totalNodes <= maxNodes && totalBytes <= maxBytes) return NOT_TRUNCATED;
 const index = new Map<number, number>();
 for (let at = 0; at < count; at++) index.set(table.ids[at]!, at);
 const parent = new Array<number>(count), size = new Array<number>(count);
 for (let at = 0; at < count; at++) { parent[at] = index.get(table.parents[at]!) ?? -1; size[at] = table.size(at); }
 const liveCount = new Array<number>(count).fill(1), liveBytes = size.slice();
 for (let at = count - 1; at >= 0; at--) { const up = parent[at]!; if (up >= 0) { liveCount[up]! += liveCount[at]!; liveBytes[up]! += liveBytes[at]!; } }
 const span = liveCount.slice(); // pre-order subtree length, fixed
 const alive = new Array<boolean>(count).fill(true);
 const replaced = new Set<number>();
 const suppressed: number[] = [];
 // A placeholder keeps its node's id and parent and is opaque with empty text: its size is that of the node with the placeholder mark.
 for (let at = count - 1; at >= 0 && (totalNodes > maxNodes || totalBytes > maxBytes); at--) {
  if (!alive[at] || liveCount[at]! <= 1) continue;
  const placeholderBytes = table.size(at, MARK_OPAQUE);
  const freedNodes = liveCount[at]! - 1, freedBytes = liveBytes[at]! - placeholderBytes;
  for (let inner = at + 1; inner < at + span[at]!; inner++) if (alive[inner]) { alive[inner] = false; suppressed.push(table.ids[inner]!); }
  replaced.add(at); suppressed.push(table.ids[at]!);
  for (let up = parent[at]!; up >= 0; up = parent[up]!) { liveCount[up]! -= freedNodes; liveBytes[up]! -= freedBytes; }
  liveCount[at] = 1; liveBytes[at] = placeholderBytes;
  totalNodes -= freedNodes; totalBytes -= freedBytes;
 }
 let kept = 0;
 for (let at = 0; at < count; at++) {
  if (!alive[at]) continue;
  table.ids[kept] = table.ids[at]!; table.parents[kept] = table.parents[at]!; table.marks[kept] = replaced.has(at) ? MARK_OPAQUE : table.marks[at]!;
  kept++;
 }
 table.length = kept;
 table.recount();
 return {truncated: true, suppressed};
}
