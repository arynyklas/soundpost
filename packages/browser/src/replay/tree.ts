// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {DomAccessors, ReplayNode} from "./types.ts";
import {MASK, MAX_DEPTH, MAX_NODES, isOpaqueWidget, isSkipped, tagFor} from "./policy.ts";

type Proto = {readonly prototype: object};
export interface DomGlobals {
 readonly Node: Proto; readonly Element: Proto; readonly HTMLElement?: Proto; readonly MouseEvent?: Proto; readonly Event?: Proto; readonly MutationRecord?: Proto;
}
type Read = (self: object) => unknown;
function getter(proto: object | undefined, name: string): Read | undefined {
 const fn = proto === undefined ? undefined : Object.getOwnPropertyDescriptor(proto, name)?.get;
 return fn === undefined ? undefined : (self: object) => Reflect.apply(fn, self, []);
}
function required(proto: object | undefined, name: string): Read {
 const read = getter(proto, name);
 if (read === undefined) throw Error("replay_dom_accessor_missing");
 return read;
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
 const target = required(g.MutationRecord?.prototype, "target"), eventTarget = required(g.Event?.prototype, "target");
 const clientX = required(g.MouseEvent?.prototype, "clientX"), clientY = required(g.MouseEvent?.prototype, "clientY");
 return {
  nodeType: node => asNumber(nodeType(node)),
  firstChild: node => asObject(first(node)),
  nextSibling: node => asObject(next(node)),
  parentNode: node => asObject(parent(node)),
  localName: element => { const name = localName(element); return typeof name === "string" ? name.toLowerCase() : ""; },
  openShadowRoot: element => asObject(shadow(element)),
  // The HTMLElement getter throws "Illegal invocation" on SVG/MathML elements, which cannot be contenteditable.
  editable: element => { try { return editable?.(element) === true; } catch { return false; } },
  mutationTarget: record => asObject(target(record)),
  eventTarget: event => asObject(eventTarget(event)),
  clientX: event => asNumber(clientX(event)),
  clientY: event => asNumber(clientY(event)),
 };
}

export interface WalkState {
 readonly nodes: ReplayNode[];
 readonly ids: WeakMap<object, number>;
 readonly allocate: () => number;
 readonly onOpenShadow?: (root: object) => void;
 overflow: boolean;
 /** Number of siblings skipped because of the node cap or depth limit. */
 truncated: number;
 steps: number;
}
export function newWalkState(ids: WeakMap<object, number>, allocate: () => number, onOpenShadow?: (root: object) => void): WalkState {
 return {nodes: [], ids, allocate, ...(onOpenShadow === undefined ? {} : {onOpenShadow}), overflow: false, truncated: 0, steps: 0};
}

function emit(state: WalkState, source: object, node: Omit<ReplayNode, "id">, id: number | undefined): void {
 const assigned = id ?? state.allocate();
 state.ids.set(source, assigned);
 state.nodes.push({id: String(assigned), ...node});
}

/**
 * Directly builds owned nodes from the live DOM. Text and input values are never read: a text node
 * or input is a constant mask. Subtrees that cannot be masked structurally become one opaque node.
 */
export function walk(dom: DomAccessors, source: object, parentId: string, state: WalkState, depth = 0, forcedId?: number): void {
 if (state.overflow || ++state.steps > MAX_NODES * 4) { state.overflow = true; return; }
 const type = dom.nodeType(source);
 if (type === 9 || type === 11) { walkChildren(dom, source, parentId, state, depth); return; }
 if (type !== 1 && type !== 3) return;
 if (state.nodes.length >= MAX_NODES - 1) {
  // Last slot: one opaque placeholder stands for everything not retained; nothing further is walked.
  state.overflow = true;
  emit(state, source, {parent: parentId, tag: "masked", class: "masked", text: ""}, forcedId);
  return;
 }
 if (type === 3) { emit(state, source, {parent: parentId, tag: "masked", class: "", text: MASK}, forcedId); return; }
 const name = dom.localName(source);
 if (isSkipped(name)) return;
 if (depth >= MAX_DEPTH || isOpaqueWidget(name) || dom.editable(source) || dom.closedShadow?.(source) === true) {
  emit(state, source, {parent: parentId, tag: "masked", class: "masked", text: ""}, forcedId);
  return;
 }
 emit(state, source, {parent: parentId, tag: tagFor(name), class: "", text: name === "input" ? MASK : ""}, forcedId);
 const id = String(state.ids.get(source));
 if (name === "input") return;
 const root = dom.openShadowRoot(source);
 if (root !== null) { state.onOpenShadow?.(root); walkChildren(dom, root, id, state, depth + 1); }
 walkChildren(dom, source, id, state, depth + 1);
}
function walkChildren(dom: DomAccessors, container: object, parentId: string, state: WalkState, depth: number): void {
 for (let child = dom.firstChild(container); child !== null; child = dom.nextSibling(child)) {
  if (state.overflow) { state.truncated++; return; }
  walk(dom, child, parentId, state, depth);
 }
}

export interface FitResult {
 readonly nodes: readonly ReplayNode[];
 /** True when whole subtrees were replaced by opaque placeholders to fit. */
 readonly truncated: boolean;
 /** Local ids of every placeholder and every node it replaced; deltas under them are suppressed until the next complete checkpoint. */
 readonly suppressed: readonly number[];
}
/**
 * Makes one emission fit one chunk without ever truncating a chunk silently or inventing a fragmented-checkpoint
 * format: whole sanitized subtrees are replaced by bounded opaque placeholders (same id and parent,
 * tag and class "masked", empty text) until `maxNodes` and `maxBytes` hold. Priority is explicit: later in document
 * order and deeper means lower priority, so the tail of the page is collapsed first, smallest subtrees first, and
 * the head of the page is kept as long as possible. The input is in walk (pre-order) order; the output keeps it.
 * A flat run of thousands of siblings cannot shrink except by collapsing their parent, which is what happens.
 */
export function fitSubtrees(nodes: readonly ReplayNode[], maxNodes: number, maxBytes: number): FitResult {
 const count = nodes.length;
 const size = nodes.map(node => JSON.stringify(node).length + 1);
 let totalNodes = count, totalBytes = size.reduce((sum, value) => sum + value, 0);
 if (totalNodes <= maxNodes && totalBytes <= maxBytes) return {nodes, truncated: false, suppressed: []};
 const index = new Map<string, number>();
 nodes.forEach((node, at) => index.set(node.id, at));
 const parent = nodes.map(node => index.get(node.parent) ?? -1);
 const liveCount = new Array<number>(count).fill(1), liveBytes = size.slice();
 for (let at = count - 1; at >= 0; at--) { const up = parent[at]!; if (up >= 0) { liveCount[up]! += liveCount[at]!; liveBytes[up]! += liveBytes[at]!; } }
 const span = liveCount.slice(); // pre-order subtree length, fixed
 const alive = new Array<boolean>(count).fill(true);
 const replaced = new Map<number, ReplayNode>();
 const suppressed: number[] = [];
 for (let at = count - 1; at >= 0 && (totalNodes > maxNodes || totalBytes > maxBytes); at--) {
  if (!alive[at] || liveCount[at]! <= 1) continue;
  const original = nodes[at]!;
  const placeholder: ReplayNode = {...original, tag: "masked", class: "masked", text: ""};
  const placeholderBytes = JSON.stringify(placeholder).length + 1;
  const freedNodes = liveCount[at]! - 1, freedBytes = liveBytes[at]! - placeholderBytes;
  for (let inner = at + 1; inner < at + span[at]!; inner++) if (alive[inner]) { alive[inner] = false; suppressed.push(Number(nodes[inner]!.id)); }
  replaced.set(at, placeholder); suppressed.push(Number(original.id));
  for (let up = parent[at]!; up >= 0; up = parent[up]!) { liveCount[up]! -= freedNodes; liveBytes[up]! -= freedBytes; }
  liveCount[at] = 1; liveBytes[at] = placeholderBytes;
  totalNodes -= freedNodes; totalBytes -= freedBytes;
 }
 return {nodes: nodes.flatMap((node, at) => (alive[at] ? [replaced.get(at) ?? node] : [])), truncated: true, suppressed};
}
