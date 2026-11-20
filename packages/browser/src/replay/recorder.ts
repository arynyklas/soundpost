// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {DomAccessors, EnqueueResult, MutationObserverLike, ReplayChunk, ReplayConfig, ReplayEvent, ReplayEventTargetLike, ReplayNode, ReplayRecorder, ReplayTimers} from "./types.ts";
import {CHECKPOINT_INTERVAL_MS, EVENT_FLUSH_MS, GAP_EVENT_BYTES, MAX_CHECKPOINTS, MAX_CHUNK_BYTES, MAX_CHUNK_NODES, MAX_MUTATION_RECORDS, MAX_MUTATION_ROOTS, MAX_NODE_ID, MAX_PENDING_EVENTS, MAX_DEPTH, MAX_NODES, MAX_SEQUENCE, RECORDER_VERSION, ZERO_HASH, CanonicalText, canonicalJSON, captureAllowed, isOpaqueWidget, quantize, sha256Hex} from "./policy.ts";
import {captureDomAccessors, fitSubtrees, newWalkState, nodeBytes, walk, type DomGlobals} from "./tree.ts";

/** The canonical JSON (keys in code unit order) of a node array the recorder built: every value is a decimal or a closed-vocabulary string, so no value needs escaping. Equals canonicalJSON(nodes). */
function canonicalNodes(nodes: readonly ReplayNode[]): string {
 let out = "[";
 for (let i = 0; i < nodes.length; i++) { const n = nodes[i]!; out += (i === 0 ? "" : ",") + '{"class":"' + n.class + '","id":"' + n.id + '","parent":"' + n.parent + '","tag":"' + n.tag + '","text":"' + n.text + '"}'; }
 return out + "]";
}
/** The new children an append delta records under one node the replay holds: `born` is every node a child-list record added to it in the batch, `roots` the ones still attached, in document order. */
interface Appended { readonly id: number; readonly born: Set<object>; roots: readonly object[] }
/** Bytes of a chunk left for nodes beside these events and the one gap event a truncation adds. */
function chunkRoom(events: readonly ReplayEvent[]): number {
 let budget = GAP_EVENT_BYTES;
 for (const event of events) budget += JSON.stringify(event).length + 1;
 return Math.max(0, MAX_CHUNK_BYTES - budget);
}
const OBSERVE = {childList: true, characterData: true, attributes: true, subtree: true} as const;
const LISTEN = {capture: true, passive: true} as const;
const defaultTimers: ReplayTimers = {set: (callback, ms) => globalThis.setTimeout(callback, ms), clear: handle => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>)};

/**
 * Creates the owned recorder. Nothing observes, reads or allocates replay state until project
 * policy, deployment opt-in and explicit consent are all true.
 */
export function createRecorder(config: ReplayConfig, emit: (chunk: ReplayChunk) => EnqueueResult): ReplayRecorder {
 return new Recorder(config, emit);
}

class Recorder implements ReplayRecorder {
 private consent = false;
 private active = false;
 private closed = false;
 private dom: DomAccessors | undefined;
 private observer: MutationObserverLike | undefined;
 private target: ReplayEventTargetLike | undefined;
 private ids = new WeakMap<object, number>();
 private shadowRoots = new WeakSet<object>();
 /** Local ids of placeholders and the nodes they replaced; deltas under them are dropped until the next complete checkpoint. */
 private suppressed = new Set<number>();
 private counter = 0;
 private sequence = 0;
 private checkpoints = 0;
 /** The replay used its whole server-side budget (sequence or checkpoint ceiling); capture ended for good. */
 private exhausted = false;
 private previousHash = ZERO_HASH;
 private checkpointSequence = 0;
 private checkpointHash = ZERO_HASH;
 private loss = 0;
 private needGap = false;
 private pending: ReplayEvent[] = [];
 private flushTimer: unknown;
 private checkpointTimer: unknown;
 private recoverTimer: unknown;
 private readonly timers: ReplayTimers;
 private readonly listeners: ReadonlyArray<readonly [string, (event: object) => void]>;

 constructor(private readonly config: ReplayConfig, private readonly output: (chunk: ReplayChunk) => EnqueueResult) {
  if (typeof config.root !== "object" || config.root === null) throw Error("replay root required");
  for (const id of [config.replayId, config.sessionId, config.domain?.host, config.domain?.boot, config.domain?.runtime]) if (typeof id !== "string" || !/^[0-9a-f]{32}$/.test(id) || id === "0".repeat(32)) throw Error("replay identifiers must be 32 lowercase hex digits and not zero");
  if (typeof config.capturePolicyRevision !== "string" || !/^[1-9][0-9]{0,19}$/.test(config.capturePolicyRevision)) throw Error("replay capture policy revision must be a decimal revision");
  this.timers = config.timers ?? defaultTimers;
  this.listeners = [
   ["pointerdown", event => this.guard(() => { const dom = this.dom!; const node = dom.eventTarget(event); this.event("pointer", node === null ? 0 : this.ids.get(node) ?? 0, dom.clientX(event), dom.clientY(event)); })],
   ["scroll", () => this.guard(() => { const view = this.viewport(); this.event("scroll", 0, view.x, view.y); })],
   ["resize", () => this.guard(() => { const view = this.viewport(); this.event("resize", 0, view.w, view.h); })],
  ];
 }

 setConsent(enabled: boolean): void {
  if (this.closed) return;
  this.consent = enabled === true;
  if (!this.consent) { this.stop(); this.config.onRevoked?.(); return; }
  if (!this.active && captureAllowed(this.config.projectPolicy, this.config.deploymentOptIn, this.consent)) this.start();
 }
 close(): void {
  if (this.closed) return;
  this.consent = false; this.stop(); this.closed = true;
 }

 private viewport(): {w: number; h: number; x: number; y: number} {
  return this.config.viewport?.() ?? {w: 0, h: 0, x: 0, y: 0};
 }
 private guard(callback: () => void): void {
  if (!this.active) return;
  try { callback(); } catch { this.loss++; this.needGap = true; }
 }

 private start(): void {
  const dom = this.config.dom ?? captureDomAccessors(globalThis as unknown as DomGlobals);
  const Observer = this.config.observer ?? (globalThis as unknown as {MutationObserver?: new (callback: (records: readonly object[]) => void) => MutationObserverLike}).MutationObserver;
  if (Observer === undefined) throw Error("replay requires MutationObserver");
  if (this.exhausted) return;
  this.dom = dom; this.active = true;
  const observer = new Observer(records => this.mutations(records));
  this.observer = observer; observer.observe(this.config.root, OBSERVE);
  const ambient = globalThis as unknown as ReplayEventTargetLike;
  const target = this.config.eventTarget ?? (typeof ambient.addEventListener === "function" ? ambient : undefined);
  if (target !== undefined) { this.target = target; for (const [type, listener] of this.listeners) target.addEventListener(type, listener, LISTEN); }
  this.checkpoint();
  this.armCheckpoint();
 }

 /** Immediately and unconditionally destroys all replay state; ACKed chunks are not recalled. */
 private stop(): void {
  const wasActive = this.active;
  this.active = false;
  this.observer?.disconnect(); this.observer = undefined;
  if (this.target !== undefined) { for (const [type, listener] of this.listeners) this.target.removeEventListener(type, listener, LISTEN); this.target = undefined; }
  for (const handle of [this.flushTimer, this.checkpointTimer, this.recoverTimer]) if (handle !== undefined) this.timers.clear(handle);
  this.flushTimer = this.checkpointTimer = this.recoverTimer = undefined;
  this.pending = []; this.ids = new WeakMap(); this.shadowRoots = new WeakSet(); this.suppressed = new Set();
  try { this.dom?.release?.(); } catch { /* a page that re-wrapped the platform hook cannot make stop() throw */ }
  this.dom = undefined;
  if (wasActive) this.needGap = true;
 }

 /** Ids are unique per chunk and restart at every checkpoint (the id map is fresh there), so the server's id ceiling is never reached in practice; reaching it anyway counts as loss and a gap. */
 private allocate = (): number => { if (this.counter >= MAX_NODE_ID) throw Error("replay_node_id_space"); return ++this.counter; };
 private observeShadow = (root: object): void => {
  if (this.shadowRoots.has(root) || this.observer === undefined) return;
  this.shadowRoots.add(root); this.observer.observe(root, OBSERVE);
 };
 private now(): {readonly wall_ns: string; readonly mono_ns: string; readonly uncertainty_ns: string} { return this.config.clock(); }

 private event(kind: ReplayEvent["kind"], node: number, x: number, y: number): void {
  this.pending.push({at_ns: this.now().mono_ns, kind, node: String(node), x: quantize(x), y: quantize(y)});
  if (this.pending.length >= MAX_PENDING_EVENTS) { this.flushEvents(); return; }
  if (this.flushTimer === undefined) this.flushTimer = this.timers.set(() => { this.flushTimer = undefined; this.guard(() => this.flushEvents()); }, EVENT_FLUSH_MS);
 }
 private flushEvents(): void {
  if (this.flushTimer !== undefined) { this.timers.clear(this.flushTimer); this.flushTimer = undefined; }
  const events = this.pending; this.pending = [];
  if (events.length > 0) this.write([], events, false, false);
 }

 private armCheckpoint(): void {
  if (!this.active) return;
  this.checkpointTimer = this.timers.set(() => { this.checkpointTimer = undefined; this.guard(() => { this.flushEvents(); this.checkpoint(); this.armCheckpoint(); }); }, CHECKPOINT_INTERVAL_MS);
 }
 /** The replay has used its whole server-side budget: nothing beyond the server's closed schema is ever emitted, so capture ends for good. */
 private exhaust(): void {
  this.exhausted = true; this.stop();
 }

 /** Full snapshot: fresh ID map so no earlier source node stays associated with a local ID. */
 private checkpoint(): void {
  const dom = this.dom!;
  this.ids = new WeakMap(); this.shadowRoots = new WeakSet(); this.suppressed = new Set(); this.counter = 0;
  const state = newWalkState(this.ids, this.allocate, this.observeShadow);
  walk(dom, this.config.root, "0", state);
  const at = this.now().mono_ns, gap = this.needGap || state.overflow;
  if (state.overflow) this.loss++;
  const events: ReplayEvent[] = [{at_ns: at, kind: "checkpoint", node: "0", x: 0, y: 0}];
  if (gap) events.push({at_ns: at, kind: "gap", node: "0", x: 0, y: 0});
  this.needGap = false;
  this.write(state.nodes, events, true, gap);
 }

 /**
  * One observer callback. A node the replay holds that only gained new children (child-list records naming nothing the replay holds, the new
  * nodes ending the parent's children) is an append: the chunk carries the new subtrees once, each under its parent's id, and one `mutation`
  * event on the first of them (a node the viewer has never held, so it deletes nothing). Every other change is the re-walk of the nearest node
  * the replay holds: its chunk carries the whole subtree and its `mutation` event makes the viewer drop the old descendants first. Both are
  * recorder_version "1" chunks; no field or vocabulary of the wire changed.
  */
 private mutations(records: readonly object[]): void {
  this.guard(() => {
   const dom = this.dom!;
   if (records.length > MAX_MUTATION_RECORDS) { this.flushEvents(); this.needGap = true; this.checkpoint(); return; }
   const rewalk = new Map<number, object>(), appended = new Map<object, Appended>(), fresh = new Set<object>(), seen = new Set<object>(), below: object[] = [];
   let full = false;
   for (const record of records) {
    const change = dom.childListChange(record);
    let node = dom.mutationTarget(record);
    // The outcome of a record that only names its target is the same however many records name it, so each such target is attributed once.
    if (change === null && node !== null) { if (seen.has(node)) continue; seen.add(node); }
    if (node !== null && dom.nodeType(node) !== 1) {
     // A text node is its parent element's change; a detached one is not in the replay tree at all. Any other kind (document, shadow root, comment) cannot be attributed.
     if (dom.nodeType(node) === 3) { node = dom.parentNode(node); if (node === null) continue; } else node = null;
    }
    if (node === null) { full = true; break; }
    // Climb to the nearest node the replay already holds. Reaching the top of an element tree without finding one means the
    // target is detached (or outside the observed root): it is not in the replay tree, and whatever removed it from the tree is a
    // record of its own on a node the replay does hold. Only a top the recorder cannot account for (a shadow root, a climb cut
    // short by the depth bound) is an unknown it must not guess about.
    let top: object = node, reached: object | null = node, id: number | undefined;
    for (let hops = 0; reached !== null && (id = this.ids.get(reached)) === undefined && hops < MAX_DEPTH * 4; hops++) { top = reached; reached = dom.parentNode(reached); }
    if (reached === null) { const topType = dom.nodeType(top); if (topType === 1 || topType === 9) continue; full = true; break; }
    if (id === undefined) { full = true; break; }
    if (this.suppressed.has(id)) continue;
    // The target is unknown to the replay: `top` hangs directly under the node the replay holds. If `top` is one of the new nodes of an append, whatever happened below it is part of that subtree (read at the end of the batch).
    if (reached !== node) { below.push(top, reached); continue; }
    if (rewalk.has(id)) continue;
    if (change === null) { rewalk.set(id, node); }
    else if (!this.appendable(dom, node, appended, change)) { rewalk.set(id, node); appended.delete(node); }
    else {
     let group = appended.get(node);
     if (group === undefined) { group = {id, born: new Set(), roots: []}; appended.set(node, group); }
     for (const born of change.added) { group.born.add(born); fresh.add(born); }
    }
    if (rewalk.size + appended.size > MAX_MUTATION_ROOTS) { full = true; break; }
   }
   if (!full) {
    for (let i = 0; i < below.length && !full; i += 2) {
     if (fresh.has(below[i]!)) continue;
     const container = below[i + 1]!, id = this.ids.get(container)!;
     rewalk.set(id, container);
     if (rewalk.size + appended.size > MAX_MUTATION_ROOTS) full = true;
    }
   }
   if (!full) {
    // The new nodes must be exactly the trailing run of the parent's children, or the viewer (which adds new nodes after the ones it holds) would show another order.
    for (const [parent, group] of appended) {
     if (rewalk.has(group.id)) { appended.delete(parent); continue; }
     let live = 0;
     for (const born of group.born) if (dom.parentNode(born) === parent) live++;
     if (live === 0) { appended.delete(parent); continue; }
     const run: object[] = [];
     for (let child = dom.lastChild(parent); child !== null && group.born.has(child); child = dom.previousSibling(child)) run.push(child);
     if (run.length !== live) { rewalk.set(group.id, parent); appended.delete(parent); } else group.roots = run.reverse();
    }
   }
   if (full) { this.flushEvents(); this.checkpoint(); return; }
   if (rewalk.size === 0 && appended.size === 0) return;
   let built = this.delta(dom, rewalk, appended, fresh);
   // An append the chunk cannot hold is the re-walk of its parent, which the chunk fit collapses into a declared gap (an append has no parent node in the chunk to collapse).
   if (!built.restart && appended.size > 0 && !this.fits(built.nodes, built.events)) {
    for (const [parent, group] of appended) rewalk.set(group.id, parent);
    appended.clear();
    built = this.delta(dom, rewalk, appended, fresh);
   }
   if (built.restart) { this.flushEvents(); this.checkpoint(); return; }
   if (built.events.length === 0) return; // every changed node had left the tree: nothing the replay shows changed
   this.flushEvents();
   this.write(built.nodes, built.events, false, false);
  });
 }

 /** A node the replay holds whose new children may be recorded alone: it shows its children (no widget, input, editable or shadow root), and the record names nothing the replay holds (no removal, no move, no re-added node). */
 private appendable(dom: DomAccessors, node: object, appended: ReadonlyMap<object, Appended>, change: {readonly added: readonly object[]; readonly removed: readonly object[]}): boolean {
  for (const gone of change.removed) if (this.ids.has(gone)) return false;
  for (const born of change.added) if (this.ids.has(born)) return false;
  if (appended.has(node)) return true;
  return this.showsChildren(dom, node) && dom.openShadowRoot(node) === null;
 }

 /** An element the replay holds shows its children unless it is an input, a widget, editable or a closed shadow host: those are one node with nothing below it. */
 private showsChildren(dom: DomAccessors, element: object): boolean {
  const name = dom.localName(element);
  return name !== "input" && !isOpaqueWidget(name) && !dom.editable(element) && dom.closedShadow?.(element) !== true;
 }

 /** The nodes and events of the batch: the re-walks and then the appended subtrees. A node inside an ancestor's re-walk or inside a new subtree (a node the replay holds that was moved into one) is part of that walk. */
 private delta(dom: DomAccessors, rewalk: ReadonlyMap<number, object>, appended: ReadonlyMap<object, Appended>, fresh: ReadonlySet<object>): {readonly nodes: ReplayNode[]; readonly events: ReplayEvent[]; readonly restart: boolean} {
  // Running total: ids come from one counter that restarts only at a checkpoint, so every node of the live tree was allocated
  // since then and a delta may add at most MAX_NODES minus what the counter already holds. A delta that would pass the cap is
  // discarded for a fresh checkpoint, which recounts the live tree exactly (replaced and removed nodes no longer count): only a
  // live tree that itself reaches the cap ends up as an opaque placeholder plus a gap (walk's last-slot rule).
  const state = newWalkState(this.ids, this.allocate, this.observeShadow, Math.max(1, MAX_NODES - this.counter)), events: ReplayEvent[] = [], at = this.now().mono_ns;
  const covered = (node: object): boolean => {
   for (let up = dom.parentNode(node), hops = 0; up !== null && hops < MAX_DEPTH * 4; up = dom.parentNode(up), hops++) {
    const upId = this.ids.get(up);
    if (fresh.has(up) || upId !== undefined && rewalk.has(upId)) return true;
   }
   return false;
  };
  let unplaced = false;
  for (const [id, node] of rewalk) {
   if (covered(node)) continue;
   const parentId = this.placement(dom, node);
   if (parentId === undefined) continue;
   if (parentId === null) { unplaced = true; continue; }
   events.push({at_ns: at, kind: "mutation", node: String(id), x: 0, y: 0});
   walk(dom, node, parentId, state, 0, id);
  }
  for (const [parent, group] of appended) {
   if (rewalk.has(group.id) || covered(parent)) continue;
   const parentId = this.placement(dom, parent);
   if (parentId === undefined) continue;
   if (parentId === null) { unplaced = true; continue; }
   const first = state.nodes.length;
   for (const root of group.roots) walk(dom, root, String(group.id), state);
   if (state.nodes.length > first) events.push({at_ns: at, kind: "mutation", node: state.nodes[first]!.id, x: 0, y: 0});
  }
  return {nodes: state.nodes, events, restart: state.overflow || unplaced};
 }

 /**
  * The parent id a node the replay holds is shown under: "0" for the observed root and for the children of a document root; undefined when the node is not in
  * the replay tree (it left the tree, so a record on its old parent covers it, or it sits inside a region the replay shows nothing of: below a widget, an input or a placeholder);
  * null when the recorder cannot say (its parent is a shadow root, whose host the platform accessors do not name), which is a full checkpoint.
  */
 private placement(dom: DomAccessors, node: object): string | undefined | null {
  if (node === this.config.root) return "0";
  const parent = dom.parentNode(node);
  if (parent === null) return undefined;
  const id = this.ids.get(parent);
  if (id !== undefined) return this.showsChildren(dom, parent) ? String(id) : undefined;
  if (parent === this.config.root) return "0";
  return dom.nodeType(parent) === 11 ? null : undefined;
 }

 /** True when one chunk can hold these nodes and events without the chunk fit having to collapse anything. */
 private fits(nodes: readonly ReplayNode[], events: readonly ReplayEvent[]): boolean {
  if (nodes.length > MAX_CHUNK_NODES) return false;
  const room = chunkRoom(events);
  let total = 0;
  for (const node of nodes) total += nodeBytes(node);
  return total <= room;
 }

 /**
  * One emission is one chunk. Nodes that do not fit are never split into an undeclared fragmented format and never
  * truncated silently: whole low-priority subtrees become opaque placeholders (fitSubtrees), the truncation is reported
  * (loss counter plus a gap event; a truncated checkpoint is gap-marked) and deltas under the replaced ids are suppressed
  * until a new complete checkpoint.
  */
 private write(nodes: readonly ReplayNode[], events: readonly ReplayEvent[], checkpoint: boolean, gap: boolean): void {
  const room = chunkRoom(events);
 // The recorder builds every node itself, so its JSON size is the frame plus the value lengths: a chunk that fits needs no per-node JSON.stringify sizing.
 let totalBytes = 0;
 for (const node of nodes) totalBytes += nodeBytes(node);
 const fit = nodes.length <= MAX_CHUNK_NODES && totalBytes <= room ? {nodes, truncated: false, suppressed: []} : fitSubtrees(nodes, MAX_CHUNK_NODES, room);
  let emitted = events, marked = gap;
  // A node this chunk shows again (a re-walked subtree keeps its ids) is no longer collapsed: its deltas count again, unless the fit below collapses it once more.
  if (this.suppressed.size > 0) for (const node of fit.nodes) this.suppressed.delete(Number(node.id));
  if (fit.truncated) {
   for (const id of fit.suppressed) this.suppressed.add(id);
   this.loss++;
   if (!events.some(event => event.kind === "gap")) emitted = [...events, {at_ns: this.now().mono_ns, kind: "gap", node: "0", x: 0, y: 0}];
   marked = true; // a truncated delta is as lossy as a truncated checkpoint: its gap event and its chunk flag agree
  }
  if (this.sequence >= MAX_SEQUENCE || checkpoint && this.checkpoints >= MAX_CHECKPOINTS) { this.exhaust(); return; }
  const sequence = ++this.sequence;
  if (checkpoint) this.checkpoints++;
  const chunk: ReplayChunk = {
   replay_id: this.config.replayId, session_id: this.config.sessionId, recorder_version: RECORDER_VERSION, sequence: String(sequence), previous_hash: this.previousHash,
   checkpoint_sequence: String(checkpoint ? sequence : this.checkpointSequence), checkpoint_hash: checkpoint ? this.previousHash : this.checkpointHash,
   clock: {...this.now(), domain: this.config.domain}, nodes: fit.nodes, events: emitted, loss: String(this.loss), gap: marked, capture_policy_revision: this.config.capturePolicyRevision,
  };
  const hash = sha256Hex(canonicalJSON({...chunk, nodes: new CanonicalText(canonicalNodes(fit.nodes))}));
  if (checkpoint) { this.checkpointSequence = sequence; this.checkpointHash = hash; }
  this.previousHash = hash;
  let result: EnqueueResult;
  try { result = this.output(chunk); } catch { result = "rejected"; }
  if (result !== "accepted") this.fail();
 }
 /** A rejected chunk leaves a visible hole: counted loss, then a gap-marked checkpoint later. */
 private fail(): void {
  this.loss++; this.needGap = true;
  if (this.recoverTimer === undefined && this.active) this.recoverTimer = this.timers.set(() => { this.recoverTimer = undefined; this.guard(() => { this.flushEvents(); this.checkpoint(); }); }, EVENT_FLUSH_MS);
 }
}
