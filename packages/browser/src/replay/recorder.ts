// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {DomAccessors, EnqueueResult, MutationObserverLike, ReplayChunk, ReplayConfig, ReplayEvent, ReplayEventTargetLike, ReplayNode, ReplayRecorder, ReplayTimers} from "./types.ts";
import {CHECKPOINT_INTERVAL_MS, EVENT_FLUSH_MS, GAP_EVENT_BYTES, MAX_CHECKPOINTS, MAX_CHUNK_BYTES, MAX_CHUNK_NODES, MAX_MUTATION_RECORDS, MAX_MUTATION_ROOTS, MAX_NODE_ID, MAX_PENDING_EVENTS, MAX_DEPTH, MAX_NODES, MAX_SEQUENCE, PREPARE_HEADROOM, PREPARE_RESTARTS, PREPARE_SLICE_NODES, RECORDER_VERSION, ZERO_HASH, CanonicalText, canonicalJSON, captureAllowed, isCustomElementName, isOpaqueWidget, isSkipped, quantize, sha256ChunkHex} from "./policy.ts";
import {captureDomAccessors, fitSubtrees, newWalkState, resetWalkState, walk, Walker, type DomGlobals, type FitResult, type WalkState} from "./tree.ts";
import {NodeTable, type Nodes} from "./nodes.ts";
import {Links} from "./links.ts";

/** Stands for the node array in the chunk text whose hash is taken: the text is cut at it and the nodes are hashed straight from the table (`sha256ChunkHex`). No other text of a chunk can hold this control character unescaped. */
const NODES_AT = "\u0001";
/** No nodes: the table of a chunk that carries only events (never added to). */
const NO_NODES = new NodeTable();
/** Why capture starts late, from the platform's own `document` accessors (captured from the prototypes, so page-planted traps never run), or null when it started while the document was still loading with no body content yet. */
function detectLateStart(): string | null {
 const g = globalThis as unknown as {Document?: {prototype: object}; document?: object};
 if (g.document === undefined || g.Document === undefined) return null;
 const ready = Object.getOwnPropertyDescriptor(g.Document.prototype, "readyState")?.get, body = Object.getOwnPropertyDescriptor(g.Document.prototype, "body")?.get;
 if (ready === undefined || Reflect.apply(ready, g.document, []) !== "loading") return "document_ready_state";
 const content = body === undefined ? null : Reflect.apply(body, g.document, []) as {firstChild?: unknown} | null;
 return content !== null && content !== undefined && content.firstChild !== null && content.firstChild !== undefined ? "body_content_present" : null;
}
/** The frozen number columns behind each chunk this module emitted (the chunk's own `nodes` getter is their lazy object form). A consumer that only forwards the chunk (the core client's delivery) reads the nodes from here and never makes the objects. */
const NODE_COLUMNS = new WeakMap<ReplayChunk, Nodes>();
export function chunkNodes(chunk: ReplayChunk): Nodes | undefined { return NODE_COLUMNS.get(chunk); }
/** The new children an append delta records under one node the replay holds: `roots` the new children (nodes the replay does not hold, ending its children) in document order. A dropped group is `dead`. */
interface Appended { readonly id: number; readonly parent: object; roots: readonly object[]; dead: boolean }
const NO_ROOTS: readonly object[] = [];
/** An id-space checkpoint being prepared in slices: the second epoch of ids it builds (its own id map, shadow-root set, node table and child links), how far it is, and what its fit found. */
class Preparation {
 ids = new WeakMap<object, number>();
 roots = new WeakSet<object>();
 counter = 0;
 /** 0 not started, 1 walking, 2 walked (to be fitted), 3 fitted (to be written). */
 stage = 0;
 /** The page changed after the walk began. */
 dirty = false;
 restarts = 0;
 fit: FitResult | undefined;
 room = 0;
 readonly state: WalkState;
 constructor(readonly epoch: number, links: Links, observer: () => MutationObserverLike | undefined) {
  const allocate = (): number => { if (this.counter >= MAX_NODE_ID) throw Error("replay_node_id_space"); return ++this.counter; };
  const watch = (root: object): void => { const live = observer(); if (live === undefined || this.roots.has(root)) return; this.roots.add(root); live.observe(root, OBSERVE); };
  this.state = newWalkState(this.ids, allocate, watch, MAX_NODES, new NodeTable(), links);
 }
 /** Starts the walk over: no node, a fresh id map, shadow-root set and counter. */
 restart(): void {
  this.ids = new WeakMap(); this.roots = new WeakSet(); this.counter = 0; this.fit = undefined;
  resetWalkState(this.state, this.ids);
 }
}
/** Bytes of a chunk left for nodes beside these events and the one gap event a truncation adds. */
function chunkRoom(events: readonly ReplayEvent[]): number {
 let budget = GAP_EVENT_BYTES;
 for (let at = 0; at < events.length; at++) budget += JSON.stringify(events[at]).length + 1;
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
 private late: string | null | undefined;
 private pending: ReplayEvent[] = [];
 /** The one node table and walk state every walk of this recorder writes into (reset, never reallocated, between batches). */
 private readonly state: WalkState;
 /** Scratch of one observer callback (`batch`): owned by the recorder, emptied after every batch so a page node is never kept alive, and never reallocated. */
 private readonly rewalk = new Map<number, object>();
 private readonly rewalkIds: number[] = [];
 private readonly rewalkNodes: object[] = [];
 private readonly appended = new Map<object, Appended>();
 private readonly groups: Appended[] = [];
 private liveGroups = 0;
 private readonly fresh = new Set<object>();
 private readonly seen = new Set<object>();
 private readonly below: object[] = [];
 private readonly run: object[] = [];
 /** The id-space checkpoint being prepared between callbacks (see `considerPrepare`), the second child-link store it fills (the live one is swapped in when it is written), its walk, and the epoch of ids it belongs to. */
 private prepared: Preparation | undefined;
 private prepareTimer: unknown;
 private spareLinks: Links | undefined;
 private readonly preparedWalker = new Walker();
 private epoch = 0;
 /** Ids in use right after the last checkpoint: the live tree it recounted. */
 private epochBase = 0;
 /** A prepared checkpoint gave up this epoch (the page kept changing): the recount waits for the callback that reaches the cap. */
 private prepareHold = false;
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
  this.state = newWalkState(this.ids, this.allocate, this.observeShadow);
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
 lateStart(): string | null { return this.late ?? null; }
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
  if (this.late === undefined) {
   // D100: the supported install loads the recorder first in <head>. A start after the page has loaded cannot see closed shadow roots made before it, so it is recorded: the first checkpoint is gap-marked and lateStart() names the reason.
   try { this.late = this.config.lateStart?.() ?? detectLateStart(); } catch { this.late = "probe_failed"; }
   if (this.late !== null) this.needGap = true;
  }
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
  this.dropPrepared();
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
  if (events.length > 0) this.write(NO_NODES, events, false, false);
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
  this.dropPrepared();
  this.ids = new WeakMap(); this.shadowRoots = new WeakSet(); this.suppressed = new Set(); this.counter = 0;
  const state = this.state;
  resetWalkState(state, this.ids);
  walk(dom, this.config.root, 0, state);
  this.epoch++; this.epochBase = this.counter; this.prepareHold = false;
  const at = this.now().mono_ns, gap = this.needGap || state.overflow;
  if (state.overflow) this.loss++;
  const events: ReplayEvent[] = [{at_ns: at, kind: "checkpoint", node: "0", x: 0, y: 0}];
  if (gap) events.push({at_ns: at, kind: "gap", node: "0", x: 0, y: 0});
  this.needGap = false;
  this.write(state.nodes, events, true, gap);
 }

 /**
  * The recount an id-space checkpoint does (ids are unique since the last checkpoint and only a checkpoint recounts the live tree, so a delta that would pass the cap is replaced
  * by one, 5-8 ms for a few thousand nodes) is prepared ahead of the callback that would hit the cap: once `PREPARE_HEADROOM` ids are left, the page is walked into a second
  * epoch (own id map, node table and child links) in slices of `PREPARE_SLICE_NODES` nodes between the page's tasks, then fitted to one chunk, then written, each its own slice.
  * Deltas go on in the old epoch meanwhile; a batch that arrives after the walk began makes it stale, and it starts over (a few times, then the recount is left to the
  * callback that reaches the cap, as before). The chunk is an ordinary checkpoint: nothing about the wire or the replay's meaning changes, only when the work is done.
  */
 private considerPrepare(): void {
  if (this.prepared !== undefined || this.prepareHold || this.counter < MAX_NODES - PREPARE_HEADROOM || this.counter - this.epochBase < PREPARE_HEADROOM) return;
  this.spareLinks ??= new Links();
  this.prepared = new Preparation(this.epoch, this.spareLinks, () => this.observer);
  this.prepareTimer = this.timers.set(this.prepareStep, 0);
 }
 private prepareStep = (): void => {
  this.prepareTimer = undefined;
  const made = this.prepared;
  if (made === undefined || !this.active) return;
  if (made.epoch !== this.epoch) { this.dropPrepared(); return; }
  try {
   if (made.dirty) {
    made.dirty = false;
    if (++made.restarts > PREPARE_RESTARTS) { this.dropPrepared(); this.prepareHold = true; return; }
    made.stage = 0;
   }
   if (made.stage === 3) { this.guard(() => this.commitPrepared(made)); return; }
   if (made.stage === 0) { made.restart(); this.preparedWalker.begin(this.dom!, this.config.root, 0, made.state); made.stage = 1; }
   if (made.stage === 1) { if (this.preparedWalker.run(PREPARE_SLICE_NODES)) made.stage = 2; }
   else if (made.stage === 2) {
    // The fit is made for the events the chunk will carry: the checkpoint and, when the walk overflowed or a loss is already known, the gap.
    made.room = chunkRoom(this.checkpointEvents(this.now().mono_ns, this.needGap || made.state.overflow));
    made.fit = fitSubtrees(made.state.nodes, MAX_CHUNK_NODES, made.room);
    made.stage = 3;
   }
  } catch { this.dropPrepared(); this.prepareHold = true; return; }
  this.prepareTimer = this.timers.set(this.prepareStep, 0);
 };
 /** Makes the prepared epoch the live one and writes its checkpoint. A loss that happened since the fit (the gap event the chunk now needs takes room the fit did not leave) cancels it: the recount is then made as before. */
 private commitPrepared(made: Preparation): void {
  this.flushEvents();
  if (this.prepared !== made || !this.active) return;
  const at = this.now().mono_ns, gap = this.needGap || made.state.overflow, events = this.checkpointEvents(at, gap);
  if (chunkRoom(events) < made.room) { this.dropPrepared(); return; }
  const state = this.state;
  this.spareLinks = state.links; state.links = made.state.links;
  this.ids = made.ids; this.shadowRoots = made.roots; this.suppressed = new Set(); this.counter = made.counter;
  this.epoch++; this.epochBase = this.counter; this.prepareHold = false;
  this.prepared = undefined;
  if (made.state.overflow) this.loss++;
  this.needGap = false;
  this.write(made.state.nodes, events, true, gap, made.fit);
 }
 private checkpointEvents(at: string, gap: boolean): ReplayEvent[] {
  const events: ReplayEvent[] = [{at_ns: at, kind: "checkpoint", node: "0", x: 0, y: 0}];
  if (gap) events.push({at_ns: at, kind: "gap", node: "0", x: 0, y: 0});
  return events;
 }
 private dropPrepared(): void {
  if (this.prepareTimer !== undefined) { this.timers.clear(this.prepareTimer); this.prepareTimer = undefined; }
  this.preparedWalker.abandon();
  this.prepared = undefined;
 }

 /**
  * One observer callback. A node the replay holds that only gained new children (child-list records naming nothing the replay holds, the new
  * nodes ending the parent's children) is an append: the chunk carries the new subtrees once, each under its parent's id, and one `mutation`
  * event on the first of them (a node the viewer has never held, so it deletes nothing). Every other change is the re-walk of the nearest node
  * the replay holds: its chunk carries the whole subtree and its `mutation` event makes the viewer drop the old descendants first. Both are
  * recorder_version "1" chunks; no field or vocabulary of the wire changed.
  */
 private mutations(records: readonly object[]): void {
  // A prepared checkpoint that has begun walking the page is stale once the page changes (its slices run between the page's own tasks, so a change shows up as a batch here).
  if (this.prepared !== undefined && this.prepared.stage > 0) this.prepared.dirty = true;
  this.guard(() => {
   try { this.batch(this.dom!, records); } finally { this.releaseBatch(); }
   this.considerPrepare();
  });
 }

 /**
  * The work of one callback. Everything here runs in the observer callback, so it is written for the garbage collector: indexed loops (a `for...of`
  * allocates an iterator result per step until the engine compiles the loop, and a batch runs once), scratch arrays and maps the recorder owns and
  * empties after every batch, and no object per node.
  */
 private batch(dom: DomAccessors, records: readonly object[]): void {
  if (records.length > MAX_MUTATION_RECORDS) { this.flushEvents(); this.needGap = true; this.checkpoint(); return; }
  const rewalk = this.rewalk, appended = this.appended, fresh = this.fresh, seen = this.seen, below = this.below, groups = this.groups;
  let full = false;
  for (let at = 0; at < records.length; at++) {
   const record = records[at]!;
   const kind = dom.recordKind(record);
   let node = dom.mutationTarget(record);
   // The outcome of a record that only names its target is the same however many records name it, so each such target is attributed once.
   if (kind === "other" && node !== null) { if (seen.has(node)) continue; seen.add(node); }
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
   if (kind === "other") { this.addRewalk(id, node); }
   else if (kind === "inside" || !this.appendable(dom, node)) { this.addRewalk(id, node); const old = appended.get(node); if (old !== undefined) this.dropGroup(old); }
   else {
    let group = appended.get(node);
    if (group === undefined) { group = {id, parent: node, roots: NO_ROOTS, dead: false}; appended.set(node, group); groups.push(group); this.liveGroups++; }
   }
   if (this.rewalkIds.length + this.liveGroups > MAX_MUTATION_ROOTS) { full = true; break; }
  }
  if (!full) {
   // A parent's new children are a pure append when its children are the replay's followed by the new ones, or the viewer (which adds new nodes after the ones it holds) would show another order.
   for (let g = 0; g < groups.length; g++) {
    const group = groups[g]!;
    if (group.dead) continue;
    if (rewalk.has(group.id)) { this.dropGroup(group); continue; }
    if (!this.appendRun(dom, group)) { this.addRewalk(group.id, group.parent); this.dropGroup(group); } else if (group.roots.length === 0) this.dropGroup(group);
   }
  }
  if (!full) {
   for (let i = 0; i < below.length && !full; i += 2) {
    if (fresh.has(below[i]!)) continue;
    const container = below[i + 1]!;
    this.addRewalk(this.ids.get(container)!, container);
    if (this.rewalkIds.length + this.liveGroups > MAX_MUTATION_ROOTS) full = true;
   }
  }
  // A container re-read because of a change below a node it does not show covers its new children too.
  if (!full) for (let g = 0; g < groups.length; g++) { const group = groups[g]!; if (!group.dead && rewalk.has(group.id)) this.dropGroup(group); }
  if (full) { this.flushEvents(); this.checkpoint(); return; }
  if (this.rewalkIds.length === 0 && this.liveGroups === 0) return;
  let built = this.delta(dom);
  // An append the chunk cannot hold is the re-walk of its parent, which the chunk fit collapses into a declared gap (an append has no parent node in the chunk to collapse).
  if (!built.restart && this.liveGroups > 0 && !this.fits(built.nodes, built.events)) {
   for (let g = 0; g < groups.length; g++) { const group = groups[g]!; if (!group.dead) { this.addRewalk(group.id, group.parent); group.dead = true; } }
   appended.clear(); this.liveGroups = 0;
   built = this.delta(dom);
  }
  if (built.restart) { this.flushEvents(); this.checkpoint(); return; }
  if (built.events.length === 0) return; // every changed node had left the tree: nothing the replay shows changed
  this.flushEvents();
  this.write(built.nodes, built.events, false, false);
 }

 private addRewalk(id: number, node: object): void {
  if (this.rewalk.has(id)) return;
  this.rewalk.set(id, node); this.rewalkIds.push(id); this.rewalkNodes.push(node);
 }
 private dropGroup(group: Appended): void {
  if (group.dead) return;
  group.dead = true; this.appended.delete(group.parent); this.liveGroups--;
 }
 /** Empties the batch scratch: no page node stays referenced between callbacks. */
 private releaseBatch(): void {
  this.rewalk.clear(); this.rewalkIds.length = 0; this.rewalkNodes.length = 0;
  this.appended.clear(); this.groups.length = 0; this.liveGroups = 0;
  this.fresh.clear(); this.seen.clear(); this.below.length = 0; this.run.length = 0;
 }

 /** A node the replay holds whose new children may be recorded alone: it shows its children (no widget, input, editable or shadow root). A custom element is never appended to: while it had no children it may have been recorded as an inferred closed shadow host, which the child itself ends, so its record re-walks it. */
 private appendable(dom: DomAccessors, node: object): boolean {
  if (this.appended.has(node)) return true;
  return this.showsChildren(dom, node) && !isCustomElementName(dom.localName(node)) && dom.openShadowRoot(node) === null;
 }

 /**
  * Whether the children of `group.parent` are, at the end of the batch, exactly the ones the replay holds followed only by nodes it does not hold, and so whether those trailing
  * nodes are a pure append: that is read from the page's children, never from the records' `addedNodes`/`removedNodes` (a platform NodeList wrapper per record, most of what a
  * batch of appends still allocated). The replay's own order of the parent's children is `links`: its last child (`tail`) and each child's predecessor (`prev`). The check
  * reads the page back from the end: the unknown trailing children (the candidate roots, kept in `group.roots`, in document order), then the replay's children one by one, which must be the
  * same nodes in the same order, all the way down to the first one (a record names the tail, but one record can stand for a batch: Firefox reports `replaceChildren(...)` as ONE record whose
  * `nextSibling` is null although nodes were inserted before, or reordered among, the held children, so no older child can be assumed unmoved). An unknown node between known ones that the replay would show (text, or an element it does not skip) means an insertion or a move, which is the re-walk of the parent.
  * False: re-walk the parent. True with no roots: nothing the replay shows was added.
  */
 private appendRun(dom: DomAccessors, group: Appended): boolean {
  const ids = this.ids, run = this.run, links = this.state.links, parent = group.parent;
  run.length = 0;
  let child = dom.lastChild(parent);
  while (child !== null && !ids.has(child)) { run.push(child); child = dom.previousSibling(child); }
  let expected = links.tail[group.id]!;
  for (;;) {
   if ((child === null ? 0 : ids.get(child)!) !== expected) return false;
   if (expected === 0) break;
   expected = links.prev[expected]!;
   child = dom.previousSibling(child!);
   while (child !== null && !ids.has(child)) { if (this.shown(dom, child)) return false; child = dom.previousSibling(child); }
  }
  const count = run.length;
  if (count === 0) { group.roots = NO_ROOTS; return true; }
  const roots = new Array<object>(count);
  for (let i = 0; i < count; i++) { const node = run[i]!; roots[count - 1 - i] = node; this.fresh.add(node); }
  group.roots = roots;
  return true;
 }
 /** True for a node a walk would record (text, or an element it does not skip): an unknown one between the replay's children is a change the replay does not show. */
 private shown(dom: DomAccessors, node: object): boolean {
  const type = dom.nodeType(node);
  return type === 3 || type === 1 && !isSkipped(dom.localName(node));
 }

 /** An element the replay holds shows its children unless it is an input, a widget, editable or a closed shadow host: those are one node with nothing below it. */
 private showsChildren(dom: DomAccessors, element: object): boolean {
  const name = dom.localName(element);
  return name !== "input" && !isOpaqueWidget(name) && !dom.editable(element) && dom.closedShadow?.(element, name) !== true;
 }

 /** True when a re-walk of an ancestor, or a new subtree, already covers this node. */
 private covered(dom: DomAccessors, node: object): boolean {
  for (let up = dom.parentNode(node), hops = 0; up !== null && hops < MAX_DEPTH * 4; up = dom.parentNode(up), hops++) {
   const upId = this.ids.get(up);
   if (this.fresh.has(up) || upId !== undefined && this.rewalk.has(upId)) return true;
  }
  return false;
 }

 /** The nodes and events of the batch: the re-walks and then the appended subtrees. A node inside an ancestor's re-walk or inside a new subtree (a node the replay holds that was moved into one) is part of that walk. */
 private delta(dom: DomAccessors): {readonly nodes: NodeTable; readonly events: ReplayEvent[]; readonly restart: boolean} {
  // Running total: ids come from one counter that restarts only at a checkpoint, so every node of the live tree was allocated
  // since then and a delta may add at most MAX_NODES minus what the counter already holds. A delta that would pass the cap is
  // discarded for a fresh checkpoint, which recounts the live tree exactly (replaced and removed nodes no longer count): only a
  // live tree that itself reaches the cap ends up as an opaque placeholder plus a gap (walk's last-slot rule).
  const state = this.state, events: ReplayEvent[] = [], at = this.now().mono_ns, ids = this.rewalkIds, nodes = this.rewalkNodes, groups = this.groups;
  resetWalkState(state, this.ids, Math.max(1, MAX_NODES - this.counter));
  let unplaced = false;
  for (let i = 0; i < ids.length; i++) {
   const id = ids[i]!, node = nodes[i]!;
   if (this.covered(dom, node)) continue;
   const parentId = this.placement(dom, node);
   if (parentId === undefined) continue;
   if (parentId === null) { unplaced = true; continue; }
   events.push({at_ns: at, kind: "mutation", node: String(id), x: 0, y: 0});
   walk(dom, node, parentId, state, 0, id);
  }
  for (let g = 0; g < groups.length; g++) {
   const group = groups[g]!, parent = group.parent;
   if (group.dead || this.rewalk.has(group.id) || this.covered(dom, parent)) continue;
   const parentId = this.placement(dom, parent);
   if (parentId === undefined) continue;
   if (parentId === null) { unplaced = true; continue; }
   const first = state.nodes.length, roots = group.roots;
   for (let r = 0; r < roots.length; r++) {
    const before = state.nodes.length;
    walk(dom, roots[r]!, group.id, state);
    if (state.nodes.length > before) state.links.link(group.id, state.nodes.ids[before]!); // the new subtree is now the replay's last child here: the next batch checks its append against it
   }
   if (state.nodes.length > first) events.push({at_ns: at, kind: "mutation", node: String(state.nodes.ids[first]!), x: 0, y: 0});
  }
  return {nodes: state.nodes, events, restart: state.overflow || unplaced};
 }

 /**
  * The parent id a node the replay holds is shown under: "0" for the observed root and for the children of a document root; undefined when the node is not in
  * the replay tree (it left the tree, so a record on its old parent covers it, or it sits inside a region the replay shows nothing of: below a widget, an input or a placeholder);
  * null when the recorder cannot say (its parent is a shadow root, whose host the platform accessors do not name), which is a full checkpoint.
  */
 private placement(dom: DomAccessors, node: object): number | undefined | null {
  if (node === this.config.root) return 0;
  const parent = dom.parentNode(node);
  if (parent === null) return undefined;
  const id = this.ids.get(parent);
  if (id !== undefined) return this.showsChildren(dom, parent) ? id : undefined;
  if (parent === this.config.root) return 0;
  return dom.nodeType(parent) === 11 ? null : undefined;
 }

 /** True when one chunk can hold these nodes and events without the chunk fit having to collapse anything. */
 private fits(nodes: NodeTable, events: readonly ReplayEvent[]): boolean {
  return nodes.length <= MAX_CHUNK_NODES && nodes.bytes <= chunkRoom(events);
 }

 /**
  * One emission is one chunk. Nodes that do not fit are never split into an undeclared fragmented format and never
  * truncated silently: whole low-priority subtrees become opaque placeholders (fitSubtrees), the truncation is reported
  * (loss counter plus a gap event; a truncated checkpoint is gap-marked) and deltas under the replaced ids are suppressed
  * until a new complete checkpoint.
  */
 private write(nodes: NodeTable, events: readonly ReplayEvent[], checkpoint: boolean, gap: boolean, prefit?: FitResult): void {
  const room = chunkRoom(events);
  // The recorder records every node itself, so the table already knows their JSON size: a chunk that fits needs no sizing pass and no per-node JSON.stringify. A prepared checkpoint was fitted in its own slice.
  const fit = prefit ?? fitSubtrees(nodes, MAX_CHUNK_NODES, room);
  let emitted = events, marked = gap;
  // A node this chunk shows again (a re-walked subtree keeps its ids) is no longer collapsed: its deltas count again, unless the fit above collapsed it once more.
  if (this.suppressed.size > 0) for (let at = 0; at < nodes.length; at++) this.suppressed.delete(nodes.ids[at]!);
  if (fit.truncated) {
   for (const id of fit.suppressed) this.suppressed.add(id);
   this.loss++;
   if (!events.some(event => event.kind === "gap")) emitted = [...events, {at_ns: this.now().mono_ns, kind: "gap", node: "0", x: 0, y: 0}];
   marked = true; // a truncated delta is as lossy as a truncated checkpoint: its gap event and its chunk flag agree
  }
  if (this.sequence >= MAX_SEQUENCE || checkpoint && this.checkpoints >= MAX_CHECKPOINTS) { this.exhaust(); return; }
  const sequence = ++this.sequence;
  if (checkpoint) this.checkpoints++;
  const shell = {
   replay_id: this.config.replayId, session_id: this.config.sessionId, recorder_version: RECORDER_VERSION, sequence: String(sequence), previous_hash: this.previousHash,
   checkpoint_sequence: String(checkpoint ? sequence : this.checkpointSequence), checkpoint_hash: checkpoint ? this.previousHash : this.checkpointHash,
   clock: {...this.now(), domain: this.config.domain}, nodes: new CanonicalText(NODES_AT), events: emitted, loss: String(this.loss), gap: marked, capture_policy_revision: this.config.capturePolicyRevision,
  };
  const [before, after] = canonicalJSON(shell).split(NODES_AT) as [string, string];
  const hash = sha256ChunkHex(before, nodes, after);
  if (checkpoint) { this.checkpointSequence = sequence; this.checkpointHash = hash; }
  this.previousHash = hash;
  // The chunk keeps the nodes as numbers (a frozen copy of the table, which the next walk reuses); the objects of `chunk.nodes` are made on the first read, once (a viewer, the closed-wire check, JSON.stringify).
  const frozen = nodes.freeze();
  nodes.trim();
  let objects: readonly ReplayNode[] | undefined;
  const chunk: ReplayChunk = {...shell, get nodes(): readonly ReplayNode[] { return objects ??= frozen.toArray(); }};
  NODE_COLUMNS.set(chunk, frozen);
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
