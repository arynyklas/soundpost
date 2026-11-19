// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {DomAccessors, EnqueueResult, MutationObserverLike, ReplayChunk, ReplayConfig, ReplayEvent, ReplayEventTargetLike, ReplayNode, ReplayRecorder, ReplayTimers} from "./types.ts";
import {CHECKPOINT_INTERVAL_MS, EVENT_FLUSH_MS, GAP_EVENT_BYTES, MAX_CHECKPOINTS, MAX_CHUNK_BYTES, MAX_CHUNK_NODES, MAX_MUTATION_RECORDS, MAX_MUTATION_ROOTS, MAX_NODE_ID, MAX_PENDING_EVENTS, MAX_DEPTH, MAX_NODES, MAX_SEQUENCE, RECORDER_VERSION, ZERO_HASH, CanonicalText, canonicalJSON, captureAllowed, quantize, sha256Hex} from "./policy.ts";
import {captureDomAccessors, fitSubtrees, newWalkState, nodeBytes, walk, type DomGlobals} from "./tree.ts";

/** The canonical JSON (keys in code unit order) of a node array the recorder built: every value is a decimal or a closed-vocabulary string, so no value needs escaping. Equals canonicalJSON(nodes). */
function canonicalNodes(nodes: readonly ReplayNode[]): string {
 let out = "[";
 for (let i = 0; i < nodes.length; i++) { const n = nodes[i]!; out += (i === 0 ? "" : ",") + '{"class":"' + n.class + '","id":"' + n.id + '","parent":"' + n.parent + '","tag":"' + n.tag + '","text":"' + n.text + '"}'; }
 return out + "]";
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

 private mutations(records: readonly object[]): void {
  this.guard(() => {
   const dom = this.dom!;
   if (records.length > MAX_MUTATION_RECORDS) { this.flushEvents(); this.needGap = true; this.checkpoint(); return; }
   const dirty = new Map<number, object>(), seen = new Set<object>();
   let full = false;
   for (const record of records) {
    let node = dom.mutationTarget(record);
    // The outcome of a target is the same however many records name it, so each target is attributed once.
    if (node !== null) { if (seen.has(node)) continue; seen.add(node); }
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
    node = reached;
    if (this.suppressed.has(id)) continue;
    dirty.set(id, node);
    if (dirty.size > MAX_MUTATION_ROOTS) { full = true; break; }
   }
   if (full) { this.flushEvents(); this.checkpoint(); return; }
   if (dirty.size === 0) return;
   // Running total: ids come from one counter that restarts only at a checkpoint, so every node of the live tree was allocated
   // since then and a delta may add at most MAX_NODES minus what the counter already holds. A delta that would pass the cap is
   // discarded for a fresh checkpoint, which recounts the live tree exactly (replaced and removed nodes no longer count): only a
   // live tree that itself reaches the cap ends up as an opaque placeholder plus a gap (walk's last-slot rule).
   const state = newWalkState(this.ids, this.allocate, this.observeShadow, Math.max(1, MAX_NODES - this.counter)), events: ReplayEvent[] = [], at = this.now().mono_ns;
   for (const [id, node] of dirty) {
    let covered = false;
    for (let up = dom.parentNode(node), hops = 0; up !== null && hops < MAX_DEPTH * 4; up = dom.parentNode(up), hops++) { const upId = this.ids.get(up); if (upId !== undefined && dirty.has(upId)) { covered = true; break; } }
    if (covered) continue;
    const parent = dom.parentNode(node), parentId = parent === null ? undefined : this.ids.get(parent);
    // A node the replay holds that has left the tree (no parent, and not the root itself) was removed by a record on its old parent; re-walking it would hang it at the root of the replay.
    if (parent === null && node !== this.config.root) continue;
    events.push({at_ns: at, kind: "mutation", node: String(id), x: 0, y: 0});
    walk(dom, node, parentId === undefined ? "0" : String(parentId), state, 0, id);
   }
   if (state.overflow) { this.flushEvents(); this.checkpoint(); return; }
   if (events.length === 0) return; // every dirty node had left the tree: nothing the replay shows changed
   this.flushEvents();
   this.write(state.nodes, events, false, false);
  });
 }

 /**
  * One emission is one chunk. Nodes that do not fit are never split into an undeclared fragmented format and never
  * truncated silently: whole low-priority subtrees become opaque placeholders (fitSubtrees), the truncation is reported
  * (loss counter plus a gap event; a truncated checkpoint is gap-marked) and deltas under the replaced ids are suppressed
  * until a new complete checkpoint.
  */
 private write(nodes: readonly ReplayNode[], events: readonly ReplayEvent[], checkpoint: boolean, gap: boolean): void {
  let budget = GAP_EVENT_BYTES;
  for (const event of events) budget += JSON.stringify(event).length + 1;
  const room = Math.max(0, MAX_CHUNK_BYTES - budget);
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
