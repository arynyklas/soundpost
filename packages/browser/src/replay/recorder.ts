// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {DomAccessors, EnqueueResult, MutationObserverLike, ReplayChunk, ReplayConfig, ReplayEvent, ReplayEventTargetLike, ReplayNode, ReplayRecorder, ReplayTimers} from "./types.ts";
import {CHECKPOINT_INTERVAL_MS, EVENT_FLUSH_MS, MAX_CHUNK_BYTES, MAX_MUTATION_RECORDS, MAX_MUTATION_ROOTS, MAX_PENDING_EVENTS, MAX_DEPTH, RECORDER_VERSION, ZERO_HASH, captureAllowed, quantize, sha256Hex} from "./policy.ts";
import {captureDomAccessors, newWalkState, walk, type DomGlobals} from "./tree.ts";

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
 private counter = 0;
 private sequence = 0;
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
  this.pending = []; this.ids = new WeakMap(); this.shadowRoots = new WeakSet(); this.dom = undefined;
  if (wasActive) this.needGap = true;
 }

 private allocate = (): number => ++this.counter;
 private observeShadow = (root: object): void => {
  if (this.shadowRoots.has(root) || this.observer === undefined) return;
  this.shadowRoots.add(root); this.observer.observe(root, OBSERVE);
 };
 private now(): {readonly wall_ns: string; readonly mono_ns: string; readonly uncertainty_ns: string} { return this.config.clock(); }

 private event(kind: ReplayEvent["kind"], node: number, x: number, y: number): void {
  this.pending.push({at_ns: this.now().wall_ns, kind, node: String(node), x: quantize(x), y: quantize(y)});
  if (this.pending.length >= MAX_PENDING_EVENTS) { this.flushEvents(); return; }
  if (this.flushTimer === undefined) this.flushTimer = this.timers.set(() => { this.flushTimer = undefined; this.guard(() => this.flushEvents()); }, EVENT_FLUSH_MS);
 }
 private flushEvents(): void {
  if (this.flushTimer !== undefined) { this.timers.clear(this.flushTimer); this.flushTimer = undefined; }
  const events = this.pending; this.pending = [];
  if (events.length > 0) this.write([], events, false, false);
 }

 private armCheckpoint(): void {
  this.checkpointTimer = this.timers.set(() => { this.checkpointTimer = undefined; this.guard(() => { this.flushEvents(); this.checkpoint(); this.armCheckpoint(); }); }, CHECKPOINT_INTERVAL_MS);
 }

 /** Full snapshot: fresh ID map so no earlier source node stays associated with a local ID. */
 private checkpoint(): void {
  const dom = this.dom!;
  this.ids = new WeakMap(); this.shadowRoots = new WeakSet();
  const state = newWalkState(this.ids, this.allocate, this.observeShadow);
  walk(dom, this.config.root, "0", state);
  const at = this.now().wall_ns, gap = this.needGap || state.overflow;
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
   const dirty = new Map<number, object>();
   let full = false;
   for (const record of records) {
    let node = dom.mutationTarget(record);
    if (node !== null && dom.nodeType(node) !== 1) node = dom.nodeType(node) === 3 ? dom.parentNode(node) : null;
    for (let hops = 0; node !== null && !this.ids.has(node) && hops < MAX_DEPTH * 4; hops++) node = dom.parentNode(node);
    const id = node === null ? undefined : this.ids.get(node);
    if (node === null || id === undefined) { full = true; break; }
    dirty.set(id, node);
    if (dirty.size > MAX_MUTATION_ROOTS) { full = true; break; }
   }
   if (full) { this.flushEvents(); this.checkpoint(); return; }
   const state = newWalkState(this.ids, this.allocate, this.observeShadow), events: ReplayEvent[] = [], at = this.now().wall_ns;
   for (const [id, node] of dirty) {
    let covered = false;
    for (let up = dom.parentNode(node), hops = 0; up !== null && hops < MAX_DEPTH * 4; up = dom.parentNode(up), hops++) { const upId = this.ids.get(up); if (upId !== undefined && dirty.has(upId)) { covered = true; break; } }
    if (covered) continue;
    const parent = dom.parentNode(node), parentId = parent === null ? undefined : this.ids.get(parent);
    events.push({at_ns: at, kind: "mutation", node: String(id), x: 0, y: 0});
    walk(dom, node, parentId === undefined ? "0" : String(parentId), state, 0, id);
   }
   if (state.overflow) { this.loss++; events.push({at_ns: at, kind: "gap", node: "0", x: 0, y: 0}); }
   this.flushEvents();
   this.write(state.nodes, events, false, state.overflow);
  });
 }

 /** Splits nodes into chunks bounded by count and bytes, chaining sequence and hashes. */
 private write(nodes: readonly ReplayNode[], events: readonly ReplayEvent[], checkpoint: boolean, gap: boolean): void {
  let index = 0, first = true, budgetUsed = 0;
  for (const event of events) budgetUsed += JSON.stringify(event).length;
  do {
   const group: ReplayNode[] = [];
   let bytes = budgetUsed;
   while (index < nodes.length) {
    const size = JSON.stringify(nodes[index]).length + 1;
    if (group.length > 0 && bytes + size > MAX_CHUNK_BYTES) break;
    bytes += size; group.push(nodes[index]!); index++;
   }
   const sequence = ++this.sequence, isCheckpoint = checkpoint && first;
   const chunk: ReplayChunk = {
    replay_id: this.config.replayId, session_id: this.config.sessionId, recorder_version: RECORDER_VERSION, sequence: String(sequence), previous_hash: this.previousHash,
    checkpoint_sequence: String(isCheckpoint ? sequence : this.checkpointSequence), checkpoint_hash: isCheckpoint ? this.previousHash : this.checkpointHash,
    clock: {...this.now(), domain: this.config.domain}, nodes: group, events: first ? events : [], loss: String(this.loss), gap: first && gap, capture_policy_revision: this.config.capturePolicyRevision,
   };
   const hash = sha256Hex(JSON.stringify(chunk));
   if (isCheckpoint) { this.checkpointSequence = sequence; this.checkpointHash = hash; }
   this.previousHash = hash;
   let result: EnqueueResult;
   try { result = this.output(chunk); } catch { result = "rejected"; }
   if (result !== "accepted") { this.fail(); return; }
   first = false; budgetUsed = 0;
  } while (index < nodes.length);
 }
 /** A rejected chunk leaves a visible hole: counted loss, then a gap-marked checkpoint later. */
 private fail(): void {
  this.loss++; this.needGap = true;
  if (this.recoverTimer === undefined && this.active) this.recoverTimer = this.timers.set(() => { this.recoverTimer = undefined; this.guard(() => { this.flushEvents(); this.checkpoint(); }); }, EVENT_FLUSH_MS);
 }
}
