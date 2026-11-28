// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {MAX_NODES} from "./policy.ts";

/**
 * The order of the children the replay holds, as two columns indexed by node id: `tail[id]` is the id of the last child recorded under node `id` (0: none) and `prev[id]` the
 * id of the child recorded just before `id` under the same parent (0: first). They are written as the nodes are walked (the walk is in document order), so they are the
 * replay's own list of children without an object or a list per element. A new batch checks an append against them at its end: the last children of the target, read from the
 * page, must be the replay's last children followed only by nodes the replay does not hold, which is what lets the recorder skip a record's `addedNodes`/`removedNodes`.
 * Ids are small (the live-tree cap bounds them), so the columns are dense typed arrays that are reused for every epoch of ids.
 */
export class Links {
 tail = new Uint32Array(1024);
 prev = new Uint32Array(1024);

 private room(id: number): void {
  if (id < this.tail.length) return;
  // An id past the cap cannot come from a walk (walks stop at MAX_NODES); a corrupt one must not allocate gigabytes.
  if (id > MAX_NODES + 1024) throw Error("replay_node_id_space");
  let size = this.tail.length;
  while (size <= id) size *= 2;
  const tail = new Uint32Array(size), prev = new Uint32Array(size);
  tail.set(this.tail); prev.set(this.prev);
  this.tail = tail; this.prev = prev;
 }
 /** Node `id` was (re)written into the table: it has no recorded child yet; its children follow. */
 open(id: number): void { this.room(id); this.tail[id] = 0; }
 /** `child` is now the last recorded child of `parent`. */
 link(parent: number, child: number): void {
  this.room(parent > child ? parent : child);
  this.prev[child] = this.tail[parent]!; this.tail[parent] = child;
 }
}
