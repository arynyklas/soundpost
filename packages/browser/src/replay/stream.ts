// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {EnqueueResult, ReplayChunk} from "./types.ts";

/**
 * Bounded single-consumer chunk stream shared by the recorder (producer) and the renderer.
 * A full buffer rejects the chunk instead of dropping older ones, so the producer sees the
 * loss and marks a gap; the stream never fabricates continuity.
 */
export class ReplayStream implements AsyncIterable<ReplayChunk> {
 private readonly buffer: ReplayChunk[] = [];
 private waiting: ((result: IteratorResult<ReplayChunk>) => void) | undefined;
 private ended = false;
 constructor(private readonly capacity = 64) {
  if (!Number.isInteger(capacity) || capacity < 1 || capacity > 4096) throw Error("invalid replay stream capacity");
 }
 /** Producer entry: matches the recorder `emit` signature. */
 readonly push = (chunk: ReplayChunk): EnqueueResult => {
  if (this.ended || this.buffer.length >= this.capacity) return "rejected";
  const waiting = this.waiting;
  if (waiting !== undefined) { this.waiting = undefined; waiting({done: false, value: chunk}); return "accepted"; }
  this.buffer.push(chunk);
  return "accepted";
 };
 /** Destroys unread chunks (consent revoked). Consumers already handed a chunk keep only that chunk. */
 clear(): void { this.buffer.length = 0; }
 get pending(): number { return this.buffer.length; }
 close(): void {
  this.ended = true; this.buffer.length = 0;
  const waiting = this.waiting;
  if (waiting !== undefined) { this.waiting = undefined; waiting({done: true, value: undefined}); }
 }
 [Symbol.asyncIterator](): AsyncIterator<ReplayChunk> {
  return {
   next: (): Promise<IteratorResult<ReplayChunk>> => {
    const value = this.buffer.shift();
    if (value !== undefined) return Promise.resolve({done: false, value});
    if (this.ended) return Promise.resolve({done: true, value: undefined});
    if (this.waiting !== undefined) return Promise.reject(Error("replay stream has one consumer"));
    return new Promise(resolve => { this.waiting = resolve; });
   },
   return: (): Promise<IteratorResult<ReplayChunk>> => { this.close(); return Promise.resolve({done: true, value: undefined}); },
  };
 }
}
