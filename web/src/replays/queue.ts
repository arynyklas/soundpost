// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { ReplayItem, ReplayStream } from './model';

/** The hand-over between the network reader and the playback host. The reader pushes every released item; the host pulls on its own pace. clear() drops everything not yet pulled and ends the stream: nothing is delivered after it. */
export class ItemQueue implements ReplayStream {
 private items: ReplayItem[] = [];
 private waiting: ((r: IteratorResult<ReplayItem>) => void) | undefined;
 private closed = false;

 push(item: ReplayItem): void {
  if (this.closed) return;
  const resolve = this.waiting;
  if (resolve !== undefined) { this.waiting = undefined; resolve({ done: false, value: item }); } else this.items.push(item);
 }
 /** No more items will arrive; items already queued are still delivered. */
 close(): void {
  this.closed = true;
  const resolve = this.waiting;
  if (resolve !== undefined && this.items.length === 0) { this.waiting = undefined; resolve({ done: true, value: undefined }); }
 }
 /** Drops queued items and ends the stream at once (revocation, deletion, error, unmount). */
 clear(): void {
  this.items = [];
  this.closed = true;
  const resolve = this.waiting;
  this.waiting = undefined;
  resolve?.({ done: true, value: undefined });
 }
 get pending(): number { return this.items.length; }

 [Symbol.asyncIterator](): AsyncIterator<ReplayItem> {
  return {
   next: (): Promise<IteratorResult<ReplayItem>> => {
    const item = this.items.shift();
    if (item !== undefined) return Promise.resolve({ done: false, value: item });
    if (this.closed) return Promise.resolve({ done: true, value: undefined });
    return new Promise((resolve) => { this.waiting = resolve; });
   },
   return: (): Promise<IteratorResult<ReplayItem>> => { this.clear(); return Promise.resolve({ done: true, value: undefined }); },
  };
 }
}
