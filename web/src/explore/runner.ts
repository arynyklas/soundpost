// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { isAbort } from '../api/client';
import type { Latest } from '../app/context';

export type RunState<T> =
 | { kind: 'loading'; key: string }
 | { kind: 'done'; key: string; value: T }
 | { kind: 'failed'; key: string; error: unknown };

/** Runs one request so that only the latest one for the scope it was started for may ever publish. Beginning a run aborts the
 * previous request; a response (or failure) is published only while its run is still the latest AND `currentKey()` still equals
 * the `key` it was started for, so a slow answer for a previous query or a previous scope can never be painted. An abort is not
 * a failure. The returned promise settles when the request has, and never rejects. */
export async function runLatest<T>(latest: Latest, currentKey: () => string, key: string, call: (signal: AbortSignal) => Promise<T>, publish: (state: RunState<T>) => void): Promise<void> {
 publish({ kind: 'loading', key });
 const read = latest.begin();
 try {
  const value = await call(read.signal);
  if (read.current() && currentKey() === key) publish({ kind: 'done', key, value });
 } catch (error) {
  if (read.current() && currentKey() === key && !isAbort(error)) publish({ kind: 'failed', key, error });
 }
}
