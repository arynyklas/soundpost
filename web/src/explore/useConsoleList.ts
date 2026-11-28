// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { ConsoleResult, ListEnvelope } from '../api/console';
import type { LoadState } from '../api/types';
import { latestOnly } from '../app/context';

/** What a list screen shows: loading, the route is not served by this installation, a fault, or the envelope the server answered. */
export type ListState<T> =
 | { kind: 'loading' }
 | { kind: 'not_built' }
 | { kind: 'fault'; state: LoadState<never> }
 | { kind: 'ready'; envelope: ListEnvelope<T> };

/** The one status an envelope states for itself, in the same vocabulary as every other view. A `not_available` list carries its reason (for example a separate grant) and no items: it is never an empty list. */
export function envelopeStatus(env: ListEnvelope<unknown>): LoadState<null> {
 const reason = env.reason ?? '';
 switch (env.state) {
  case 'ready': return { kind: 'ready', data: null };
  case 'empty': return { kind: 'empty', data: null };
  case 'incomplete': return { kind: 'incomplete', data: null, reason: reason === '' ? 'sections_not_available' : reason };
  case 'stale': return { kind: 'stale', data: null, reason: reason === '' ? 'freshness_stale' : reason };
  case 'not_available': return { kind: 'unsupported', reason: reason === '' ? 'not_available' : reason, data: null };
 }
}

/** The envelope after one more page: items appended in the server's order, the cursor and `more` of the newest page. */
export function appendPage<T>(env: ListEnvelope<T>, next: ListEnvelope<T>): ListEnvelope<T> {
 const { nextCursor: _old, ...rest } = env;
 return { ...rest, ...(next.nextCursor !== undefined ? { nextCursor: next.nextCursor } : {}), state: next.state, ...(next.reason !== undefined ? { reason: next.reason } : {}), items: [...env.items, ...next.items], more: next.more, sections: next.sections };
}

function toState<T>(result: ConsoleResult<ListEnvelope<T>>): ListState<T> {
 switch (result.kind) {
  case 'ok': return { kind: 'ready', envelope: result.data };
  case 'not_built': return { kind: 'not_built' };
  case 'fault': return { kind: 'fault', state: stateOfFault(result.fault) };
 }
}

/** Reads a console list keyed to the scope it was asked for: a new key shows loading at once and aborts the old read, so a slow answer for an older scope never paints a newer one. */
export function useConsoleList<T>(key: string, load: (cursor: string | undefined, signal: AbortSignal) => Promise<ConsoleResult<ListEnvelope<T>>>): { state: ListState<T>; loadMore: () => void; loadingMore: boolean } {
 const [held, setHeld] = React.useState<{ key: string; state: ListState<T> }>({ key: '', state: { kind: 'loading' } });
 const [loadingMore, setLoadingMore] = React.useState(false);
 const latest = React.useRef(latestOnly());
 React.useEffect(() => {
  const read = latest.current.begin();
  setHeld({ key, state: { kind: 'loading' } });
  setLoadingMore(false);
  load(undefined, read.signal).then(
   (result) => { if (read.current()) setHeld({ key, state: toState(result) }); },
   (error: unknown) => { if (read.current() && !isAbort(error)) setHeld({ key, state: { kind: 'fault', state: stateOfFault(error) } }); },
  );
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 const state: ListState<T> = held.key === key ? held.state : { kind: 'loading' };
 const loadMore = (): void => {
  if (state.kind !== 'ready' || state.envelope.nextCursor === undefined) return;
  const cursor = state.envelope.nextCursor;
  const read = latest.current.begin();
  setLoadingMore(true);
  load(cursor, read.signal).then(
   (result) => {
    if (!read.current()) return;
    setLoadingMore(false);
    if (result.kind === 'ok') setHeld((h) => (h.key === key && h.state.kind === 'ready' ? { key, state: { kind: 'ready', envelope: appendPage(h.state.envelope, result.data) } } : h));
    else setHeld({ key, state: toState(result) });
   },
   (error: unknown) => { if (read.current() && !isAbort(error)) { setLoadingMore(false); setHeld({ key, state: { kind: 'fault', state: stateOfFault(error) } }); } },
  );
 };
 return { state, loadMore, loadingMore };
}
