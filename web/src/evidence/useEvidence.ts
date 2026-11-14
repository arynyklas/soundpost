// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { LoadState, ViewState } from '../api/types';
import { latestOnly, type Latest } from '../app/context';

/** Maps a server view to the one load state it may be shown as; not_available is an explicit unsupported state that keeps the view (its sections say what is missing), never an empty success. */
export function stateOfEvidence<V extends { state: ViewState; reason?: string }>(view: V): LoadState<V> {
 switch (view.state) {
  case 'ready': return { kind: 'ready', data: view };
  case 'empty': return { kind: 'empty', data: view };
  case 'incomplete': return { kind: 'incomplete', data: view, reason: view.reason ?? 'incomplete' };
  case 'stale': return { kind: 'stale', data: view, reason: view.reason ?? 'stale' };
  case 'not_available': return { kind: 'unsupported', reason: view.reason ?? 'not_available', data: view };
 }
}

/** The data of a state that may carry some. */
export function dataOf<T>(state: LoadState<T>): T | undefined {
 return 'data' in state ? state.data : undefined;
}

/** Loads one evidence view keyed to the scope and target it was requested for. A new key shows loading at once and aborts the old read, so a slow answer for an older scope can never paint a newer one. `reload` re-reads the same key and keeps what is on screen until the server answers; a reload that is refused clears it. */
export function useEvidence<V extends { state: ViewState; reason?: string }>(key: string, load: (signal: AbortSignal) => Promise<V>): { state: LoadState<V>; reload: () => void; reloading: boolean } {
 const [held, setHeld] = React.useState<{ key: string; state: LoadState<V> }>({ key: '', state: { kind: 'loading' } });
 const [reloading, setReloading] = React.useState(false);
 const latest = React.useRef<Latest>(latestOnly());
 const run = (initial: boolean): void => {
  const read = latest.current.begin();
  if (initial) setHeld({ key, state: { kind: 'loading' } }); else setReloading(true);
  load(read.signal).then(
   (view) => { if (read.current()) { setHeld({ key, state: stateOfEvidence(view) }); setReloading(false); } },
   (error: unknown) => { if (read.current() && !isAbort(error)) { setHeld({ key, state: stateOfFault(error) }); setReloading(false); } },
  );
 };
 React.useEffect(() => {
  run(true);
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return { state: held.key === key ? held.state : { kind: 'loading' }, reload: () => run(false), reloading };
}
