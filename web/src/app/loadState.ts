// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { ConsoleResult, ListEnvelope } from '../api/console';
import type { LoadState } from '../api/types';
import { latestOnly, scopeKey, type Latest, type ViewContext } from './context';

/** Maps a console list answer to the one closed set of states every view shows separately: an unserved route is `unsupported` (reason `not_built`), never an empty list. */
export function stateOfConsole<T>(result: ConsoleResult<ListEnvelope<T>>): LoadState<ListEnvelope<T>> {
 if (result.kind === 'not_built') return { kind: 'unsupported', reason: 'not_built' };
 if (result.kind === 'fault') return stateOfFault(result.fault);
 const env = result.data;
 switch (env.state) {
  case 'ready': return env.items.length === 0 ? { kind: 'empty', data: env } : { kind: 'ready', data: env };
  case 'empty': return { kind: 'empty', data: env };
  case 'incomplete': return { kind: 'incomplete', data: env, reason: env.reason ?? 'incomplete' };
  case 'stale': return { kind: 'stale', data: env, reason: env.reason ?? 'stale' };
  case 'not_available': return { kind: 'unsupported', reason: env.reason ?? 'not_available', data: env };
 }
}

/** Loads something for the scope. The held answer is keyed to the scope (and refresh generation) it was requested for: a change of scope shows loading at once, aborts
 * the old read, and an answer for an older scope can never paint. */
export function useScoped<T>(context: ViewContext, name: string, load: (signal: AbortSignal) => Promise<LoadState<T>>): LoadState<T> {
 const key = `${scopeKey(context)}|${name}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; state: LoadState<T> }>({ key: '', state: { kind: 'loading' } });
 const latest = React.useRef<Latest>(latestOnly());
 React.useEffect(() => {
  const read = latest.current.begin();
  setHeld({ key, state: { kind: 'loading' } });
  load(read.signal).then(
   (state) => { if (read.current()) setHeld({ key, state }); },
   (error: unknown) => { if (read.current() && !isAbort(error)) setHeld({ key, state: stateOfFault(error) }); },
  );
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return held.key === key ? held.state : { kind: 'loading' };
}
