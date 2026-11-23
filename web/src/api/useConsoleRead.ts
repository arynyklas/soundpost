// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Scope-keyed reads of the console routes (console.ts). A read is held under the key it was requested for: a new key shows loading at once and
// aborts the old read, so a slow answer for an older scope can never paint a newer one. A route the installation does not serve yet is its own
// state (`not_built`): never an empty list and never zero.
import * as React from 'react';
import { isAbort, stateOfFault } from './client';
import type { ConsoleResult, ListEnvelope } from './console';
import type { LoadState } from './types';
import { latestOnly, type Latest } from '../app/context';

export type ConsoleState<T> =
 | { kind: 'loading' }
 | { kind: 'ok'; data: T }
 | { kind: 'not_built' }
 | { kind: 'fault'; state: LoadState<never> };

/** The state a settled console call is shown as. */
export function settleConsole<T>(result: ConsoleResult<T>): ConsoleState<T> {
 switch (result.kind) {
  case 'ok': return { kind: 'ok', data: result.data };
  case 'not_built': return { kind: 'not_built' };
  case 'fault': return { kind: 'fault', state: stateOfFault(result.fault) };
 }
}

/** One read of a console route, keyed. `reload` re-reads the same key and keeps what is on screen until the new answer arrives. */
export function useConsoleRead<T>(key: string, load: (signal: AbortSignal) => Promise<ConsoleResult<T>>): { state: ConsoleState<T>; reload: () => void; reloading: boolean } {
 const [held, setHeld] = React.useState<{ key: string; state: ConsoleState<T> }>({ key: '', state: { kind: 'loading' } });
 const [reloading, setReloading] = React.useState(false);
 const latest = React.useRef<Latest>(latestOnly());
 const run = (initial: boolean): void => {
  const read = latest.current.begin();
  if (initial) setHeld({ key, state: { kind: 'loading' } }); else setReloading(true);
  load(read.signal).then(
   (result) => { if (read.current()) { setHeld({ key, state: settleConsole(result) }); setReloading(false); } },
   (error: unknown) => { if (read.current() && !isAbort(error)) { setHeld({ key, state: { kind: 'fault', state: stateOfFault(error) } }); setReloading(false); } },
  );
 };
 React.useEffect(() => {
  run(true);
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return { state: held.key === key ? held.state : { kind: 'loading' }, reload: () => run(false), reloading };
}

/** The items shown after the first page and the pages that followed it. */
export function appendUnique<I>(shown: readonly I[], page: readonly I[], keyOf: (item: I) => string): I[] {
 const have = new Set(shown.map(keyOf));
 return [...shown, ...page.filter((item) => !have.has(keyOf(item)))];
}

interface More<I> { base: ListEnvelope<I>; items: I[]; next: string | undefined; more: boolean; fault: LoadState<never> | null; notBuilt: boolean; busy: boolean }

export interface PagedList<I> {
 state: ConsoleState<ListEnvelope<I>>;
 /** The first page and every page loaded after it, each item once. */
 items: I[];
 /** The server says more items follow what is shown. */
 more: boolean;
 busy: boolean;
 /** A later page failed: the items already shown stay. */
 moreFault: LoadState<never> | null;
 loadMore: () => void;
 reload: () => void;
 reloading: boolean;
}

/** A cursor-paged list. Pages after the first belong to the first page they follow: when a new first page arrives they are dropped and "Load more" starts again from it. */
export function usePagedList<I>(key: string, keyOf: (item: I) => string, load: (cursor: string | undefined, signal: AbortSignal) => Promise<ConsoleResult<ListEnvelope<I>>>): PagedList<I> {
 const first = useConsoleRead<ListEnvelope<I>>(key, (signal) => load(undefined, signal));
 const [extra, setExtra] = React.useState<More<I> | null>(null);
 const latest = React.useRef<Latest>(latestOnly());
 React.useEffect(() => () => latest.current.stop(), [key]);
 const base = first.state.kind === 'ok' ? first.state.data : undefined;
 const mine = base !== undefined && extra !== null && extra.base === base ? extra : null;
 const items = base === undefined ? [] : mine === null ? base.items : appendUnique(base.items, mine.items, keyOf);
 const next = mine !== null ? mine.next : base?.nextCursor;
 const more = base !== undefined && (mine !== null ? mine.more : base.more) && next !== undefined;
 const loadMore = (): void => {
  if (base === undefined || next === undefined || mine?.busy === true) return;
  const prior = mine?.items ?? [];
  const read = latest.current.begin();
  setExtra({ base, items: prior, next, more: true, fault: null, notBuilt: false, busy: true });
  load(next, read.signal).then(
   (result) => {
    if (!read.current()) return;
    if (result.kind === 'ok') setExtra({ base, items: appendUnique(prior, result.data.items, keyOf), next: result.data.nextCursor, more: result.data.more, fault: null, notBuilt: false, busy: false });
    else setExtra({ base, items: prior, next, more: true, fault: result.kind === 'fault' ? stateOfFault(result.fault) : null, notBuilt: result.kind === 'not_built', busy: false });
   },
   (error: unknown) => { if (read.current() && !isAbort(error)) setExtra({ base, items: prior, next, more: true, fault: stateOfFault(error), notBuilt: false, busy: false }); },
  );
 };
 return { state: first.state, items, more, busy: mine?.busy === true, moreFault: mine?.fault ?? null, loadMore, reload: first.reload, reloading: first.reloading };
}
