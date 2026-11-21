// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { discover, stateOfQueryFault } from '../api/client';
import { DISCOVER_KINDS, type DiscoverKind, type DiscoverSignal, type DiscoveryRequest, type DiscoveryResult, type LoadState, type QueryLanguage } from '../api/types';
import { latestOnly, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { runLatest } from './runner';

/** The most names kept in the page at once; more pages stop being offered beyond it, and the page says so. */
const MAX_HELD = 2000;
const KIND_LABEL: Record<DiscoverKind, string> = { metric_names: 'Metric names', label_names: 'Label names', label_values: 'Label values', templates: 'Log templates', fields: 'Template fields' };

interface Held { key: string; items: string[]; next: string | null; capped: boolean; status: LoadState<DiscoveryResult> }

function statusOf(result: DiscoveryResult, total: number): LoadState<DiscoveryResult> {
 switch (result.freshness.completeness) {
  case 'partial': return { kind: 'incomplete', data: result, reason: 'shards_missing' };
  case 'stale': return { kind: 'stale', data: result, reason: 'freshness_stale' };
  default: return total === 0 ? { kind: 'empty', data: result } : { kind: 'ready', data: result };
 }
}

/** Own paginated discovery of names: one authenticated page at a time, exact (every matching row is read), with a cursor that is
 * bound to the parameters that produced it. Changing a parameter or the scope forgets the list; a stale page never replaces a new one. */
export function Discovery(props: { context: ViewContext; language: QueryLanguage; projects: string[]; source: string; onInsert: (text: string) => void }): React.JSX.Element {
 const { context, language, projects, source } = props;
 const signal: DiscoverSignal = language === 'promql' ? 'metric' : 'log';
 const kinds = DISCOVER_KINDS[signal];
 const [chosen, setChosen] = React.useState<DiscoverKind>('label_names');
 const kind: DiscoverKind = kinds.includes(chosen) ? chosen : (kinds[0] ?? 'label_names');
 const [field, setField] = React.useState('');
 const [limit, setLimit] = React.useState('25');
 const [problem, setProblem] = React.useState('');
 const [held, setHeld] = React.useState<Held | null>(null);
 const latest = React.useRef(latestOnly());
 const scope = `${scopeKey(context)}|${context.generation}`;
 const fieldNow = kind === 'label_values' ? field : '';
 const key = JSON.stringify([scope, signal, kind, fieldNow, limit, projects, source]);
 const keyRef = React.useRef(key);
 keyRef.current = key;
 const view = held !== null && held.key === key ? held : null;
 React.useEffect(() => () => latest.current.stop(), [key]);

 const load = (more: boolean): void => {
  const size = /^[1-9][0-9]{0,3}$/.test(limit) ? Number(limit) : 0;
  if (size < 1 || size > 1000) return setProblem('The page size must be a whole number from 1 to 1000.');
  if (kind === 'label_values' && (field.trim() === '' || field.length > 256)) return setProblem('Enter the label name whose values to list.');
  if (projects.length === 0) return setProblem('Select at least one project.');
  setProblem('');
  const previous = more && view !== null ? view : null;
  const req: DiscoveryRequest = {
   org: context.org, projects, signal, kind, matchers: [], time: { start: context.start, end: context.end }, limit: size,
   ...(fieldNow !== '' ? { field: fieldNow } : {}), ...(previous?.next ? { cursor: previous.next } : {}), ...(source !== '' ? { permission: 'raw.read' as const, source } : {}),
  };
  void runLatest(latest.current, () => keyRef.current, key, (s) => discover(req, s), (state) => {
   if (state.kind === 'loading') setHeld({ key, items: previous?.items ?? [], next: null, capped: previous?.capped ?? false, status: { kind: 'loading' } });
   else if (state.kind === 'done') {
    const all = [...(previous?.items ?? []), ...state.value.items];
    const capped = all.length > MAX_HELD;
    const items = capped ? all.slice(0, MAX_HELD) : all;
    setHeld({ key, items, next: state.value.more && !capped ? state.value.next_cursor ?? null : null, capped, status: statusOf(state.value, items.length) });
   } else setHeld({ key, items: previous?.items ?? [], next: null, capped: previous?.capped ?? false, status: stateOfQueryFault(state.error) });
  });
 };
 const insertText = (item: string): string => (kind === 'label_values' ? JSON.stringify(item) : item);
 const canInsert = kind === 'metric_names' || kind === 'label_names' || kind === 'label_values';
 return (
  <section className="panel" aria-labelledby="discover-heading" data-section="discovery">
   <h3 id="discover-heading">Discover names</h3>
   <p>Names are read through your own scope for the selected projects and window. A page cursor is bound to exactly these parameters: changing any of them starts over.</p>
   <form aria-label="Discover names" onSubmit={(e) => { e.preventDefault(); load(false); }}>
    <div className="field-row">
     <label>Kind <select value={kind} onChange={(e) => setChosen(e.target.value as DiscoverKind)}>{kinds.map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}</select></label>
     <label>Label name (for label values) <input value={fieldNow} onChange={(e) => setField(e.target.value)} disabled={kind !== 'label_values'} autoComplete="off" spellCheck={false} /></label>
     <label>Page size (1 to 1000) <input value={limit} onChange={(e) => setLimit(e.target.value)} inputMode="numeric" autoComplete="off" /></label>
    </div>
    <button type="submit">List names</button>
   </form>
   {problem && <p role="alert" className="error">{problem}</p>}
   {view !== null && <StatusPanel state={view.status} />}
   {view !== null && view.items.length > 0 && (
    <ul className="discovery-items" data-testid="discovery-items" aria-label={`${KIND_LABEL[kind]}, ${view.items.length} loaded`}>
     {view.items.map((item) => <li key={item}><code>{item}</code>{canInsert && <> <button type="button" onClick={() => props.onInsert(insertText(item))}>Insert into the query</button></>}</li>)}
    </ul>
   )}
   {view !== null && view.capped && <p role="status" className="banner">Only the first {MAX_HELD} names are held here; narrow the window or the projects to see the rest.</p>}
   {view !== null && view.next !== null && view.status.kind !== 'loading' && <button type="button" onClick={() => load(true)}>Load the next page ({view.items.length} loaded)</button>}
  </section>
 );
}
