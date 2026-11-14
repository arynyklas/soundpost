// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { exemplars, investigate, isAbort, stateOfFault, stateOfQueryFault } from '../api/client';
import type { Exemplar, ExemplarRequest, ExemplarResult, LoadState, QueryLanguage } from '../api/types';
import { latestOnly, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { LabelText, SampleValue, TimeText } from './MetricResult';
import { runLatest } from './runner';

/** Whether the server resolves a trace for this reader. A link exists only after the scope-resolved link route says so. */
type LinkState = { kind: 'unchecked' } | { kind: 'checking' } | { kind: 'available'; project: string; trace: string } | { kind: 'not_found' } | { kind: 'failed'; code: string };

function TraceLink(props: { exemplar: Exemplar; context: ViewContext }): React.JSX.Element {
 const { exemplar, context } = props;
 const [link, setLink] = React.useState<LinkState>({ kind: 'unchecked' });
 const latest = React.useRef(latestOnly());
 React.useEffect(() => () => latest.current.stop(), []);
 const check = (): void => {
  const read = latest.current.begin();
  setLink({ kind: 'checking' });
  investigate({ org: context.org, kind: 'trace', projects: [exemplar.project_id], target: exemplar.trace_id, window: { start: context.start, end: context.end }, limit: 1 }, read.signal).then(
   (view) => {
    if (!read.current()) return;
    const l = view.link;
    // Only a link the server resolved for this very project and trace may be shown; anything else is not a link.
    setLink(l !== undefined && l.available && l.project_id === exemplar.project_id && l.id === exemplar.trace_id ? { kind: 'available', project: l.project_id, trace: l.id } : { kind: 'not_found' });
   },
   (error: unknown) => {
    if (!read.current() || isAbort(error)) return;
    const state = stateOfFault(error);
    setLink(state.kind === 'unauthorized' ? { kind: 'not_found' } : { kind: 'failed', code: state.kind === 'error' ? state.fault.code : state.kind });
   },
  );
 };
 switch (link.kind) {
  case 'unchecked': return <button type="button" onClick={check}>Check trace link</button>;
  case 'checking': return <span role="status">Checking the trace link…</span>;
  case 'available': return <span data-link="available" role="status">Trace link authorized for this scope: trace <code>{link.trace}</code> in project <code>{link.project}</code>. The trace view itself is not built yet.</span>;
  case 'not_found': return <span data-link="not-found" role="status">Not found. This trace was not found or is not available to this account.</span>;
  case 'failed': return <span data-link="failed" role="alert">The link check failed ({link.code}). No link is shown.</span>;
 }
}

function statusOf(result: ExemplarResult, total: number): LoadState<ExemplarResult> {
 switch (result.freshness.completeness) {
  case 'partial': return { kind: 'incomplete', data: result, reason: 'shards_missing' };
  case 'stale': return { kind: 'stale', data: result, reason: 'freshness_stale' };
  default: return total === 0 ? { kind: 'empty', data: result } : { kind: 'ready', data: result };
 }
}
interface Held { key: string; items: Exemplar[]; next: string | null; status: LoadState<ExemplarResult> }
const MAX_HELD = 500;

/** Exemplars of the series a PromQL expression selects. A trace id is only ever text here: a link to it appears only through
 * the server's scope-resolved link route, so an exemplar can never reveal or link a trace this account may not read. */
export function Exemplars(props: { context: ViewContext; language: QueryLanguage; projects: string[]; profile: string; featureSet: string; expression: string }): React.JSX.Element {
 const { context, language, projects, profile, featureSet, expression } = props;
 const [limit, setLimit] = React.useState('20');
 const [problem, setProblem] = React.useState('');
 const [held, setHeld] = React.useState<Held | null>(null);
 const latest = React.useRef(latestOnly());
 const scope = `${scopeKey(context)}|${context.generation}`;
 const key = JSON.stringify([scope, projects, profile, featureSet, expression, limit]);
 const keyRef = React.useRef(key);
 keyRef.current = key;
 const view = held !== null && held.key === key ? held : null;
 React.useEffect(() => () => latest.current.stop(), [key]);
 const load = (more: boolean): void => {
  const size = /^[1-9][0-9]{0,2}$/.test(limit) ? Number(limit) : 0;
  if (size < 1 || size > 500) return setProblem('The page size must be a whole number from 1 to 500.');
  if (expression.trim() === '') return setProblem('Enter a PromQL expression above first.');
  if (projects.length === 0) return setProblem('Select at least one project.');
  setProblem('');
  const previous = more && view !== null ? view : null;
  const req: ExemplarRequest = { org: context.org, projects, profile, feature_set: featureSet, expression, window: { start: context.start, end: context.end }, limit: size, ...(previous?.next ? { cursor: previous.next } : {}) };
  void runLatest(latest.current, () => keyRef.current, key, (s) => exemplars(req, s), (state) => {
   if (state.kind === 'loading') setHeld({ key, items: previous?.items ?? [], next: null, status: { kind: 'loading' } });
   else if (state.kind === 'done') {
    const all = [...(previous?.items ?? []), ...state.value.exemplars].slice(0, MAX_HELD);
    setHeld({ key, items: all, next: state.value.more && all.length < MAX_HELD ? state.value.next_cursor ?? null : null, status: statusOf(state.value, all.length) });
   } else setHeld({ key, items: previous?.items ?? [], next: null, status: stateOfQueryFault(state.error) });
  });
 };
 return (
  <section className="panel" aria-labelledby="exemplar-heading" data-section="exemplars">
   <h3 id="exemplar-heading">Exemplars</h3>
   {language !== 'promql'
    ? <p role="status">Exemplars link metric samples to traces, so they exist only for PromQL metric expressions.</p>
    : (
     <>
      <p>Exemplars of the series the expression above selects in the selected window. A trace is only linked after the server confirms that this account may read it.</p>
      <form aria-label="Find exemplars" onSubmit={(e) => { e.preventDefault(); load(false); }}>
       <label>Page size (1 to 500) <input value={limit} onChange={(e) => setLimit(e.target.value)} inputMode="numeric" autoComplete="off" /></label>
       <button type="submit">Find exemplars</button>
      </form>
      {problem && <p role="alert" className="error">{problem}</p>}
      {view !== null && <StatusPanel state={view.status} />}
      {view !== null && view.items.length > 0 && (
       <table className="data-table" data-testid="exemplar-table">
        <caption>{view.items.length} exemplars, ordered by project, series, time and record</caption>
        <thead><tr><th scope="col">Series</th><th scope="col">Value</th><th scope="col">Time (nanoseconds)</th><th scope="col">Trace</th><th scope="col">Trace link</th></tr></thead>
        <tbody>
         {view.items.map((e) => (
          <tr key={e.record_id} data-exemplar data-trace={e.trace_id}>
           <th scope="row"><LabelText labels={e.labels} /><br /><small>project <code>{e.project_id}</code></small></th>
           <td><SampleValue sample={e.sample} /></td>
           <td><TimeText ns={e.sample.time} /></td>
           <td><code>{e.trace_id}</code>{e.span_id !== undefined && <small> span <code>{e.span_id}</code></small>}</td>
           <td><TraceLink exemplar={e} context={context} /></td>
          </tr>
         ))}
        </tbody>
       </table>
      )}
      {view !== null && view.next !== null && view.status.kind !== 'loading' && <button type="button" onClick={() => load(true)}>Load the next page ({view.items.length} loaded)</button>}
     </>
    )}
  </section>
 );
}
