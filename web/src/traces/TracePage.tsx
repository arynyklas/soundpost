// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getTrace } from '../api/client';
import type { Id, SpanId, SpanReport, TraceView } from '../api/types';
import { encodeHash, formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { CriticalPath } from './CriticalPath';
import { exploreWindow } from './model';

/** One trace under the caller's own scope: its spans, causal critical path, duration bounds and every limit of the analysis. The server reads only spans this account may read, inside the selected window; nothing outside that window or scope is inferred. The observed duration is a bound, never an authoritative total. */
export function TracePage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const evidence = useEvidence<TraceView>(key, (signal) => getTrace(context.org, project, id, { start: context.start, end: context.end }, signal));
 const view = dataOf(evidence.state);
 const [selected, setSelected] = React.useState<{ key: string; span: SpanId } | null>(null);
 const exploreHref = (span: SpanReport): string => {
  const w = exploreWindow(span);
  return encodeHash({ ...context, start: w.start, end: w.end }, 'explore');
 };
 return (
  <section className="panel" aria-labelledby="trace-heading">
   <h2 id="trace-heading">Trace <code>{id}</code></h2>
   <p>Spans are read from {formatNs(context.start, context.timezone)} to {formatNs(context.end, context.timezone)} ({context.timezone}). A span outside this window or outside your access is not shown, and its absence is not proof that no work happened.</p>
   <StatusPanel state={evidence.state} />
   {view && <EvidenceSections sections={view.sections} />}
   {view?.path && <CriticalPath path={view.path} partial={view.partial} selectedSpan={selected?.key === key ? selected.span : null} onSelect={(span) => setSelected({ key, span })} exploreHref={exploreHref} />}
  </section>
 );
}
