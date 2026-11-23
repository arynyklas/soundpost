// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getTrace } from '../api/client';
import type { Id, SpanId, SpanReport, SpanTarget, TraceView } from '../api/types';
import { encodeHash, formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { Content, Explain, Hero } from '../shell/Frames';
import { Callout, CopyButton, shortId } from '../ui/primitives';
import { CriticalPath } from './CriticalPath';
import { targetLocation } from './links';
import { exploreWindow, uncertaintyText } from './model';
import { SpanDetails } from './SpanDetails';
import { Waterfall, durationShort } from './Waterfall';

/** One trace under the caller's own scope: its spans, causal critical path, duration bounds and every limit of the analysis. The server reads only spans this account may read, inside the selected window; nothing outside that window or scope is inferred. The observed duration is a bound, never an authoritative total. */
export function TracePage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const evidence = useEvidence<TraceView>(key, (signal) => getTrace(context.org, project, id, { start: context.start, end: context.end }, signal));
 const view = dataOf(evidence.state);
 const path = view?.path;
 const [selected, setSelected] = React.useState<{ key: string; span: SpanId } | null>(null);
 const selectedSpan = selected?.key === key ? selected.span : null;
 const select = (span: SpanId): void => setSelected({ key, span });
 const windowHref = (screen: 'logs' | 'metrics', span: SpanReport): string => {
  const w = exploreWindow(span);
  return encodeHash({ ...context, start: w.start, end: w.end }, screen);
 };
 // Jobs, replays and profiles open in their own view and an error occurrence in its issue; each checks the scope again.
 const targetHref = (target: SpanTarget): string | null => targetLocation(context, project, target);
 const root = path === undefined ? undefined : path.spans.find((s) => s.span_id === path.trees[0]?.root_span_id);
 return (
  <>
   <Hero>
    <div className="row top g16 wrap">
     <div className="col g4 grow">
      <h1 tabIndex={-1}>Trace <code title={id}>{shortId(id)}</code></h1>
      <div className="row wrap g12 small t2">
       {root !== undefined && <span className="bold" data-testid="trace-root">{root.operation}</span>}
       {root !== undefined && <span>started {formatNs(root.start_wall_ns, context.timezone)} ({context.timezone})</span>}
      </div>
      <div className="row small t3"><span>Trace ID <code>{id}</code></span><CopyButton text={id} label="Copy trace ID" /></div>
     </div>
     {path !== undefined && (
      <div className="kpis" data-testid="trace-kpis">
       <div className="kpi"><span className="label">Duration</span><span className="value">{durationShort(path.observed)}</span><span className="detail">{path.unlike_clock_domains ? `clock uncertainty up to ${uncertaintyText(BigInt(path.max_uncertainty_ns))}` : path.observed.known ? 'one clock domain' : 'no bound'}</span></div>
       <div className="kpi"><span className="label">Spans read</span><span className="value">{path.span_count}</span><span className="detail">only spans you may read</span></div>
       <div className="kpi"><span className="label">Critical path</span><span className="value">{path.complete && view?.partial !== true ? 'complete' : 'partial'}</span><span className="detail">{path.reasons.length} {path.reasons.length === 1 ? 'limit' : 'limits'} listed</span></div>
      </div>
     )}
    </div>
   </Hero>
   <Content>
    <Explain line={<>Spans read from {formatNs(context.start, context.timezone)} to {formatNs(context.end, context.timezone)} ({context.timezone}).</>}>A span outside this window or outside your access is not shown, and its absence is not proof that no work happened.</Explain>
    <StatusPanel state={evidence.state} />
    {view && <EvidenceSections sections={view.sections} />}
    {path !== undefined && (!path.complete || view?.partial === true) && <Callout tone="warn" role="status" testId="trace-incomplete"><strong>Critical path incomplete.</strong> The observed duration is a bound, not a total. Every limit is listed under Limits of this analysis.</Callout>}
    {path !== undefined && (
     <div className="grid-side exp-trace-grid">
      <Waterfall path={path} selectedSpan={selectedSpan} onSelect={select} />
      <SpanDetails path={path} selectedSpan={selectedSpan} targets={view?.targets} targetHref={targetHref} windowHref={windowHref} />
     </div>
    )}
    {path !== undefined && <CriticalPath path={path} partial={view?.partial === true} selectedSpan={selectedSpan} onSelect={select} />}
   </Content>
  </>
 );
}
