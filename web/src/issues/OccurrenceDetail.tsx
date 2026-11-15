// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getErrorOccurrence, getFrames } from '../api/client';
import type { ErrorOccurrenceDetail, ErrorOccurrenceView, FramesView, Id, OccurrenceEvidence } from '../api/types';
import { FramePanel } from '../artifacts/FramePanel';
import { encodeHash, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { chainEdgeWords, chainReasonWords, handledFatalWords, mechanismWords } from '../evidence/model';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { occurrenceReadKey, storedFramesPlan, type StoredFramesPlan } from './model';

function FramesRead(props: { plan: StoredFramesPlan; buildId: Id }): React.JSX.Element {
 const { plan } = props;
 const frames = useEvidence<FramesView>(plan.key, (signal) => getFrames(plan.request, signal));
 const view = dataOf(frames.state);
 return (
  <div data-testid="stored-frames">
   <StatusPanel state={frames.state} />
   {view && view.frames.map((f, i) => <FramePanel key={i} frame={f} buildId={props.buildId} index={i} />)}
   {plan.unsent > 0 && <p>{plan.unsent} more stored frames are not resolved here.</p>}
  </div>
 );
}

/** The primary stack of one stored occurrence, resolved through the server under the caller's own scope. The frames are the ones the error record stored, never typed or guessed; an unmapped frame keeps its original sanitized form and says why. At most one lookup's worth of frames is resolved and the rest are counted. */
function StoredFrames(props: { context: ViewContext; project: Id; detail: ErrorOccurrenceDetail }): React.JSX.Element {
 const plan = storedFramesPlan(props.context, props.project, props.detail);
 if (plan === null) return <p data-testid="stored-frames-none">This record stores no frames, so there is nothing to map.</p>;
 return <FramesRead plan={plan} buildId={props.detail.build_id} />;
}

function Link(props: { href: string; testid: string; children: React.ReactNode }): React.JSX.Element {
 return <a href={props.href} data-testid={props.testid}>{props.children}</a>;
}

/** Everything the stored record says, as text nodes only: class names, codes, frame names and chain reasons come from the application and are never markup. */
export function OccurrenceFacts(props: { context: ViewContext; project: Id; view: ErrorOccurrenceView }): React.JSX.Element | null {
 const { context, project } = props;
 const d = props.view.detail;
 if (!d) return null;
 const chain = d.exception_graph;
 return (
  <>
   <dl className="scope-bar">
    <dt>Exception class</dt><dd data-testid="occ-class"><code>{d.exception_class}</code></dd>
    <dt>Mechanism</dt><dd data-testid="occ-mechanism"><code>{d.mechanism}</code>. {mechanismWords(d.mechanism)}</dd>
    <dt>Handled and fatal</dt><dd data-testid="occ-handled-fatal" data-handled={d.handled ? 'yes' : 'no'} data-fatal={d.fatal ? 'yes' : 'no'}>{handledFatalWords(d.handled, d.fatal)}</dd>
    <dt>Code</dt><dd data-testid="occ-code">{d.code === null ? 'No code was recorded.' : <code>{d.code}</code>}</dd>
    {d.template_id !== undefined && <><dt>Template</dt><dd><code>{d.template_id}</code></dd></>}
    <dt>Build</dt><dd data-testid="occ-build"><code>{d.build_id}</code></dd>
    <dt>Release</dt><dd data-testid="occ-release">{d.release_id === undefined ? 'The record names no release.' : <Link href={encodeHash(context, 'releases', '', null, { project, id: d.release_id })} testid="occ-release-link">Release <code>{d.release_id}</code></Link>}</dd>
    <dt>Trace</dt><dd data-testid="occ-trace">{d.trace_id === undefined ? 'The record names no trace.' : <><Link href={encodeHash(context, 'traces', '', null, { project, id: d.trace_id })} testid="occ-trace-link">Trace <code>{d.trace_id}</code></Link>{d.span_id !== undefined && <> at span <code>{d.span_id}</code></>}</>}</dd>
    {d.replay_id !== undefined && <><dt>Replay</dt><dd><code>{d.replay_id}</code></dd></>}
    {d.profile_id !== undefined && <><dt>Profile</dt><dd><code>{d.profile_id}</code></dd></>}
    {d.run_id !== undefined && <><dt>Job run</dt><dd><code>{d.run_id}</code></dd></>}
   </dl>
   <h4>Exception chain</h4>
   {chain === undefined
    ? <p data-testid="occ-chain-none">The record stores no exception chain: only the error itself was captured.</p>
    : (
     <div data-testid="occ-chain">
      <ol aria-label="Errors in the chain">
       {chain.nodes.map((n) => (
        <li key={n.id} data-node={n.id} data-suppressed={n.context_suppressed ? 'yes' : 'no'}>
         <code>{n.exception_class}</code> (node {n.id}){n.context_suppressed ? '. The runtime suppressed the context of this error, so the chain may continue past it.' : ''}
         {n.frames.length > 0 && <> {n.frames.length} stored frame{n.frames.length === 1 ? '' : 's'}.</>}
        </li>
       ))}
      </ol>
      {chain.edges.length === 0 ? <p>No edge joins these errors.</p> : (
       <ul aria-label="Links between errors in the chain">
        {chain.edges.map((e, i) => <li key={i} data-edge-kind={e.kind}>{chainEdgeWords(chain, e)}</li>)}
       </ul>
      )}
      {chain.reasons.length > 0 && (
       <ul aria-label="Why the chain may be incomplete" data-testid="occ-chain-reasons">
        {chain.reasons.map((r) => <li key={r} data-reason={r}>Not captured: {chainReasonWords(r)}.</li>)}
       </ul>
      )}
     </div>
    )}
   <h4>Stored frames</h4>
   <StoredFrames context={context} project={project} detail={d} />
  </>
 );
}

/** The stored error record behind one occurrence: class, mechanism, handled and fatal, code, exception chain and its frames mapped through the real source map of the record's own build, with links to the release and the trace the record itself names. Read on request, under the caller's own telemetry scope; an administrator without telemetry.read is told so and nothing is shown. */
export function OccurrenceDetail(props: { context: ViewContext; project: Id; issue: Id; occurrence: OccurrenceEvidence }): React.JSX.Element {
 const { context, project, issue, occurrence } = props;
 const key = occurrenceReadKey(context, project, issue, occurrence.occurrence_id);
 const evidence = useEvidence<ErrorOccurrenceView>(key, (signal) => getErrorOccurrence(context.org, project, issue, occurrence.occurrence_id, signal));
 const view = dataOf(evidence.state);
 return (
  <section className="panel" aria-labelledby="occ-detail-heading" data-section="occurrence-detail" data-occurrence={occurrence.occurrence_id}>
   <h3 id="occ-detail-heading">Stored occurrence <code>{occurrence.occurrence_id}</code></h3>
   <StatusPanel state={evidence.state} />
   {view && <OccurrenceFacts context={context} project={project} view={view} />}
  </section>
 );
}
