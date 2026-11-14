// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { createLiveTicket, openLive } from '../api/client';
import { ApiFault, QueryFault, type Cursor, type LiveTicketRequest } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { DEFAULT_LIVE_LIMITS, applyLiveEvent, beginAttachment, endAttachment, initialLive, type LiveEnd, type LiveGapItem, type LiveItem, type LiveRow, type LiveView } from './liveModel';
import { labelsText } from './model';
import { TimeText } from './MetricResult';

const GAP_REASONS: Record<string, string> = {
 replay_evicted: 'the replay buffer dropped events this browser had not read yet',
 replay_expired: 'the retained stream was gone (its 60-second replay window had passed), so a new stream started here',
 feed_overrun: 'the committed change feed overran this stream',
 feed_catch_up: 'commits between the cursors predate this subscription',
 feed_gap: 'the change feed reported a gap',
 partial_shard: 'a shard answered only partly',
 unannounced_sequence_jump: 'sequence numbers were skipped without the server announcing a gap',
};
const END_WORDS: Record<string, string> = {
 scope_revoked: 'The server revoked this live view: this account no longer has access.',
 deleted: 'The server ended this live view because data it could read was deleted.',
 slow_consumer: 'The server disconnected this browser because it could not keep up with the stream (slow consumer). The gap before this message names what was not delivered.',
 deadline: 'The stream reached its time limit and ended.',
 superseded: 'A newer connection took over this stream.',
 service_closed: 'The server is shutting this stream down.',
 feed_error: 'The server could not read the committed change feed.',
 corrupt_record: 'The server could not decode a committed record, so it ended the stream.',
 buffer_overflow: 'A record was larger than the stream buffer, so the stream ended.',
 unavailable: 'The stream ended because a dependency was unavailable.',
 foreign_project: 'A record for a project that was not requested arrived. The view was cleared and ended.',
 stream_mismatch: 'An event for another stream arrived. The view was cleared and ended.',
 invalid_response: 'The server sent something this view could not trust. The view ended.',
};

function Cursors(props: { cursors: Cursor[] }): React.JSX.Element {
 if (props.cursors.length === 0) return <>unknown</>;
 return <>{props.cursors.length} {props.cursors.length === 1 ? 'cursor' : 'cursors'} (<code>{props.cursors.slice(0, 3).map((c) => `${c.group}:${c.index}`).join(', ')}{props.cursors.length > 3 ? ', …' : ''}</code>)</>;
}

function GapItem(props: { item: LiveGapItem }): React.JSX.Element {
 const g = props.item;
 return (
  <li className="live-gap" data-gap data-announced={g.announced ? 'yes' : 'no'} data-reason={g.reason} data-from={g.from} data-to={g.to}>
   <strong>Gap ({g.reason}):</strong> stream sequences {g.from === g.to ? <code>{g.from}</code> : <><code>{g.from}</code> to <code>{g.to}</code></>} were not delivered; {GAP_REASONS[g.reason] ?? 'the server did not say more'}.
   {g.announced ? <> Committed feed: after <Cursors cursors={g.after} />, through <Cursors cursors={g.through} />.</> : <> This browser noticed it; the server did not announce it.</>}
  </li>
 );
}

function RowItem(props: { item: LiveRow }): React.JSX.Element {
 const r = props.item;
 return (
  <li className="live-row" data-row data-sequence={r.sequence} data-time={r.time}>
   <span className="live-meta"><code>#{r.sequence}</code> <TimeText ns={r.time} /> project <code>{r.project}</code></span>
   <code className="log-line" data-line>{r.line}</code>{r.multiplicity !== '1' && <small> (× {r.multiplicity} identical)</small>}
   <small className="live-labels"> labels <code>{labelsText(r.labels)}</code> · stream labels <code>{labelsText(r.streamLabels)}</code> · structured metadata {r.metadata.length === 0 ? 'none' : <code>{labelsText(r.metadata)}</code>}</small>
  </li>
 );
}

/** The held rows and gaps, oldest first. Every value is a text node: a log line or label is never interpreted as markup. */
export function LiveItems(props: { items: LiveItem[] }): React.JSX.Element {
 return <ol className="live-items" tabIndex={0} aria-label="Live log rows and gaps, oldest first">{props.items.map((item, i) => (item.kind === 'gap' ? <GapItem key={`g${i}:${item.from}`} item={item} /> : <RowItem key={item.sequence} item={item} />))}</ol>;
}

function endOf(error: unknown): LiveEnd {
 if (error instanceof ApiFault) {
  if (error.status === 401 || error.status === 403 || error.status === 404) return { kind: 'refused', reason: 'not_found_or_not_available', code: error.code };
  return { kind: 'failed', reason: error.code, code: error.code };
 }
 return { kind: 'interrupted', reason: 'connection_lost', code: '' };
}

function Banner(props: { view: LiveView; fault: QueryFault | null }): React.JSX.Element | null {
 const { view, fault } = props;
 const end = view.end;
 if (end === null) return null;
 const seq = view.lastSequence;
 switch (end.kind) {
  case 'revoked': return <p role="alert" className="banner banner-warning" data-end="revoked"><strong>Access ended.</strong> {END_WORDS[end.reason] ?? 'The server revoked this live view.'} Every buffered row was cleared and nothing further will be shown. ({end.reason})</p>;
  case 'refused': return <p role="alert" className="banner banner-warning" data-end="refused"><strong>Not found.</strong> This live view was not found or is not available to this account. Nothing is shown.</p>;
  case 'error': return <p role="alert" className="banner banner-warning" data-end="error" data-reason={end.reason}><strong>The stream ended with an error ({end.reason}).</strong> {END_WORDS[end.reason] ?? 'The server ended the stream.'} Rows already received are kept; this is not a complete tail.</p>;
  case 'stopped': return <p role="status" className="banner" data-end="stopped"><strong>Stopped by you.</strong> Rows already received are kept. Resuming continues after sequence {seq} and shows a gap if events were lost.</p>;
  case 'interrupted': return <p role="alert" className="banner banner-warning" data-end="interrupted"><strong>The connection ended without a final event.</strong> Rows already received are kept and the view may be incomplete. Nothing reconnects by itself: resuming continues after sequence {seq} and shows a gap if events were lost.</p>;
  case 'failed': return <p role="alert" className="banner banner-warning" data-end="failed" data-code={end.code}><strong>The live view could not be started or continued ({end.code}).</strong>{fault?.language ? <> Language error, category {fault.language.category}{fault.language.languageCode ? `, code ${fault.language.languageCode}` : ''}: {fault.language.detail}.</> : null}</p>;
 }
}

/** A live tail of one LogQL log query over server-sent events through a real, one-use, session-bound ticket. It is one open
 * stream: nothing polls, nothing reconnects by itself, a lost connection is shown as lost and resuming is an explicit act that
 * sends the last handled sequence as Last-Event-ID. Every gap is shown with its exact bounds, a revoke clears the view at once,
 * and the rows held in memory are bounded with a visible count of what was dropped. */
export function LiveLogView(props: { request: LiveTicketRequest; context: ViewContext }): React.JSX.Element {
 const { request, context } = props;
 const scope = `${scopeKey(context)}|${context.generation}`;
 const [held, setHeld] = React.useState<{ scope: string; view: LiveView; request: LiveTicketRequest | null; fault: QueryFault | null }>({ scope, view: initialLive(), request: null, fault: null });
 const current = held.scope === scope ? held : { scope, view: initialLive(), request: null, fault: null };
 const view = current.view;
 const viewRef = React.useRef(view);
 viewRef.current = view;
 const controller = React.useRef<AbortController | null>(null);
 // Leaving the page or the scope ends the stream; a view of another scope is never shown (see `current`).
 React.useEffect(() => () => { controller.current?.abort(); controller.current = null; }, [scope]);

 const patch = (mine: string, fn: (v: LiveView) => LiveView, fault: QueryFault | null = null): void => {
  setHeld((h) => (h.scope === mine ? { ...h, view: fn(h.view), fault: fault ?? h.fault } : h));
 };

 const start = (resume: boolean): void => {
  controller.current?.abort();
  const mine = new AbortController();
  controller.current = mine;
  const base = resume ? viewRef.current : initialLive();
  const resumable = resume && base.streamId !== '';
  const body: LiveTicketRequest = resumable ? { ...request, resume_stream_id: base.streamId } : request;
  const lastEventId = resumable && base.lastSequence !== '0' ? base.lastSequence : null;
  setHeld({ scope, view: beginAttachment(base, resumable), request, fault: null });
  void (async () => {
   try {
    const ticket = await createLiveTicket(body, mine.signal);
    for await (const ev of await openLive(ticket.ticket, lastEventId, mine.signal)) {
     if (mine.signal.aborted) return;
     const now = Date.now();
     patch(scope, (v) => applyLiveEvent(v, ev, { now, projects: request.projects, limits: DEFAULT_LIVE_LIMITS }));
     if (ev.type === 'revoke' || ev.type === 'error') { mine.abort(); return; }
    }
    if (!mine.signal.aborted) patch(scope, (v) => (v.end === null ? endAttachment(v, { kind: 'interrupted', reason: 'connection_ended', code: '' }) : v));
   } catch (error) {
    if (mine.signal.aborted) return;
    patch(scope, (v) => endAttachment(v, endOf(error)), error instanceof QueryFault ? error : null);
   }
  })();
 };
 const stop = (): void => {
  controller.current?.abort();
  controller.current = null;
  patch(scope, (v) => endAttachment(v, { kind: 'stopped', reason: 'stopped_by_you', code: '' }));
 };

 const running = view.phase === 'connecting' || view.phase === 'live';
 const canResume = view.phase === 'ended' && view.streamId !== '' && view.end !== null && view.end.kind !== 'revoked' && view.end.kind !== 'refused';
 const shownRequest = current.request ?? request;
 const rows = view.items.filter((i) => i.kind === 'row').length;
 const words = view.phase === 'idle' ? 'Not started.' : view.phase === 'connecting' ? 'Connecting: waiting for the server to open the stream.' : view.phase === 'live' ? `Live: connected to stream ${view.streamId}.` : 'Ended.';
 return (
  <section className="panel" aria-labelledby="live-heading" data-live-state={view.phase} data-live-end={view.end?.kind ?? ''}>
   <h3 id="live-heading">Live log view</h3>
   <p>One open server-sent stream of the log query below, through a real one-use ticket. It never polls and never reconnects by itself. The server keeps 60 seconds of replay: a resume after that starts with an explicit <code>replay_expired</code> gap.</p>
   <dl className="scope-bar">
    <dt>Query</dt><dd><code data-testid="live-expression">{shownRequest.expression}</code></dd>
    <dt>Projects</dt><dd><code>{shownRequest.projects.join(', ')}</code></dd>
    <dt>Profile</dt><dd><code>{shownRequest.profile}</code>, feature set <code>{shownRequest.feature_set}</code></dd>
   </dl>
   <div className="field-row">
    {!running && <button type="button" className="primary" onClick={() => start(false)}>{view.phase === 'idle' ? 'Start live view' : 'Start a new live view'}</button>}
    {running && <button type="button" onClick={stop}>Stop live view</button>}
    {canResume && <button type="button" onClick={() => start(true)}>Resume after sequence {view.lastSequence}</button>}
   </div>
   <p role="status" aria-live="polite" data-testid="live-status">{words}{view.replaced ? ' The retained stream had expired, so this is a new stream: see the gap below.' : ''}</p>
   <Banner view={view} fault={current.fault} />
   <ul className="sections" aria-label="Live view counters">
    <li>Rows held: <strong data-testid="live-rows">{rows}</strong> (newest of {view.received} received)</li>
    <li>Gap events: <strong data-testid="live-gaps">{view.gaps}</strong></li>
    <li>Heartbeats: {view.heartbeats}{view.lastHeartbeatAt !== null ? `, last at ${new Date(view.lastHeartbeatAt).toISOString()}` : ''}; events ignored as already handled: {view.duplicates}</li>
   </ul>
   {view.evicted > 0 && <p role="status" className="banner" data-truncated={view.evicted}><strong>Truncated view.</strong> Only the newest {view.items.length} of {view.items.length + view.evicted} rows and gaps are held. {view.evicted} older items were delivered but are no longer held here.</p>}
   {view.items.length === 0
    ? <p data-testid="live-empty">{view.end?.kind === 'revoked' || view.end?.kind === 'refused' ? 'Nothing is shown.' : running ? 'No row has arrived yet. Rows appear as soon as they are committed.' : 'No rows.'}</p>
    : <LiveItems items={view.items} />}
  </section>
 );
}
