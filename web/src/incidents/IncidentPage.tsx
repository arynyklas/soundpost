// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getIncident, isAbort, stateOfFault } from '../api/client';
import type { ApiFault, Id, IncidentView, LoadState, TimelineEntry, WindowView } from '../api/types';
import { formatNs, latestOnly, scopeKey, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { ActionForm } from './ActionForm';
import { describeReason, msUntilExpiry, rateText, responseWords, sourceWords, splitTimeline } from './model';

interface Loaded { state: LoadState<IncidentView>; view: IncidentView | undefined; reload: () => void; reloading: boolean; refreshFault: ApiFault | null; adopt: (view: IncidentView) => void }

/** Loads one incident for the scope. Data is keyed to the scope it was requested for; a reload
 * keeps what is on screen (and the action form's draft) until the server answers, and a reload
 * that finds the incident no longer readable clears it instead of keeping stale content. */
function useIncident(context: ViewContext, project: Id, id: Id): Loaded {
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; state: LoadState<IncidentView> }>({ key: '', state: { kind: 'loading' } });
 const [reloading, setReloading] = React.useState(false);
 const [refreshFault, setRefreshFault] = React.useState<ApiFault | null>(null);
 const latest = React.useRef<Latest>(latestOnly());
 const load = (initial: boolean): void => {
  const read = latest.current.begin();
  if (initial) { setHeld({ key, state: { kind: 'loading' } }); setRefreshFault(null); } else setReloading(true);
  getIncident(context.org, project, id, read.signal).then(
   (view) => { if (read.current()) { setHeld({ key, state: { kind: 'ready', data: view } }); setReloading(false); setRefreshFault(null); } },
   (error: unknown) => {
    if (!read.current() || isAbort(error)) return;
    const failed = stateOfFault(error);
    setReloading(false);
    if (initial || failed.kind === 'unauthorized') setHeld({ key, state: failed });
    else if (failed.kind === 'error') setRefreshFault(failed.fault);
    else setHeld({ key, state: failed });
   },
  );
 };
 React.useEffect(() => {
  load(true);
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 const state: LoadState<IncidentView> = held.key === key ? held.state : { kind: 'loading' };
 const view = state.kind === 'ready' ? state.data : undefined;
 return {
  state, view, reloading, refreshFault,
  reload: () => load(false),
  adopt: (next) => { latest.current.stop(); setReloading(false); setRefreshFault(null); setHeld({ key, state: { kind: 'ready', data: next } }); },
 };
}

const ENTRY_LABEL: Record<string, string> = {
 open: 'Source reported the incident opening', impact: 'Source impact observation', assign: 'Assignment', ack: 'Acknowledged', resolve: 'Resolved', link: 'Evidence linked',
 snooze: 'Reminders snoozed', unsnooze: 'Snooze ended', maintenance: 'Maintenance started', maintenance_end: 'Maintenance ended',
};

function Entry(props: { entry: TimelineEntry; tz: string }): React.JSX.Element {
 const e = props.entry;
 return (
  <li data-version={e.version} data-type={e.type}>
   <strong>Revision {e.version}: {ENTRY_LABEL[e.type] ?? 'Action'}</strong> at {formatNs(e.at, props.tz)}, by <code>{e.actor}</code> ({e.origin === 'human' ? 'a person' : 'recorded as a system observation'}).
   {e.owner !== undefined && <> Owner <code>{e.owner}</code>.</>}
   {e.type === 'assign' && e.owner === undefined && <> Owner removed.</>}
   {e.impact && <> Severity {e.impact.severity}, source {e.impact.state}, {e.impact.freshness} data.</>}
   {e.link && <> Linked {e.link.kind} <code>{e.link.id}</code>.</>}
   {e.until !== undefined && <> Until {formatNs(e.until, props.tz)}.</>}
   {e.reason && <> Reason: {e.reason}</>}
  </li>
 );
}

function windowWords(w: WindowView, tz: string): string {
 const state = w.ended !== undefined ? `ended ${formatNs(w.ended, tz)}` : w.active ? 'active' : 'expired';
 return `${state}; from ${formatNs(w.from, tz)} until ${formatNs(w.until, tz)}`;
}

/** The incident workspace. Three concerns stay separate in their own badges, text and timelines:
 * the alert condition (what the source reports), the issue workflow (not available: no issue
 * control handler exists) and the incident response (what people decided). Nothing here shows a
 * committed status before the server answered. */
export function IncidentPage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const incident = useIncident(context, props.project, props.id);
 const { view } = incident;
 const expired = React.useRef(new Set<string>());
 React.useEffect(() => {
  if (!view) return;
  const ms = msUntilExpiry(view, Date.now());
  const windows = [view.snooze, view.maintenance].filter((w): w is WindowView => w?.active === true);
  const first = windows.sort((a, b) => Number(BigInt(a.until) - BigInt(b.until)))[0];
  if (ms === null || !first || ms > 2_000_000_000 || expired.current.has(first.until)) return;
  // A window that ended is refreshed from the server exactly once per window, even if the clocks disagree.
  const timer = setTimeout(() => { expired.current.add(first.until); incident.reload(); }, ms + 750);
  return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [view?.version, view?.snooze?.until, view?.maintenance?.until, view?.snooze?.active, view?.maintenance?.active]);
 const tz = context.timezone;
 const parts = view?.timeline ? splitTimeline(view.timeline) : { condition: [], response: [] };
 const issueLinks = view?.links.filter((l) => l.kind === 'issue') ?? [];
 return (
  <section className="panel" aria-labelledby="incident-heading">
   <h2 id="incident-heading">Incident <code>{props.id}</code></h2>
   <StatusPanel state={incident.state} />
   {incident.refreshFault && <p role="alert" className="error">The latest reload failed (code <code>{incident.refreshFault.code}</code>). The incident below is the last answer the server gave, not necessarily current.</p>}
   {view && (
    <>
     <p aria-live="polite" data-testid="revision">Revision <strong>{view.version}</strong>{incident.reloading ? ' (reloading…)' : ''}. Project <code>{view.project_id}</code>.</p>
     <button type="button" onClick={incident.reload} disabled={incident.reloading}>Reload incident</button>
     {view.status === 'resolved' && view.source_firing && (
      <div role="alert" className="banner banner-warning" data-testid="unresolved-source">
       <strong>Resolved by a person, but the alert source is still firing.</strong> The incident response was closed at {view.resolved_at ? formatNs(view.resolved_at, tz) : 'an unrecorded time'}; the source last reported firing at {formatNs(view.condition.observed_at, tz)}. Resolving does not recover the source.
      </div>
     )}
     {view.status === 'open' && view.ack && view.source_firing && (
      <p role="status" className="banner" data-testid="ack-source-firing"><strong>Acknowledged, and the source is still firing.</strong> An acknowledgement pauses reminders only; it does not change the alert condition.</p>
     )}

     <section className="panel" aria-labelledby="cond-heading" data-section="alert-condition">
      <h3 id="cond-heading">Alert condition</h3>
      <p><span className={`badge badge-${view.condition.state}`} data-testid="source-badge">{sourceWords(view)}</span> Impact severity {view.severity}, impact revision {view.impact_revision}. Condition <code>{view.condition.id}</code>, episode <code>{view.episode_id}</code>.</p>
      <p data-testid="rate">{rateText(view, (ns) => formatNs(ns, tz))}</p>
      <h4>Condition timeline</h4>
      <ol className="timeline" aria-label="Condition timeline">{parts.condition.map((e) => <Entry key={e.version} entry={e} tz={tz} />)}</ol>
     </section>

     <section className="panel" aria-labelledby="issue-heading" data-section="issue-workflow">
      <h3 id="issue-heading">Issue workflow</h3>
      <p><span className="badge badge-unavailable">Issue workflow: not available</span> {describeReason('issue_control_handler_not_built')}</p>
      {issueLinks.length > 0 ? <ul>{issueLinks.map((l) => <li key={l.id}>Linked issue <code>{l.id}</code> (its workflow state is not shown)</li>)}</ul> : <p>No issue is linked to this incident.</p>}
     </section>

     <section className="panel" aria-labelledby="resp-heading" data-section="incident-response">
      <h3 id="resp-heading">Incident response</h3>
      <p><span className={`badge badge-${view.status}`} data-testid="status-badge">Incident: {view.status === 'open' ? 'open' : 'resolved by a person'}</span></p>
      <ul data-testid="response-words">{responseWords(view).map((w) => <li key={w}>{w}</li>)}</ul>
      {view.ack && <p>Acknowledged by <code>{view.ack.actor}</code> at {formatNs(view.ack.at, tz)}; it covers impact revision {view.ack.impact_revision}{view.ack.current ? '' : ' only, and the impact is now revision ' + view.impact_revision}.</p>}
      {view.snooze && <p data-testid="snooze">Snooze by <code>{view.snooze.actor}</code>, {windowWords(view.snooze, tz)}. Reason: {view.snooze.reason}</p>}
      {view.maintenance && <p data-testid="maintenance">Maintenance by <code>{view.maintenance.actor}</code>, {windowWords(view.maintenance, tz)}. Reason: {view.maintenance.reason}</p>}
      <h4>Response timeline</h4>
      <ol className="timeline" aria-label="Response timeline">{parts.response.length === 0 ? <li>No person has acted on this incident yet.</li> : parts.response.map((e) => <Entry key={e.version} entry={e} tz={tz} />)}</ol>
     </section>

     <section className="panel" aria-labelledby="notify-heading" data-section="notifications">
      <h3 id="notify-heading">Notifications</h3>
      <ul>
       <li data-testid="reminders">{view.notification.reminders_paused ? `Reminders are paused by ${view.notification.paused_by === 'ack+snooze' ? 'the acknowledgement and the snooze' : view.notification.paused_by === 'snooze' ? 'the snooze' : 'the acknowledgement'}.` : 'Reminders are not paused.'}</li>
       <li data-testid="worse-impact">{view.notification.worse_impact_eligible ? 'A worse impact is eligible to notify: acknowledging or snoozing does not suppress it.' : `A worse impact is not eligible to notify: ${view.notification.suppressed_by === 'maintenance' ? 'an active maintenance window suppresses new notifications' : 'the incident is resolved, so a worse impact proposes a new linked incident'}.`}</li>
       <li data-testid="delivery">Delivery: not available. {describeReason(view.notification.delivery.reason ?? 'notification_outbox_not_built')}</li>
      </ul>
     </section>

     <section className="panel" aria-labelledby="links-heading">
      <h3 id="links-heading">Evidence links</h3>
      <ul>{view.links.map((l) => <li key={`${l.kind}:${l.id}`}>{l.kind} <code>{l.id}</code></li>)}</ul>
      {view.previous && <p>Follows incident <code>{view.previous}</code>.</p>}
     </section>

     <ActionForm view={view} onCommitted={incident.adopt} onReload={incident.reload} reloading={incident.reloading} />
    </>
   )}
  </section>
 );
}
