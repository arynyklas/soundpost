// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getQueue, isAbort, stateOfFault } from '../api/client';
import type { IncidentView, LoadState, QueueView } from '../api/types';
import { PAGE_LIMIT, formatNs, latestOnly, scopeKey, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { SessionContext } from '../auth/ElevationDialog';
import { memberName, projectLabel, useShell, type Names } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, DataTable, FilterChips, Person, Pill, SeverityIcon, cx, type Column } from '../ui/primitives';
import { CHIPS, agoWords, chipCounts, incidentTitle, isUnacknowledged, matchesChip, matchesSearch, nextStep, summarize, type ChipId, type Summary } from './listModel';
import { deliveryEntryText, deliveryHeadline, describeReason, digestText, responseWords, sourceWords, unreadText, urgencyText } from './model';

export function stateOfQueue(view: QueueView): LoadState<QueueView> {
 switch (view.state) {
  case 'ready': return { kind: 'ready', data: view };
  case 'empty': return { kind: 'empty', data: view };
  case 'incomplete': return { kind: 'incomplete', data: view, reason: view.reason ?? 'incomplete' };
  case 'stale': return { kind: 'stale', data: view, reason: view.reason ?? 'stale' };
  case 'not_available': return { kind: 'unsupported', reason: view.reason ?? 'not_available', data: view };
 }
}

function useQueue(context: ViewContext): LoadState<QueueView> {
 const key = `${scopeKey(context)}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; state: LoadState<QueueView> }>({ key: '', state: { kind: 'loading' } });
 const latest = React.useRef<Latest>(latestOnly());
 React.useEffect(() => {
  const read = latest.current.begin();
  setHeld({ key, state: { kind: 'loading' } });
  getQueue(context.org, context.projects, PAGE_LIMIT, read.signal).then(
   (view) => { if (read.current()) setHeld({ key, state: stateOfQueue(view) }); },
   (error: unknown) => { if (read.current() && !isAbort(error)) setHeld({ key, state: stateOfFault(error) }); },
  );
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return held.key === key ? held.state : { kind: 'loading' };
}

const SECTION_LABEL: Record<string, string> = { ready: 'Ready', empty: 'Empty', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };
const SECTION_TITLE: Record<string, string> = { incidents: 'Incidents', urgency: 'Urgency', delivery: 'Delivery state', digest: 'Digest state', unread_change: 'Unread changes' };

export function Stats(props: { summary: Summary }): React.JSX.Element {
 const s = props.summary;
 const d = s.delivery;
 const deliveryUnstated = s.open > 0 && d.unstated === s.open;
 return (
  <div className="inc-stats" data-testid="incident-stats">
   <div className="stat"><span className="k">Open</span><span className="v inc-fig">{s.open}</span><p>{s.loaded} incident{s.loaded === 1 ? '' : 's'} loaded</p></div>
   <div className="stat"><span className="k">Needs action</span><span className={cx('v inc-fig', s.needsAction > 0 && 'tone-crit')}>{s.needsAction}</span><p>acknowledge, check delivery or resolve</p></div>
   <div className="stat"><span className="k">Not acknowledged</span><span className="v inc-fig">{s.unacknowledged}</span><p>{s.outdatedAck > 0 ? `includes ${s.outdatedAck} acknowledged before a worse impact` : 'no current acknowledgement'}</p></div>
   <div className="stat"><span className="k">Delivery problems</span>
    <span className={cx('v inc-fig', !deliveryUnstated && d.failed + d.uncertain > 0 && 'tone-high')}>{deliveryUnstated ? 'Not stated' : d.failed + d.uncertain}</span>
    <p>{deliveryUnstated ? 'No delivery state is available for these incidents' : `${d.failed} failed · ${d.uncertain} uncertain${d.unstated > 0 ? ` · ${d.unstated} not stated` : ''}`}</p></div>
  </div>
 );
}

const SEV_ROW: Record<IncidentView['severity'], string> = { critical: 'sev-row-crit', major: 'sev-row-high', minor: 'sev-row-low' };

interface RowEnv { context: ViewContext; names: Names; open: (v: IncidentView) => void; href: (v: IncidentView) => string; nowMs: number }

function columns(env: RowEnv): Column<IncidentView>[] {
 const tz = env.context.timezone;
 const fmt = (ns: string): string => formatNs(ns, tz);
 return [
  {
   key: 'incident', header: 'Incident', cell: (e) => (
    <div className="row top g8">
     {e.status === 'open' ? <SeverityIcon severity={e.severity} /> : <span className="sev sev-low"><Icon name="check" size="xs" /><span className="sr-only">resolved</span></span>}
     <div className="cell-title">
      <a className="a" href={env.href(e)}>{incidentTitle(e)}</a>
      <span className="s"><b>{projectLabel(env.names, e.project_id)}</b> · <span title={e.incident_id}>{e.incident_id.slice(0, 8)}…</span> · {agoWords(e.last_activity, env.nowMs)}{e.notification.unread_change.state === 'ready' && e.notification.unread_change.changed && <> · <span className="unread">● changed since the last digest</span></>}</span>
     </div>
    </div>
   ),
  },
  {
   key: 'source', header: 'Source', cell: (e) => (
    <div className="col g4">
     <Pill tone={e.condition.state === 'firing' ? 'crit' : e.condition.state === 'recovered' ? 'ok' : 'unk'} icon={e.condition.state === 'firing' ? 'fire' : e.condition.state === 'recovered' ? 'check' : 'question'}>{sourceWords(e)}</Pill>
     <span className="xsmall t3" title="No denominator is recorded for the condition, so no rate is stated.">Rate unknown</span>
     {e.status === 'resolved' && e.source_firing && <span className="xsmall tone-high">Resolved, source still firing</span>}
    </div>
   ),
  },
  {
   key: 'response', header: 'Response', cell: (e) => {
    const owner = e.owner;
    const extras = responseWords(e).filter((w) => !w.startsWith('Owner') && w !== 'Unassigned' && w !== 'Open' && w !== 'Resolved by a person');
    return (
     <div className="col g4">
      <Pill tone={e.status === 'open' ? 'high' : 'ok'}>{e.status === 'open' ? 'Open' : 'Resolved by a person'}</Pill>
      <Person id={owner} name={memberName(env.names, owner)} />
      {extras.length > 0 && <span className="xsmall t2">{extras.join('; ')}</span>}
      {e.ack === undefined && e.status === 'open' && !e.snooze?.active && !e.maintenance?.active && <span className="xsmall tone-crit">Not acknowledged</span>}
     </div>
    );
   },
  },
  {
   key: 'notifications', header: 'Notifications', cell: (e) => {
    const n = e.notification;
    const entries = n.delivery.entries ?? [];
    return (
     <div className="col g4 inc-notify-cell" data-cell="notifications">
      <strong className={cx('small', n.delivery.attention === 'failed' && 'tone-crit', n.delivery.attention === 'uncertain' && 'tone-high')} data-cell="delivery" data-attention={n.delivery.attention ?? n.delivery.state}>{deliveryHeadline(n.delivery)}</strong>
      {entries.length > 0 && <ul className="xsmall t2 inc-entries" data-cell="delivery-entries">{entries.map((d) => <li key={d.id} data-status={d.status}>{deliveryEntryText(d, fmt)}</li>)}</ul>}
      {n.delivery.truncated && <span className="xsmall t3">Older deliveries are not listed.</span>}
      {n.urgency.state === 'ready' && <span className="xsmall t2" data-cell="urgency">{urgencyText(n.urgency)}</span>}
      {/* A not-ready urgency, digest and digest coverage are the same sentence on most rows; they stay in the row, folded. */}
      <details className="inc-policy">
       <summary>Policy and digest</summary>
       {n.urgency.state !== 'ready' && <span className="xsmall t2" data-cell="urgency">{urgencyText(n.urgency)}</span>}
       <span className="xsmall t2" data-cell="digest">{digestText(n.digest, fmt)}</span>
       <span className="xsmall t2" data-cell="unread">{unreadText(n.unread_change)}</span>
       <span className="xsmall t3">{n.worse_impact_eligible ? 'Worse impact eligible' : 'Worse impact not eligible'}</span>
       <span className="xsmall t3" data-cell="activity">Last activity {fmt(e.last_activity)}</span>
      </details>
     </div>
    );
   },
  },
  {
   key: 'next', header: 'Next step', cell: (e) => {
    const step = nextStep(e);
    return step ? <button type="button" className="need" aria-label={`${step.label}: open ${incidentTitle(e)}`} onClick={() => env.open(e)}>{step.label}<Icon name="arrow" size="xs" /></button> : <span className="t3"><span aria-hidden="true">—</span><span className="sr-only">No next step</span></span>;
   },
  },
 ];
}

/** The list over one loaded page of the queue: summary figures, search and chips all computed client-side from the rows the server answered with. */
export function IncidentTable(props: { entries: readonly IncidentView[]; env: RowEnv; me: string | undefined }): React.JSX.Element {
 const { entries, env, me } = props;
 const [chip, setChip] = React.useState<ChipId>('all');
 const [query, setQuery] = React.useState('');
 const counts = chipCounts(entries, me);
 const shown = entries.filter((v) => matchesChip(v, chip, me) && matchesSearch(v, query, { project: projectLabel(env.names, v.project_id), owner: memberName(env.names, v.owner) ?? '' }));
 return (
  <>
   <div className="searchbar">
    <Icon name="search" size="s" className="t3" />
    <input type="search" aria-label="Search incidents" placeholder="Search title, project, owner, ID…" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" spellCheck={false} />
   </div>
   <FilterChips label="Filter incidents" value={chip} onChange={setChip} options={CHIPS.map((c) => ({ value: c.id, label: c.label, count: counts[c.id] }))} />
   {shown.length === 0
    ? <p className="t2" role="status" data-state="empty">No loaded incident matches this filter ({entries.length} {entries.length === 1 ? 'incident is' : 'incidents are'} loaded). Change the chip or the search.</p>
    : <div className="card"><DataTable label="Incidents in the selected projects: open first, then by urgency tier, impact severity and recent activity" rows={shown} rowKey={(v) => `${v.project_id}:${v.incident_id}`} columns={columns(env)} rowAttrs={(v) => ({ 'data-incident': v.incident_id, 'data-status': v.status })} rowClass={(v) => (v.status === 'open' ? SEV_ROW[v.severity] : undefined)} />
       <div className="table-foot">{shown.length} of {entries.length} loaded incident{entries.length === 1 ? '' : 's'}</div></div>}
  </>
 );
}

/** The shared incident queue: every row is a real committed incident, shown as soon as it is committed, with the urgency tier, every delivery (failed and uncertain ones named
 * as such), the digest state and the digest-coverage change state. A part whose reader is not wired is listed as not available, never as sent. */
export function IncidentsList(props: { context: ViewContext; open: (project: string, id: string) => void }): React.JSX.Element {
 const shell = useShell();
 const session = React.useContext(SessionContext);
 const state = useQueue(props.context);
 const view = 'data' in state ? state.data : undefined;
 const summary = view ? summarize(view.entries) : undefined;
 const { setCounts } = shell;
 const open = summary?.open;
 const truncated = view?.truncated;
 React.useEffect(() => { if (open !== undefined) setCounts({ incidents: truncated ? undefined : open }); }, [open, truncated, setCounts]);
 const env: RowEnv = { context: props.context, names: shell.names, nowMs: Date.now(), open: (v) => props.open(v.project_id, v.incident_id), href: (v) => shell.href('incidents', { incident: { project: v.project_id, id: v.incident_id } }) };
 const notable = view?.sections.filter((s) => s.state === 'not_available' || s.state === 'incomplete' || s.state === 'stale') ?? [];
 return (
  <>
   {state.kind !== 'ready' && <StatusPanel state={state} />}
   {view && summary && view.entries.length > 0 && (
    <>
     {notable.length > 0 && (
      <Callout tone="warn" role="status">
       <span><strong>Some parts of this list are not complete.</strong> The parts shown are real.</span>
      </Callout>
     )}
     {notable.length > 0 && (
      <ul className="sections" aria-label="Queue sections">
       {notable.map((s) => <li key={s.name} data-section={s.name} data-state={s.state}><strong>{SECTION_TITLE[s.name] ?? s.name}</strong>: {SECTION_LABEL[s.state] ?? 'Unknown'}{s.reason ? ` — ${describeReason(s.reason)}` : ''}</li>)}
      </ul>
     )}
     <Stats summary={summary} />
     <p className="small t2">New incidents appear here as soon as they are committed, not at a scheduled digest time.</p>
     <IncidentTable entries={view.entries} env={env} me={session?.session.user} />
     {view.truncated && <p role="status" className="small">Only the first {view.entries.length} incidents are shown; more exist. Search and the figures above cover only these.</p>}
    </>
   )}
   {view && view.entries.length === 0 && state.kind !== 'empty' && <p className="small t2">No incident was found in the selected projects.</p>}
   {state.kind === 'empty' && <p className="small t2">New incidents appear here as soon as they are committed, not at a scheduled digest time.</p>}
  </>
 );
}
