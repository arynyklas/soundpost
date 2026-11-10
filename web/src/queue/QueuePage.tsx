// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getQueue, isAbort, stateOfFault } from '../api/client';
import type { IncidentView, LoadState, QueueView } from '../api/types';
import { PAGE_LIMIT, encodeHash, formatNs, latestOnly, scopeKey, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { describeReason, rateText, responseWords, sourceWords } from '../incidents/model';

function stateOfQueue(view: QueueView): LoadState<QueueView> {
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

function Row(props: { entry: IncidentView; context: ViewContext }): React.JSX.Element {
 const e = props.entry;
 const tz = props.context.timezone;
 return (
  <tr data-incident={e.incident_id} data-status={e.status}>
   <th scope="row"><a href={encodeHash(props.context, 'incidents', '', { project: e.project_id, id: e.incident_id })}>Incident <code>{e.incident_id}</code></a><br />Project <code>{e.project_id}</code>, revision {e.version}</th>
   <td>{e.status === 'open' ? 'Open' : 'Resolved by a person'}<br />Severity {e.severity}</td>
   <td>{sourceWords(e)}<br />{rateText(e, (ns) => formatNs(ns, tz))}</td>
   <td>{e.owner ? <>Owner <code>{e.owner}</code></> : 'Unassigned'}</td>
   <td><ul>{responseWords(e).filter((w) => !w.startsWith('Owner') && w !== 'Unassigned' && w !== 'Open').map((w) => <li key={w}>{w}</li>)}</ul>{e.ack === undefined && e.status === 'open' && !e.snooze?.active && !e.maintenance?.active && 'Not acknowledged'}</td>
   <td>Last activity {formatNs(e.last_activity, tz)}<br />Unread change: not available</td>
   <td data-cell="delivery">Delivery: not available<br />{e.notification.worse_impact_eligible ? 'Worse impact eligible' : 'Worse impact not eligible'}</td>
  </tr>
 );
}

/** The shared incident queue: every row is a real committed incident, shown as soon as it is
 * committed. Urgency, delivery attempts, the digest and unread changes belong to services that do
 * not exist yet and are listed as not available, never as empty, sent or healthy. */
export function QueuePage(props: { context: ViewContext }): React.JSX.Element {
 const state = useQueue(props.context);
 const view = 'data' in state ? state.data : undefined;
 return (
  <section className="panel" aria-labelledby="view-heading">
   <h2 id="view-heading">Queue</h2>
   <StatusPanel state={state} />
   {view && (
    <>
     <ul className="sections" aria-label="Queue sections">
      {view.sections.map((s) => (
       <li key={s.name} data-section={s.name} data-state={s.state}><strong>{SECTION_TITLE[s.name] ?? s.name}</strong>: {SECTION_LABEL[s.state] ?? 'Unknown'}{s.reason ? ` — ${describeReason(s.reason)}` : ''}</li>
      ))}
     </ul>
     <p>New incidents appear here as soon as they are committed, not at a scheduled digest time.</p>
     {view.entries.length === 0
      ? <p>No incident was found in the selected projects.</p>
      : (
       <table className="queue-table">
        <caption>Incidents in the selected projects, open first, then by impact severity and recent activity (this is not the canonical urgency order)</caption>
        <thead><tr><th scope="col">Incident</th><th scope="col">Response status</th><th scope="col">Alert condition</th><th scope="col">Owner</th><th scope="col">Acknowledgement, snooze, maintenance</th><th scope="col">Activity</th><th scope="col">Notifications</th></tr></thead>
        <tbody>{view.entries.map((e) => <Row key={`${e.project_id}:${e.incident_id}`} entry={e} context={props.context} />)}</tbody>
       </table>
      )}
     {view.truncated && <p role="status">Only the first {view.entries.length} incidents are shown; more exist.</p>}
    </>
   )}
  </section>
 );
}
