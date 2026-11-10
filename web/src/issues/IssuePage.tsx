// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, getIssueEvidence, isAbort } from '../api/client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionKind, type ActionRequest, type Id, type IssueEvidenceView, type OccurrenceEvidence } from '../api/types';
import { FrameLookup } from '../artifacts/FrameLookup';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { ISSUE_ACTIONS, ISSUE_ACTION_LABEL, buildIssueAction, occurrenceAncestryWords } from '../evidence/model';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import { describeReason, faultText, newCommandId } from '../incidents/model';

/** What the server has told us about the last action. Nothing here is a committed issue state: the browser holds none, and `not_available` is shown as exactly that. */
type Outcome =
 | { kind: 'idle' }
 | { kind: 'invalid'; text: string }
 | { kind: 'pending' }
 | { kind: 'not_available'; reason: string }
 | { kind: 'conflict'; expected: string; current: string }
 | { kind: 'unknown'; request: ActionRequest }
 | { kind: 'refused'; status: number; detail: string; code: string; requestId: string };

function OccurrenceTable(props: { caption: string; rows: OccurrenceEvidence[]; tz: string; empty: string }): React.JSX.Element {
 const { rows } = props;
 if (rows.length === 0) return <p>{props.empty}</p>;
 return (
  <table className="data-table">
   <caption>{props.caption}</caption>
   <thead><tr><th scope="col">Occurrence</th><th scope="col">Event time</th><th scope="col">Arrived</th><th scope="col">Grouping</th><th scope="col">Release ancestry</th><th scope="col">Freshness</th></tr></thead>
   <tbody>
    {rows.map((o) => (
     <tr key={o.occurrence_id} data-occurrence={o.occurrence_id} data-late={o.late ? 'yes' : 'no'} data-ancestry={o.ancestry}>
      <td><code>{o.occurrence_id}</code>{o.late ? <> <strong>(late)</strong></> : null}</td>
      <td>{formatNs(o.event_time_ns, props.tz)}</td>
      <td>{formatNs(o.arrival_time_ns, props.tz)}</td>
      <td>version {o.grouping_version}, hash <code>{o.fingerprint}</code></td>
      <td>{occurrenceAncestryWords(o)}</td>
      <td>{o.freshness}</td>
     </tr>
    ))}
   </tbody>
  </table>
 );
}

function IssueActions(props: { org: Id; project: Id; view: IssueEvidenceView }): React.JSX.Element {
 const [kind, setKind] = React.useState<ActionKind>('resolve');
 const [reason, setReason] = React.useState('');
 const [outcome, setOutcome] = React.useState<Outcome>({ kind: 'idle' });
 const live = React.useRef<AbortController | null>(null);
 const note = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => () => live.current?.abort(), []);
 React.useEffect(() => { if (outcome.kind !== 'idle') note.current?.focus(); }, [outcome.kind]);
 const send = async (request: ActionRequest): Promise<void> => {
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setOutcome({ kind: 'pending' });
  try {
   const response = await act(request, controller.signal);
   if (controller.signal.aborted) return;
   // The only state the server answers for an issue action today. A committed answer cannot be rendered: the issue view that would carry it does not exist.
   setOutcome({ kind: 'not_available', reason: response.reason ?? 'not_available' });
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   if (error instanceof VersionConflict) setOutcome({ kind: 'conflict', expected: request.expected_version, current: error.currentVersion });
   else if (error instanceof OutcomeUnknown) setOutcome({ kind: 'unknown', request });
   else if (error instanceof ApiFault) setOutcome({ kind: 'refused', status: error.status, detail: error.detail, code: error.code, requestId: error.requestId });
   else setOutcome({ kind: 'refused', status: 0, detail: '', code: 'unavailable', requestId: '' });
  }
 };
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (outcome.kind === 'pending') return;
  const built = buildIssueAction(props.org, props.project, props.view, kind, reason, newCommandId());
  if (!built.ok) { setOutcome({ kind: 'invalid', text: built.error }); return; }
  void send(built.value);
 };
 const pending = outcome.kind === 'pending';
 return (
  <section className="panel" aria-labelledby="issue-action-heading" data-section="issue-actions">
   <h3 id="issue-action-heading">Respond to this issue</h3>
   <p>You are acting on revision <strong data-testid="issue-expected-version">{props.view.grouping?.revision ?? 'unknown'}</strong>. Actions go to the shared action surface; the browser keeps no issue state and shows nothing as changed until the server says so.</p>
   <form onSubmit={submit} aria-label="Issue action" aria-busy={pending}>
    <fieldset disabled={pending}>
     <legend>Action</legend>
     {ISSUE_ACTIONS.map((k) => <label key={k} className="check"><input type="radio" name="issue-action" value={k} checked={k === kind} onChange={() => setKind(k)} /> {ISSUE_ACTION_LABEL[k]}</label>)}
    </fieldset>
    <label>Reason (optional) <textarea name="reason" rows={2} maxLength={512} value={reason} onChange={(e) => setReason(e.target.value)} disabled={pending} /></label>
    <button type="submit" className="primary" disabled={pending}>{pending ? 'Waiting for the server…' : `Submit: ${ISSUE_ACTION_LABEL[kind]}`}</button>
   </form>
   <div ref={note} tabIndex={-1} data-outcome={outcome.kind}>
    {outcome.kind === 'pending' && <p role="status"><strong>Pending.</strong> Waiting for the server. Nothing has changed.</p>}
    {outcome.kind === 'invalid' && <p role="alert" className="error"><strong>Not sent.</strong> {outcome.text}</p>}
    {outcome.kind === 'not_available' && <p role="status" data-testid="issue-action-not-available"><strong>Not available. Nothing was changed.</strong> {describeReason(outcome.reason)}</p>}
    {outcome.kind === 'conflict' && <p role="alert" className="error"><strong>Conflict: not applied.</strong> The issue is now at revision {outcome.current}; you were acting on revision {outcome.expected}. Reload the issue before acting again.</p>}
    {outcome.kind === 'refused' && <p role="alert" className="error"><strong>Not applied.</strong> {faultText(outcome.detail, outcome.status)} Code <code>{outcome.code}</code>.{outcome.requestId && <> Request <code>{outcome.requestId}</code>.</>}</p>}
    {outcome.kind === 'unknown' && (
     <div role="alert" className="error">
      <p><strong>Outcome unknown.</strong> The connection failed after the request was sent, so it may or may not have been applied. Resending the same request is safe: the server returns the original result.</p>
      <button type="button" onClick={() => { void send(outcome.request); }}>Resend the same request</button>
     </div>
    )}
   </div>
  </section>
 );
}

/** Persisted evidence for one issue: the grouping version and hash, every stored occurrence, the late history listed apart, and release ancestry stated as known or unknown. A regression is never computed or guessed here, and parts that have no backing view (occurrence payloads, regression explanations, issue actions) are listed as not available. */
export function IssuePage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const evidence = useEvidence<IssueEvidenceView>(key, (signal) => getIssueEvidence(context.org, project, id, signal));
 const view = dataOf(evidence.state);
 const tz = context.timezone;
 return (
  <section className="panel" aria-labelledby="issue-heading">
   <h2 id="issue-heading">Issue <code>{id}</code></h2>
   <StatusPanel state={evidence.state} />
   {view && (
    <>
     <button type="button" onClick={evidence.reload} disabled={evidence.reloading}>Reload issue</button>
     <EvidenceSections sections={view.sections} />
     {view.grouping && (
      <section className="panel" aria-labelledby="grouping-heading" data-section="grouping">
       <h3 id="grouping-heading">Grouping</h3>
       <dl className="scope-bar">
        <dt>Grouping version</dt><dd data-testid="grouping-version">{view.grouping.grouping_version}</dd>
        <dt>Grouping hash</dt><dd data-testid="grouping-hash"><code>{view.grouping.fingerprint}</code></dd>
        <dt>Workflow state</dt><dd data-testid="workflow">{view.grouping.workflow} (revision {view.grouping.revision})</dd>
        {view.grouping.resolution_time_ns !== undefined && <><dt>Resolved at</dt><dd>{formatNs(view.grouping.resolution_time_ns, tz)}</dd></>}
        <dt>Audited grouping migrations</dt><dd data-testid="migrations">{view.grouping.migration_links.length === 0 ? 'None recorded' : view.grouping.migration_links.map((m) => <code key={m}>{m} </code>)}</dd>
       </dl>
      </section>
     )}
     <section className="panel" aria-labelledby="occ-heading" data-section="occurrences">
      <h3 id="occ-heading">Occurrences</h3>
      <OccurrenceTable caption="Stored occurrences" rows={view.occurrences} tz={tz} empty="No occurrence evidence is stored for this issue." />
      <h4>Late history</h4>
      <p>Evidence that arrived after the issue was resolved is listed here, apart from the occurrences above. It is never merged into them and never rewrites the resolution.</p>
      <OccurrenceTable caption="Late history" rows={view.late_history} tz={tz} empty="No late evidence is recorded." />
      <p data-testid="regression-note">No regression is claimed. A regression needs known release ancestry from a registered release graph and is never inferred from timestamps or release labels; an occurrence with unknown ancestry stays unknown.</p>
     </section>
     <IssueActions org={context.org} project={project} view={view} />
    </>
   )}
   <FrameLookup context={context} project={project} />
  </section>
 );
}
