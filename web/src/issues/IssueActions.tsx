// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, isAbort } from '../api/client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionKind, type ActionRequest, type Id, type IssueActionView, type IssueEvidenceView } from '../api/types';
import { ISSUE_ACTIONS, ISSUE_ACTION_LABEL, buildIssueAction } from '../evidence/model';
import { describeReason, faultText, newCommandId } from '../incidents/model';

/** What the server has told us about the last action. A committed answer is the issue exactly as the lifecycle committed it; the browser holds no issue state of its own, and `not_available` is shown as exactly that. */
export type IssueOutcome =
 | { kind: 'idle' }
 | { kind: 'invalid'; text: string }
 | { kind: 'pending' }
 | { kind: 'committed'; action: ActionKind; issue: IssueActionView }
 | { kind: 'not_available'; reason: string }
 | { kind: 'conflict'; detail: string; expected: string; current: string }
 | { kind: 'unknown'; request: ActionRequest }
 | { kind: 'refused'; status: number; detail: string; code: string; requestId: string };

/** The one sentence a conflict gets: a moved revision and a transition the workflow does not allow are different facts and are never merged. */
export function conflictWords(detail: string, expected: string, current: string): string {
 return detail === 'issue_state_conflict'
  ? `The issue is at revision ${current}, the revision you acted on, but its workflow state does not allow this action (for example: resolving an issue that is already resolved, or reopening one that is not resolved). Nothing was changed.`
  : `The issue is now at revision ${current}; you were acting on revision ${expected}. Nothing was changed. The page is reloading the issue so you can act on what is there now.`;
}

/** Resolve, ignore, stop ignoring and reopen go to the shared version-checked action surface with the revision on screen and a reason. The issue on screen changes only when the server answers committed, and then the page re-reads the stored issue instead of trusting its own guess. */
export function IssueActions(props: { org: Id; project: Id; view: IssueEvidenceView; busy: boolean; onChanged: () => void }): React.JSX.Element {
 const [kind, setKind] = React.useState<ActionKind>('resolve');
 const [reason, setReason] = React.useState('');
 const [fixedIn, setFixedIn] = React.useState('');
 const [outcome, setOutcome] = React.useState<IssueOutcome>({ kind: 'idle' });
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
   if (response.state === 'committed' && response.issue) {
    setOutcome({ kind: 'committed', action: request.kind, issue: response.issue });
    setReason('');
    setFixedIn('');
    props.onChanged();
   } else setOutcome({ kind: 'not_available', reason: response.reason ?? 'not_available' });
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   if (error instanceof VersionConflict) {
    setOutcome({ kind: 'conflict', detail: error.detail, expected: request.expected_version, current: error.currentVersion });
    props.onChanged();
   } else if (error instanceof OutcomeUnknown) setOutcome({ kind: 'unknown', request });
   else if (error instanceof ApiFault) setOutcome({ kind: 'refused', status: error.status, detail: error.detail, code: error.code, requestId: error.requestId });
   else setOutcome({ kind: 'refused', status: 0, detail: '', code: 'unavailable', requestId: '' });
  }
 };
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (outcome.kind === 'pending' || props.busy) return;
  const built = buildIssueAction(props.org, props.project, props.view, kind, reason, newCommandId(), kind === 'resolve' ? fixedIn : '');
  if (!built.ok) { setOutcome({ kind: 'invalid', text: built.error }); return; }
  void send(built.value);
 };
 const pending = outcome.kind === 'pending' || props.busy;
 return (
  <section className="panel" aria-labelledby="issue-action-heading" data-section="issue-actions">
   <h3 id="issue-action-heading">Respond to this issue</h3>
   <p>You are acting on revision <strong data-testid="issue-expected-version">{props.view.grouping?.revision ?? 'unknown'}</strong>. Actions go to the shared action surface and are refused, not merged, if the issue has moved; the browser keeps no issue state and shows nothing as changed until the server says so.</p>
   <form onSubmit={submit} aria-label="Issue action" aria-busy={pending}>
    <fieldset disabled={pending}>
     <legend>Action</legend>
     {ISSUE_ACTIONS.map((k) => <label key={k} className="check"><input type="radio" name="issue-action" value={k} checked={k === kind} onChange={() => setKind(k)} /> {ISSUE_ACTION_LABEL[k]}</label>)}
    </fieldset>
    <label>Reason (recorded in the audit trail) <textarea name="reason" rows={2} maxLength={512} value={reason} onChange={(e) => setReason(e.target.value)} disabled={pending} required /></label>
    {kind === 'resolve' && (
     <label>Fixed in releases (optional; release IDs, comma separated, at most 16) <input name="fixed-in" value={fixedIn} onChange={(e) => setFixedIn(e.target.value)} disabled={pending} autoComplete="off" spellCheck={false} /></label>
    )}
    <button type="submit" className="primary" disabled={pending}>{outcome.kind === 'pending' ? 'Waiting for the server…' : `Submit: ${ISSUE_ACTION_LABEL[kind]}`}</button>
   </form>
   <div ref={note} tabIndex={-1} data-outcome={outcome.kind}>
    {outcome.kind === 'pending' && <p role="status"><strong>Pending.</strong> Waiting for the server. Nothing has changed.</p>}
    {outcome.kind === 'invalid' && <p role="alert" className="error"><strong>Not sent.</strong> {outcome.text}</p>}
    {outcome.kind === 'committed' && (
     <p role="status" data-testid="issue-action-committed"><strong>{ISSUE_ACTION_LABEL[outcome.action]} committed.</strong> The server says the issue is now <strong>{outcome.issue.workflow}</strong> at revision <strong>{outcome.issue.revision}</strong>.</p>
    )}
    {outcome.kind === 'not_available' && <p role="status" data-testid="issue-action-not-available"><strong>Not available. Nothing was changed.</strong> {describeReason(outcome.reason)}</p>}
    {outcome.kind === 'conflict' && <p role="alert" className="error" data-testid="issue-action-conflict" data-conflict={outcome.detail}><strong>Conflict: not applied.</strong> {conflictWords(outcome.detail, outcome.expected, outcome.current)}</p>}
    {outcome.kind === 'refused' && <p role="alert" className="error" data-testid="issue-action-refused"><strong>Not applied.</strong> {faultText(outcome.detail, outcome.status)} Code <code>{outcome.code}</code>.{outcome.requestId && <> Request <code>{outcome.requestId}</code>.</>}</p>}
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
