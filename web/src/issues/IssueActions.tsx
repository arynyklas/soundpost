// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, isAbort } from '../api/client';
import type { ActionKind, ActionRequest, Id, IssueEvidenceView } from '../api/types';
import { ISSUE_ACTIONS, ISSUE_ACTION_LABEL } from '../evidence/model';
import { describeReason, faultText, newCommandId } from '../incidents/model';
import { conflictWords, settleIssueAction, submitIssueAction, type IssueOutcome, type Settlement } from './actionModel';

/** Resolve, ignore, stop ignoring and reopen go to the shared version-checked action surface with the revision on screen and a reason. The issue on screen changes only when the server answers committed, and then the page re-reads the stored issue instead of trusting its own guess. The transitions themselves are in actionModel.ts. */
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
  let settlement: Settlement;
  try {
   const response = await act(request, controller.signal);
   if (controller.signal.aborted) return;
   settlement = settleIssueAction(request, { kind: 'answer', response });
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   settlement = settleIssueAction(request, { kind: 'failure', error });
  }
  setOutcome(settlement.outcome);
  if (settlement.clearForm) { setReason(''); setFixedIn(''); }
  if (settlement.reload) props.onChanged();
 };
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  const next = submitIssueAction({ org: props.org, project: props.project, view: props.view, kind, reason, fixedIn, outcome, busy: props.busy, commandId: newCommandId() });
  if (next.request === null) { if (next.outcome !== outcome) setOutcome(next.outcome); return; }
  void send(next.request);
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
