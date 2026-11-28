// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, isAbort } from '../api/client';
import type { ActionKind, ActionRequest, Id, IncidentView, IssueEvidenceView } from '../api/types';
import { ISSUE_ACTION_LABEL } from '../evidence/model';
import { describeReason, faultText, newCommandId } from '../incidents/model';
import type { Names } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Dialog, Person } from '../ui/primitives';
import { conflictWords, settleIssueAction, submitIssueAction, type IssueOutcome, type Settlement } from './actionModel';
import { ASSIGN_UNAVAILABLE_TEXT, assignUnavailable, buildAssignAction, consequences, type IssueActionChoice } from './pageModel';

/** The actions one workflow state offers as buttons. The form behind them still lets a person pick any of the four: the server, not this page, decides which transition the workflow allows, and a forbidden one is answered as a conflict. */
export function actionsFor(workflow: string | undefined): IssueActionChoice[] {
 switch (workflow) {
  case 'open': return ['resolve', 'ignore'];
  case 'ignored': return ['unignore'];
  case 'resolved': return ['reopen'];
  default: return [];
 }
}
const BUTTON_LABEL: Record<IssueActionChoice, string> = { resolve: 'Resolve error issue', ignore: 'Ignore', unignore: 'Stop ignoring', reopen: 'Reopen' };
const CHOICES: readonly IssueActionChoice[] = ['resolve', 'ignore', 'unignore', 'reopen'];

/** One request to the shared version-checked action surface at a time. The issue on screen changes only when the server answers committed, and then the page re-reads the stored issue instead of trusting its own guess. The transitions themselves are in actionModel.ts. */
function useIssueRequest(onChanged: () => void, onSettled: (outcome: IssueOutcome) => void): { outcome: IssueOutcome; setOutcome: (o: IssueOutcome) => void; send: (request: ActionRequest) => Promise<Settlement | null>; pending: boolean } {
 const [outcome, setOutcome] = React.useState<IssueOutcome>({ kind: 'idle' });
 const live = React.useRef<AbortController | null>(null);
 React.useEffect(() => () => live.current?.abort(), []);
 const send = async (request: ActionRequest): Promise<Settlement | null> => {
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setOutcome({ kind: 'pending' });
  let settlement: Settlement;
  try {
   const response = await act(request, controller.signal);
   if (controller.signal.aborted) return null;
   settlement = settleIssueAction(request, { kind: 'answer', response });
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return null;
   settlement = settleIssueAction(request, { kind: 'failure', error });
  }
  setOutcome(settlement.outcome);
  onSettled(settlement.outcome);
  if (settlement.reload) onChanged();
  return settlement;
 };
 return { outcome, setOutcome, send, pending: outcome.kind === 'pending' };
}

function Outcome(props: { outcome: IssueOutcome; send: (request: ActionRequest) => Promise<Settlement | null>; testPrefix?: string }): React.JSX.Element {
 const { outcome } = props;
 const note = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => { if (outcome.kind !== 'idle') note.current?.focus(); }, [outcome.kind]);
 return (
  <div ref={note} tabIndex={-1} data-outcome={outcome.kind}>
   {outcome.kind === 'pending' && <p role="status"><strong>Pending.</strong> Waiting for the server. Nothing has changed.</p>}
   {outcome.kind === 'invalid' && <p role="alert" className="error"><strong>Not sent.</strong> {outcome.text}</p>}
   {outcome.kind === 'committed' && (
    <p role="status" data-testid="issue-action-committed"><strong>{ISSUE_ACTION_LABEL[outcome.action] ?? 'Change'} committed.</strong> The server says the issue is now <strong>{outcome.issue.workflow}</strong> at revision <strong>{outcome.issue.revision}</strong>.</p>
   )}
   {outcome.kind === 'not_available' && <p role="status" data-testid="issue-action-not-available"><strong>Not available. Nothing was changed.</strong> {describeReason(outcome.reason)}</p>}
   {outcome.kind === 'conflict' && <p role="alert" className="error" data-testid="issue-action-conflict" data-conflict={outcome.detail}><strong>Conflict: not applied.</strong> {conflictWords(outcome.detail, outcome.expected, outcome.current)}</p>}
   {outcome.kind === 'refused' && <p role="alert" className="error" data-testid="issue-action-refused"><strong>Not applied.</strong> {faultText(outcome.detail, outcome.status)} Code <code>{outcome.code}</code>.{outcome.requestId && <> Request <code>{outcome.requestId}</code>.</>}</p>}
   {outcome.kind === 'unknown' && (
    <div role="alert" className="error">
     <p><strong>Outcome unknown.</strong> The connection failed after the request was sent, so it may or may not have been applied. Resending the same request is safe: the server returns the original result.</p>
     <button type="button" onClick={() => { void props.send(outcome.request); }}>Resend the same request</button>
    </div>
   )}
  </div>
 );
}

/** The body of the action dialog: which action, the reason (recorded in the audit trail), the fix releases of a resolve, and in words what the action does to the other entities. */
export function IssueActionForm(props: { org: Id; project: Id; view: IssueEvidenceView; busy: boolean; initialKind: IssueActionChoice; incidents: readonly IncidentView[] | null; onChanged: () => void; onCommitted: (outcome: IssueOutcome) => void; onPending: (pending: boolean) => void; onCancel: () => void }): React.JSX.Element {
 const [kind, setKind] = React.useState<IssueActionChoice>(props.initialKind);
 const [reason, setReason] = React.useState('');
 const [fixedIn, setFixedIn] = React.useState('');
 const clear = React.useRef<() => void>(() => undefined);
 clear.current = () => { setReason(''); setFixedIn(''); };
 const { outcome, setOutcome, send, pending } = useIssueRequest(props.onChanged, (o) => { if (o.kind === 'committed') { clear.current(); props.onCommitted(o); } });
 React.useEffect(() => { props.onPending(pending); }, [pending]);
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  const next = submitIssueAction({ org: props.org, project: props.project, view: props.view, kind: kind as ActionKind, reason, fixedIn, outcome, busy: props.busy, commandId: newCommandId() });
  if (next.request === null) { if (next.outcome !== outcome) setOutcome(next.outcome); return; }
  void send(next.request);
 };
 const busy = pending || props.busy;
 const fixed = kind === 'resolve' ? fixedIn.split(/[\s,]+/).filter((s) => /^[0-9a-f]{32}$/.test(s)) : [];
 return (
  <form onSubmit={submit} aria-label="Issue action" aria-busy={busy} className="modal-body">
   <fieldset disabled={busy}>
    <legend>Action</legend>
    <div className="iss-radios">
     {CHOICES.map((k) => <label key={k} className="check"><input type="radio" name="issue-action" value={k} checked={k === kind} onChange={() => setKind(k)} /> {ISSUE_ACTION_LABEL[k]}</label>)}
    </div>
   </fieldset>
   <label>Reason (recorded in the audit trail) <textarea name="reason" rows={3} maxLength={512} value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} required data-autofocus /></label>
   {kind === 'resolve' && (
    <label>Fixed in releases (optional; release IDs, comma separated, at most 16) <input name="fixed-in" value={fixedIn} onChange={(e) => setFixedIn(e.target.value)} disabled={busy} autoComplete="off" spellCheck={false} /></label>
   )}
   <div className="col g4" data-testid="issue-action-consequences">
    <span className="small bold">What this does</span>
    <ul className="consequences">
     {consequences(kind, props.incidents, fixed).map((c) => <li key={c.key}><Icon name={c.icon} size="s" /><span>{c.text}</span></li>)}
    </ul>
   </div>
   <Outcome outcome={outcome} send={send} />
   <div className="row wrap">
    <span className="xsmall t3 grow">You act on revision {props.view.grouping?.revision ?? 'unknown'}. If the issue has moved, nothing is applied.</span>
    <button type="button" className="btn" onClick={props.onCancel} disabled={pending}>Cancel</button>
    <button type="submit" className="btn btn-primary" disabled={busy}>{outcome.kind === 'pending' ? 'Waiting for the server…' : `Submit: ${ISSUE_ACTION_LABEL[kind]}`}</button>
   </div>
  </form>
 );
}

/** The owner dialog. The owner must be a member of the organization; a name is offered only for a member whose display name is known, and any other member is entered by account ID. */
export function ReassignForm(props: { org: Id; project: Id; view: IssueEvidenceView; busy: boolean; names: Names; owner: Id | undefined; onChanged: () => void; onCommitted: (outcome: IssueOutcome) => void; onUnavailable: () => void; onPending: (pending: boolean) => void; onCancel: () => void }): React.JSX.Element {
 const [owner, setOwner] = React.useState<string>(props.owner ?? '');
 const [typed, setTyped] = React.useState('');
 const { outcome, setOutcome, send, pending } = useIssueRequest(props.onChanged, (o) => {
  if (o.kind === 'committed') props.onCommitted(o);
  else if (assignUnavailable(o)) props.onUnavailable();
 });
 React.useEffect(() => { props.onPending(pending); }, [pending]);
 const members = [...props.names.members].sort((a, b) => a[1].localeCompare(b[1]));
 const chosen = typed.trim() !== '' ? typed.trim() : owner;
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (pending || props.busy) return;
  const built = buildAssignAction(props.org, props.project, props.view, chosen, newCommandId());
  if (!built.ok) { setOutcome({ kind: 'invalid', text: built.error }); return; }
  void send(built.value);
 };
 const busy = pending || props.busy;
 return (
  <form onSubmit={submit} aria-label="Assign an owner" aria-busy={busy} className="modal-body">
   <label>Owner
    <select name="owner" value={owner} onChange={(e) => setOwner(e.target.value)} disabled={busy} data-autofocus>
     <option value="">Unassigned</option>
     {members.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
     {props.owner !== undefined && !props.names.members.has(props.owner) && <option value={props.owner}>{`Member ${props.owner.slice(0, 8)}…`}</option>}
    </select>
   </label>
   <label>Or a member account ID <input name="owner-id" value={typed} onChange={(e) => setTyped(e.target.value)} disabled={busy} autoComplete="off" spellCheck={false} placeholder="32 hexadecimal characters" /></label>
   <p className="small t2">The owner must be a member of the organization; the server refuses anyone else and nothing changes. You act on revision {props.view.grouping?.revision ?? 'unknown'}.</p>
   <Outcome outcome={outcome} send={send} />
   <div className="row">
    <button type="button" className="btn ml-auto" onClick={props.onCancel} disabled={pending}>Cancel</button>
    <button type="submit" className="btn btn-primary" disabled={busy}>{pending ? 'Waiting for the server…' : chosen === '' ? 'Remove the owner' : 'Assign'}</button>
   </div>
  </form>
 );
}

/** The actions of the issue page: the buttons its workflow state offers, the owner button and the dialogs behind them. A committed change closes the dialog and is said on the page; a conflict, a refusal or an unknown outcome stays in the dialog with its words. */
export function IssueActions(props: { org: Id; project: Id; view: IssueEvidenceView; busy: boolean; names: Names; owner: Id | undefined; incidents: readonly IncidentView[] | null; onChanged: () => void; extra?: React.ReactNode }): React.JSX.Element {
 const [dialog, setDialog] = React.useState<{ type: 'action'; kind: IssueActionChoice } | { type: 'owner' } | null>(null);
 const [pending, setPending] = React.useState(false);
 const [committed, setCommitted] = React.useState<IssueOutcome | null>(null);
 const [assignOff, setAssignOff] = React.useState(false);
 const workflow = props.view.grouping?.workflow;
 const buttons = actionsFor(workflow);
 const close = (): void => { if (!pending) setDialog(null); };
 const done = (outcome: IssueOutcome): void => { setCommitted(outcome); setDialog(null); setPending(false); };
 return (
  <>
   <div className="row wrap iss-actions" role="group" aria-label="Issue actions">
    {buttons.map((k, i) => (
     <button key={k} type="button" className={i === 0 && k === 'resolve' ? 'btn btn-primary' : 'btn'} data-testid="issue-action-open" onClick={() => { setCommitted(null); setDialog({ type: 'action', kind: k }); }}>
      <Icon name={k === 'resolve' ? 'check' : k === 'ignore' ? 'snooze' : 'bug'} size="s" />{BUTTON_LABEL[k]}
     </button>
    ))}
    <button type="button" className="btn" data-testid="issue-reassign" disabled={assignOff || props.view.grouping === undefined} aria-describedby={assignOff ? 'issue-assign-off' : undefined} onClick={() => { setCommitted(null); setDialog({ type: 'owner' }); }}>
     <Icon name="user" size="s" />Reassign
    </button>
    {props.extra}
    <span className="ml-auto row sm t2 small">Assigned to <Person id={props.owner} name={props.owner ? props.names.members.get(props.owner) : undefined} /></span>
   </div>
   {assignOff && <p id="issue-assign-off" className="small t2 iss-note" role="status" data-testid="issue-assign-unavailable">{ASSIGN_UNAVAILABLE_TEXT}</p>}
   {committed !== null && committed.kind === 'committed' && (
    <p role="status" className="small iss-note" data-testid="issue-action-committed"><strong>{ISSUE_ACTION_LABEL[committed.action] ?? 'Change'} committed.</strong> The server says the issue is now <strong>{committed.issue.workflow}</strong> at revision <strong>{committed.issue.revision}</strong>.</p>
   )}
   <Dialog open={dialog?.type === 'action'} onClose={close} title={dialog?.type === 'action' ? `${ISSUE_ACTION_LABEL[dialog.kind]}: error issue` : 'Issue action'} testId="issue-action-dialog">
    {dialog?.type === 'action' && <IssueActionForm org={props.org} project={props.project} view={props.view} busy={props.busy} initialKind={dialog.kind} incidents={props.incidents} onChanged={props.onChanged} onCommitted={done} onPending={setPending} onCancel={close} />}
   </Dialog>
   <Dialog open={dialog?.type === 'owner'} onClose={close} title="Assign an owner" testId="issue-owner-dialog">
    {dialog?.type === 'owner' && <ReassignForm org={props.org} project={props.project} view={props.view} busy={props.busy} names={props.names} owner={props.owner} onChanged={props.onChanged} onCommitted={done} onUnavailable={() => setAssignOff(true)} onPending={setPending} onCancel={close} />}
   </Dialog>
  </>
 );
}
