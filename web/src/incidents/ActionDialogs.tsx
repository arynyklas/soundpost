// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { Icon } from '../ui/Icon';
import { Callout, Dialog } from '../ui/primitives';
import type { IncidentActionKind } from '../api/types';
import { ACTION_LABEL, CONDITION_STATES, DURATIONS, FRESHNESS, LINK_KINDS, MAX_TITLE_BYTES, SEVERITIES, describeReason, faultText, reasonRequired } from './model';
import { LOST_RACE_WORDS, resolveConsequences } from './pageModel';
import type { IncidentActions, Outcome } from './useIncidentActions';

const DIALOG_TITLE: Record<IncidentActionKind, string> = {
 ack: 'Acknowledge this incident', assign: 'Assign an owner', resolve: 'Resolve incident', link: 'Link evidence', impact: 'Report impact', snooze: 'Snooze reminders', unsnooze: 'End the snooze',
 maintenance: 'Start maintenance', maintenance_end: 'End maintenance', title: 'Set the title', note: 'Add a note',
};
export const SUBMIT_LABEL: Record<IncidentActionKind, string> = { ...ACTION_LABEL, resolve: 'Resolve incident', assign: 'Assign owner' };
const WHAT: Partial<Record<IncidentActionKind, string>> = {
 ack: 'Pauses reminders for the current impact. It does not change the alert source, which stays as reported, and a worse impact still notifies.',
 snooze: 'Pauses reminders until the snooze ends. A worse impact still notifies, and the alert source stays as reported.',
 unsnooze: 'Reminders resume at once.',
 maintenance: 'Suppresses new notifications for this incident until the window ends. The alert source stays as reported.',
 maintenance_end: 'Notifications resume at once.',
 impact: 'Records an impact observation by a person. A recovery can only be reported from fresh data: missing or stale data is unknown, not recovered.',
 link: 'Links another record to this incident as evidence. Nothing is changed on the linked record.',
};
const hasReason = (kind: IncidentActionKind): boolean => kind !== 'title' && kind !== 'note';

/** The words of what the server has and has not said. Pending, not-applied and unknown outcomes are never shown as committed. */
export function OutcomeView(props: { actions: IncidentActions; outcome: Outcome }): React.JSX.Element {
 const { outcome, actions } = props;
 const { view } = actions;
 const ref = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => { if (outcome.kind !== 'idle') ref.current?.focus(); }, [outcome.kind]);
 return (
  <div ref={ref} tabIndex={-1} data-outcome={outcome.kind}>
   {outcome.kind === 'pending' && <p role="status"><strong>Pending.</strong> Waiting for the server to acknowledge. Nothing is committed yet and the incident has not changed.</p>}
   {outcome.kind === 'invalid' && <p role="alert" className="error"><strong>Not sent.</strong> {outcome.text}</p>}
   {outcome.kind === 'committed' && <p role="status"><strong>Committed.</strong> The server acknowledged revision {outcome.revision} ({ACTION_LABEL[outcome.action]}).</p>}
   {outcome.kind === 'not_available' && <p role="status"><strong>Not available.</strong> {outcome.reason === 'action_not_served' ? 'This installation does not serve this action yet. Nothing was changed.' : describeReason(outcome.reason)}</p>}
   {outcome.kind === 'refused' && <p role="alert" className="error"><strong>Not applied.</strong> {faultText(outcome.detail, outcome.status)}{outcome.code && <> Code <code>{outcome.code}</code>.</>}{outcome.requestId && <> Request <code>{outcome.requestId}</code>.</>} Your draft is kept.</p>}
   {outcome.kind === 'unknown' && (
    <div role="alert" className="error">
     <p><strong>Outcome unknown.</strong> The connection failed after the request was sent, so it may or may not have been applied. Do not assume it failed. Resending the same request is safe: the server returns the original result instead of applying it twice.</p>
     <button type="button" onClick={() => actions.resend(outcome.request)}>Resend the same request</button>
    </div>
   )}
   {outcome.kind === 'conflict' && (outcome.expected !== view.version
    ? <p role="alert" className="error" data-conflict="reloaded"><strong>Reloaded.</strong> The incident is now at revision {view.version}; your action expected revision {outcome.expected} and was not applied. Review what changed, then submit again. Your draft is kept.</p>
    : (
     <div role="alert" className="error" data-conflict="current">
      <p><strong>Conflict: not applied.</strong> Another action committed first. The incident is now at revision <strong data-testid="current-version">{outcome.current}</strong>; you were acting on revision {outcome.expected}. Nothing of yours was applied and nothing was retried. Your draft is kept.</p>
      <button type="button" onClick={actions.reload} disabled={actions.reloading}>Reload the current incident</button>
     </div>
    ))}
  </div>
 );
}

/** The result of an action while no dialog is open (committed, or an unknown outcome the person closed the dialog on). */
export function PageOutcome(props: { actions: IncidentActions }): React.JSX.Element | null {
 const { actions } = props;
 if (actions.open !== null || actions.outcome.kind === 'idle') return null;
 return <OutcomeView actions={actions} outcome={actions.outcome} />;
}

export interface Member { id: string; name: string }

function Fields(props: { actions: IncidentActions; kind: IncidentActionKind; members: readonly Member[]; me: string | undefined }): React.JSX.Element {
 const { actions, kind, members, me } = props;
 const { draft, view, pending } = actions;
 const set = actions.set;
 return (
  <>
   {WHAT[kind] && <p className="small t2">{WHAT[kind]}</p>}
   {kind === 'resolve' && (
    <>
     {view.source_firing && <div role="note"><Callout tone="crit"><span><strong>The alert source is still firing.</strong> Resolving is a human decision about this incident; it does not recover the source. A reason is required.</span></Callout></div>}
     <div className="col g4"><span className="small bold">What resolving does</span>
      <ul className="consequences">
       {resolveConsequences(view).map((c) => <li key={c.text}><Icon name={c.icon} size="s" className={c.tone === 'ok' ? 'tone-ok' : c.tone === 'crit' ? 'tone-crit' : c.tone === 'high' ? 'tone-high' : 't3'} /><span>{c.text}</span></li>)}
      </ul>
     </div>
    </>
   )}
   {kind === 'assign' && (
    <div className="col g4">
     <label>Owner user ID (empty removes the owner) <input name="owner" value={draft.owner} onChange={(e) => set({ owner: e.target.value })} autoComplete="off" spellCheck={false} disabled={pending} data-autofocus /></label>
     <div className="row wrap">
      {me && <button type="button" disabled={pending} onClick={() => set({ owner: me })}>Use my user ID</button>}
      {members.length > 0 && <label className="inc-member">Or choose a member <select value={members.some((m) => m.id === draft.owner) ? draft.owner : ''} onChange={(e) => set({ owner: e.target.value })} disabled={pending}><option value="">Choose a member…</option>{members.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}</select></label>}
     </div>
    </div>
   )}
   {kind === 'link' && (
    <div className="inc-fields">
     <label>Evidence kind <select name="link-kind" value={draft.linkKind} onChange={(e) => set({ linkKind: LINK_KINDS.find((l) => l === e.target.value) ?? 'issue' })} disabled={pending}>{LINK_KINDS.map((l) => <option key={l} value={l}>{l}</option>)}</select></label>
     <label>Evidence ID <input name="link-id" value={draft.linkId} onChange={(e) => set({ linkId: e.target.value })} autoComplete="off" spellCheck={false} disabled={pending} data-autofocus /></label>
    </div>
   )}
   {kind === 'impact' && (
    <div className="inc-fields">
     <label>Severity <select name="severity" value={draft.severity} onChange={(e) => set({ severity: SEVERITIES.find((s) => s === e.target.value) ?? 'major' })} disabled={pending}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
     <label>Source state <select name="state" value={draft.state} onChange={(e) => set({ state: CONDITION_STATES.find((s) => s === e.target.value) ?? 'firing' })} disabled={pending}>{CONDITION_STATES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
     <label>Data freshness <select name="freshness" value={draft.freshness} onChange={(e) => set({ freshness: FRESHNESS.find((s) => s === e.target.value) ?? 'fresh' })} disabled={pending}>{FRESHNESS.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
    </div>
   )}
   {(kind === 'snooze' || kind === 'maintenance') && (
    <label>Duration <select name="duration" value={draft.minutes} onChange={(e) => set({ minutes: Number(e.target.value) })} disabled={pending}>{DURATIONS.map((d) => <option key={d.minutes} value={d.minutes}>{d.label}</option>)}</select></label>
   )}
   {kind === 'title' && <label>Title (1 to {MAX_TITLE_BYTES} bytes) <input name="title" value={draft.title} onChange={(e) => set({ title: e.target.value })} autoComplete="off" disabled={pending} data-autofocus /></label>}
   {hasReason(kind) && <label>Reason{reasonRequired(kind) ? ' (required)' : ' (optional)'} <textarea name="reason" rows={3} maxLength={512} value={draft.reason} onChange={(e) => set({ reason: e.target.value })} disabled={pending} data-autofocus={kind === 'resolve' || kind === 'ack' || undefined} /></label>}
  </>
 );
}

/** The dialog of the open action. It holds the draft, says which revision the person is acting on and what happens when someone else commits first. */
export function ActionDialog(props: { actions: IncidentActions; members: readonly Member[]; me: string | undefined }): React.JSX.Element | null {
 const { actions } = props;
 const kind = actions.open;
 if (kind === null) return null;
 const pending = actions.pending;
 return (
  <Dialog open onClose={actions.close} title={DIALOG_TITLE[kind]} testId="incident-action-dialog">
   <form className="modal-body" aria-label="Incident action" aria-busy={pending} onSubmit={(e) => { e.preventDefault(); actions.submit(); }}>
    <p className="small">You are acting on revision <strong data-testid="expected-version">{actions.view.version}</strong>. {LOST_RACE_WORDS}</p>
    <Fields actions={actions} kind={kind} members={props.members} me={props.me} />
    <OutcomeView actions={actions} outcome={actions.outcome} />
    <div className="row wrap inc-dialog-foot">
     <button type="button" className="ml-auto" onClick={actions.close}>Cancel</button>
     <button type="submit" className={kind === 'resolve' ? 'btn-primary' : 'primary'} disabled={pending}>{pending ? 'Waiting for the server…' : SUBMIT_LABEL[kind]}</button>
    </div>
   </form>
  </Dialog>
 );
}
