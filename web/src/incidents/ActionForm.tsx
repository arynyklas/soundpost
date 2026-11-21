// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, isAbort } from '../api/client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionRequest, type IncidentActionKind, type IncidentView } from '../api/types';
import { SessionContext } from '../auth/ElevationDialog';
import { ACTION_LABEL, CONDITION_STATES, DURATIONS, FRESHNESS, LINK_KINDS, SEVERITIES, availableActions, buildRequest, describeReason, emptyDraft, faultText, newCommandId, reasonRequired, type Draft } from './model';

/** What the server has and has not told us about the last submission. Nothing here is a committed
 * status: `committed` exists only after the server acknowledged the action. */
type Outcome =
 | { kind: 'idle' }
 | { kind: 'invalid'; text: string }
 | { kind: 'pending' }
 | { kind: 'conflict'; expected: string; current: string; requestId: string }
 | { kind: 'unknown'; request: ActionRequest }
 | { kind: 'refused'; status: number; detail: string; code: string; requestId: string }
 | { kind: 'not_available'; reason: string }
 | { kind: 'committed'; revision: string; action: IncidentActionKind };

export function ActionForm(props: { view: IncidentView; onCommitted: (view: IncidentView) => void; onReload: () => void; reloading: boolean }): React.JSX.Element {
 const { view } = props;
 const session = React.useContext(SessionContext);
 const kinds = availableActions(view);
 const [draft, setDraft] = React.useState<Draft>(() => emptyDraft(kinds[0] ?? 'ack'));
 const [outcome, setOutcome] = React.useState<Outcome>({ kind: 'idle' });
 const live = React.useRef<AbortController | null>(null);
 const note = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => () => live.current?.abort(), []);
 React.useEffect(() => { if (outcome.kind !== 'idle') note.current?.focus(); }, [outcome.kind]);
 const kind: IncidentActionKind = kinds.includes(draft.kind) ? draft.kind : (kinds[0] ?? 'ack');
 const effective: Draft = { ...draft, kind };
 const set = (patch: Partial<Draft>): void => setDraft((d) => ({ ...d, ...patch }));

 const send = async (request: ActionRequest): Promise<void> => {
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setOutcome({ kind: 'pending' });
  try {
   const response = await act(request, controller.signal);
   if (controller.signal.aborted) return;
   if (response.state === 'not_available' || !response.incident) { setOutcome({ kind: 'not_available', reason: response.reason ?? 'not_available' }); return; }
   setOutcome({ kind: 'committed', revision: response.incident.version, action: request.kind as IncidentActionKind });
   setDraft(emptyDraft(availableActions(response.incident)[0] ?? 'ack'));
   props.onCommitted(response.incident);
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   if (error instanceof VersionConflict) setOutcome({ kind: 'conflict', expected: request.expected_version, current: error.currentVersion, requestId: error.requestId });
   else if (error instanceof OutcomeUnknown) setOutcome({ kind: 'unknown', request });
   else if (error instanceof ApiFault) setOutcome({ kind: 'refused', status: error.status, detail: error.detail, code: error.code, requestId: error.requestId });
   else setOutcome({ kind: 'refused', status: 0, detail: '', code: 'unavailable', requestId: '' });
  }
 };

 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (outcome.kind === 'pending') return;
  // Every new submission is a new command; only the explicit resend below reuses one.
  const built = buildRequest(view, effective, newCommandId(), Date.now());
  if (!built.ok) { setOutcome({ kind: 'invalid', text: built.error }); return; }
  void send(built.request);
 };

 const pending = outcome.kind === 'pending';
 const status = (
  <div ref={note} tabIndex={-1} data-outcome={outcome.kind}>
   {outcome.kind === 'pending' && <p role="status"><strong>Pending.</strong> Waiting for the server to acknowledge. Nothing is committed yet and the incident above has not changed.</p>}
   {outcome.kind === 'invalid' && <p role="alert" className="error"><strong>Not sent.</strong> {outcome.text}</p>}
   {outcome.kind === 'committed' && <p role="status"><strong>Committed.</strong> The server acknowledged revision {outcome.revision} ({ACTION_LABEL[outcome.action]}).</p>}
   {outcome.kind === 'not_available' && <p role="status"><strong>Not available.</strong> {describeReason(outcome.reason)}</p>}
   {outcome.kind === 'refused' && <p role="alert" className="error"><strong>Not applied.</strong> {faultText(outcome.detail, outcome.status)}{outcome.code && <> Code <code>{outcome.code}</code>.</>}{outcome.requestId && <> Request <code>{outcome.requestId}</code>.</>} Your draft is kept.</p>}
   {outcome.kind === 'unknown' && (
    <div role="alert" className="error">
     <p><strong>Outcome unknown.</strong> The connection failed after the request was sent, so it may or may not have been applied. Do not assume it failed. Resending the same request is safe: the server returns the original result instead of applying it twice.</p>
     <button type="button" onClick={() => { void send(outcome.request); }}>Resend the same request</button>
    </div>
   )}
   {outcome.kind === 'conflict' && (outcome.expected !== view.version
    ? <p role="alert" className="error" data-conflict="reloaded"><strong>Reloaded.</strong> The incident is now at revision {view.version}; your action expected revision {outcome.expected} and was not applied. Review what changed above, then submit again. Your draft is kept.</p>
    : (
     <div role="alert" className="error" data-conflict="current">
      <p><strong>Conflict: not applied.</strong> Another action committed first. The incident is now at revision <strong data-testid="current-version">{outcome.current}</strong>; you were acting on revision {outcome.expected}. Nothing of yours was applied and nothing was retried. Your draft is kept.</p>
      <button type="button" onClick={props.onReload} disabled={props.reloading}>Reload the current incident</button>
     </div>
    ))}
  </div>
 );
 if (kinds.length === 0) {
  return (
   <section className="panel" aria-labelledby="action-heading">
    <h3 id="action-heading">Respond</h3>
    <p>This incident is resolved. A resolved incident accepts no further human actions. The source is reported separately above, and a worse impact or a new episode proposes a new linked incident.</p>
    {status}
   </section>
  );
 }
 return (
  <section className="panel" aria-labelledby="action-heading">
   <h3 id="action-heading">Respond</h3>
   <p>You are acting on revision <strong data-testid="expected-version">{view.version}</strong>. If someone else commits first, nothing of yours is applied and you are told the current revision.</p>
   <form onSubmit={submit} aria-label="Incident action" aria-busy={pending}>
    <fieldset disabled={pending}>
     <legend>Action</legend>
     {kinds.map((k) => (
      <label key={k} className="check"><input type="radio" name="action-kind" value={k} checked={k === kind} onChange={() => set({ kind: k })} /> {ACTION_LABEL[k]}</label>
     ))}
    </fieldset>
    {kind === 'resolve' && view.source_firing && (
     <p role="note" className="banner banner-warning"><strong>The alert source is still firing.</strong> Resolving is a human decision about this incident; it does not recover the source, which stays firing. A reason is required.</p>
    )}
    {kind === 'assign' && (
     <div className="field-row">
      <label>Owner user ID (empty removes the owner) <input name="owner" value={draft.owner} onChange={(e) => set({ owner: e.target.value })} autoComplete="off" spellCheck={false} disabled={pending} /></label>
      {session && <button type="button" disabled={pending} onClick={() => set({ owner: session.session.user })}>Use my user ID</button>}
     </div>
    )}
    {kind === 'link' && (
     <div className="field-row">
      <label>Evidence kind <select name="link-kind" value={draft.linkKind} onChange={(e) => set({ linkKind: LINK_KINDS.find((l) => l === e.target.value) ?? 'issue' })} disabled={pending}>{LINK_KINDS.map((l) => <option key={l} value={l}>{l}</option>)}</select></label>
      <label>Evidence ID <input name="link-id" value={draft.linkId} onChange={(e) => set({ linkId: e.target.value })} autoComplete="off" spellCheck={false} disabled={pending} /></label>
     </div>
    )}
    {kind === 'impact' && (
     <div className="field-row">
      <label>Severity <select name="severity" value={draft.severity} onChange={(e) => set({ severity: SEVERITIES.find((s) => s === e.target.value) ?? 'major' })} disabled={pending}>{SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
      <label>Source state <select name="state" value={draft.state} onChange={(e) => set({ state: CONDITION_STATES.find((s) => s === e.target.value) ?? 'firing' })} disabled={pending}>{CONDITION_STATES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
      <label>Data freshness <select name="freshness" value={draft.freshness} onChange={(e) => set({ freshness: FRESHNESS.find((s) => s === e.target.value) ?? 'fresh' })} disabled={pending}>{FRESHNESS.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
     </div>
    )}
    {(kind === 'snooze' || kind === 'maintenance') && (
     <label>Duration <select name="duration" value={draft.minutes} onChange={(e) => set({ minutes: Number(e.target.value) })} disabled={pending}>{DURATIONS.map((d) => <option key={d.minutes} value={d.minutes}>{d.label}</option>)}</select></label>
    )}
    <label>Reason{reasonRequired(kind) ? ' (required)' : ' (optional)'} <textarea name="reason" rows={3} maxLength={512} value={draft.reason} onChange={(e) => set({ reason: e.target.value })} disabled={pending} /></label>
    <button type="submit" className="primary" disabled={pending}>{pending ? 'Waiting for the server…' : `Submit: ${ACTION_LABEL[kind]}`}</button>
   </form>
   {status}
  </section>
 );
}
