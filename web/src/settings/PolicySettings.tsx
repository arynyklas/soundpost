// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getPolicies, isAbort, stateOfFault, writePolicy } from '../api/client';
import type { DestinationView, Id, LoadState, PolicyChange, PolicyView } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { DESTINATION_TYPES, RETENTION_SIGNALS, buildDestination, buildNotification, buildRetention, describeWriteFailure, durationWords, notificationChanged, notificationDraft, secondsToNs, validReason, type Built, type DestinationDraft, type NotificationDraft } from './policy';

type Phase = { kind: 'idle' } | { kind: 'pending' } | { kind: 'saved'; revision: string } | { kind: 'failed'; text: string; failure: string };

/** One audited settings change: fields, a reason, and a save that shows nothing as saved until the server's answer says committed.
 * A failed or refused save says nothing was changed. A save whose outcome is unknown keeps its command ID, so saving again sends the
 * same command and the server applies it once. */
function WriteForm(props: { name: string; label: string; context: ViewContext; project: Id; policy: PolicyView; build: () => Built<PolicyChange>; onCommitted: (view: PolicyView) => void; onStale: () => void; submitLabel: string; children: React.ReactNode }): React.JSX.Element {
 const [reason, setReason] = React.useState('');
 const [phase, setPhase] = React.useState<Phase>({ kind: 'idle' });
 const command = React.useRef<{ fingerprint: string; id: Id } | null>(null);
 const live = React.useRef(true);
 React.useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (phase.kind === 'pending') return;
  const built = props.build();
  if (!built.ok) { setPhase({ kind: 'failed', text: built.error, failure: 'local' }); return; }
  if (!validReason(reason)) { setPhase({ kind: 'failed', text: 'A reason of 1 to 512 bytes, without control characters, is required: it is kept in the audit record.', failure: 'local' }); return; }
  const fingerprint = JSON.stringify([built.value, reason, props.policy.revision]);
  if (command.current === null || command.current.fingerprint !== fingerprint) command.current = { fingerprint, id: newCommandId() };
  const sent = command.current;
  setPhase({ kind: 'pending' });
  writePolicy({ org: props.context.org, project_id: props.project, command_id: sent.id, expected_revision: props.policy.revision, reason, change: built.value }, new AbortController().signal).then(
   (answer) => {
    command.current = null;
    if (!live.current) return;
    setPhase({ kind: 'saved', revision: answer.revision });
    setReason('');
    props.onCommitted(answer.policy);
   },
   (error: unknown) => {
    const failure = describeWriteFailure(error);
    if (failure.kind !== 'unknown_outcome') command.current = null;
    if (!live.current) return;
    setPhase({ kind: 'failed', text: failure.text, failure: failure.kind });
    if (failure.kind === 'conflict') props.onStale();
   },
  );
 };
 const pending = phase.kind === 'pending';
 return (
  <form aria-label={props.label} data-write={props.name} data-write-phase={phase.kind} aria-busy={pending} onSubmit={submit} className="panel">
   {props.children}
   <label>Reason (kept in the audit record) <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={512} autoComplete="off" /></label>
   <button type="submit" className="primary" disabled={pending}>{pending ? 'Saving…' : props.submitLabel}</button>
   {pending && <p role="status">Waiting for the server. Nothing is saved until it confirms.</p>}
   {phase.kind === 'saved' && <p role="status" data-write-result="committed">Saved. The server committed this change at control revision {phase.revision}; the settings above are the committed ones.</p>}
   {phase.kind === 'failed' && <p role="alert" className="error" data-write-result={phase.failure}>{phase.text}</p>}
  </form>
 );
}

interface SectionProps { context: ViewContext; project: Id; policy: PolicyView; onCommitted: (view: PolicyView) => void; onStale: () => void }

function NotificationSection(props: SectionProps): React.JSX.Element {
 const p = props.policy.notification;
 const [draft, setDraft] = React.useState<NotificationDraft>(() => notificationDraft(p));
 const set = (key: keyof NotificationDraft) => (e: React.ChangeEvent<HTMLInputElement>): void => setDraft((d) => ({ ...d, [key]: e.target.value }));
 const words = (text: string): string => { const ns = secondsToNs(text); return ns === null ? '' : ` = ${durationWords(ns)}`; };
 return (
  <section aria-labelledby={`notification-${props.project}`} data-section="policy-notification">
   <h4 id={`notification-${props.project}`}>Notification policy</h4>
   <p data-policy-source={p.source}>{p.source === 'default' ? 'This project runs on the approved default policy (revision 1). Saving a change creates a project policy.' : `This project has its own policy, revision ${p.revision}.`} A change is urgent when a critical code occurs, a regression reaches the regression minimum, or the window has at least {p.min_operations} operations and {p.min_failures} failures at a rate of at least {(p.rate_basis_points / 100).toString()}%. A policy is adopted by the notification worker at its next pass; changes to a destination apply to every project of the organization.</p>
   <WriteForm name="notification_policy" label="Change the notification policy" context={props.context} project={props.project} policy={props.policy} submitLabel="Save notification policy" onCommitted={props.onCommitted} onStale={props.onStale}
    build={() => { const built = buildNotification(draft); if (built.ok && !notificationChanged(draft, p)) return { ok: false, error: 'Nothing to save: the policy shown is already the committed one.' }; return built.ok ? { ok: true, value: { kind: 'notification_policy', notification: built.value } } : built; }}>
    <label>Minimum operations <input inputMode="numeric" value={draft.minOperations} onChange={set('minOperations')} /></label>
    <label>Minimum failures <input inputMode="numeric" value={draft.minFailures} onChange={set('minFailures')} /></label>
    <label>Failure rate (%) <input inputMode="decimal" value={draft.ratePercent} onChange={set('ratePercent')} /></label>
    <label>Regression minimum occurrences <input inputMode="numeric" value={draft.regressionMin} onChange={set('regressionMin')} /></label>
    <label>Critical operation codes (comma separated) <input value={draft.criticalCodes} onChange={set('criticalCodes')} autoComplete="off" spellCheck={false} /></label>
    <label>First reminder (seconds){words(draft.firstReminderSeconds)} <input inputMode="decimal" value={draft.firstReminderSeconds} onChange={set('firstReminderSeconds')} /></label>
    <label>Reminder interval (seconds){words(draft.reminderEverySeconds)} <input inputMode="decimal" value={draft.reminderEverySeconds} onChange={set('reminderEverySeconds')} /></label>
    <label>Longest snooze or maintenance window (seconds){words(draft.maxSuppressionSeconds)} <input inputMode="decimal" value={draft.maxSuppressionSeconds} onChange={set('maxSuppressionSeconds')} /></label>
    <label>Digest time zone (empty is UTC) <input value={draft.defaultZone} onChange={set('defaultZone')} autoComplete="off" spellCheck={false} /></label>
   </WriteForm>
  </section>
 );
}

const TYPE_WORDS: Record<string, string> = { webhook: 'Webhook', smtp: 'Email', telegram: 'Telegram' };

function DestinationRow(props: SectionProps & { destination: DestinationView }): React.JSX.Element {
 const d = props.destination;
 const [enabled, setEnabled] = React.useState(d.enabled);
 const [secret, setSecret] = React.useState('');
 return (
  <li data-destination={d.id} data-destination-enabled={String(d.enabled)} data-destination-secret={d.has_secret ? 'set' : 'unset'}>
   <strong>{TYPE_WORDS[d.type] ?? d.type}</strong> <code>{d.id}</code> — {d.endpoint_host ? `endpoint host ${d.endpoint_host}` : d.address ? `recipient ${d.address}` : 'no address'}; {d.enabled ? 'enabled' : 'disabled'}; secret {d.has_secret ? 'set (write-only, never shown)' : 'not set'}.
   {props.policy.manage_destinations && (
    <WriteForm name={`destination-${d.id}`} label={`Change destination ${d.id}`} context={props.context} project={props.project} policy={props.policy} submitLabel="Save destination" onCommitted={(v) => { setSecret(''); props.onCommitted(v); }} onStale={props.onStale}
     build={() => {
      if (enabled === d.enabled && secret === '') return { ok: false, error: 'Nothing to save: change the enabled state or enter a new secret.' };
      if (secret.length > 4096) return { ok: false, error: 'The secret is too long.' };
      return { ok: true, value: { kind: 'destination', destination: { id: d.id, type: d.type, enabled, ...(secret !== '' ? { secret } : {}) } } };
     }}>
     <label><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
     <label>New secret (write-only; leave empty to keep the sealed one) <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" spellCheck={false} /></label>
    </WriteForm>
   )}
  </li>
 );
}

function NewDestination(props: SectionProps): React.JSX.Element {
 const [draft, setDraft] = React.useState<DestinationDraft>(() => ({ id: newCommandId(), type: 'webhook', endpoint: '', address: '', enabled: true, secret: '' }));
 const set = (key: 'endpoint' | 'address' | 'secret') => (e: React.ChangeEvent<HTMLInputElement>): void => setDraft((d) => ({ ...d, [key]: e.target.value }));
 return (
  <WriteForm name="destination-new" label="Add a notification destination" context={props.context} project={props.project} policy={props.policy} submitLabel="Add destination" onStale={props.onStale}
   onCommitted={(v) => { setDraft({ id: newCommandId(), type: 'webhook', endpoint: '', address: '', enabled: true, secret: '' }); props.onCommitted(v); }}
   build={() => { const built = buildDestination(draft); return built.ok ? { ok: true, value: { kind: 'destination', destination: built.value } } : built; }}>
   <label>Type <select value={draft.type} onChange={(e) => setDraft((d) => ({ ...d, type: e.target.value }))}>{DESTINATION_TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}</select></label>
   {draft.type !== 'smtp' && <label>Endpoint (https, no credentials, query or fragment) <input value={draft.endpoint} onChange={set('endpoint')} autoComplete="off" spellCheck={false} /></label>}
   {draft.type === 'smtp' && <label>Recipient address <input value={draft.address} onChange={set('address')} autoComplete="off" spellCheck={false} /></label>}
   <label>Secret (write-only; sealed on save and never shown again) <input type="password" value={draft.secret} onChange={set('secret')} autoComplete="new-password" spellCheck={false} /></label>
   <label><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))} /> Enabled</label>
  </WriteForm>
 );
}

function DestinationsSection(props: SectionProps): React.JSX.Element {
 const ds = props.policy.destinations;
 return (
  <section aria-labelledby={`destinations-${props.project}`} data-section="policy-destinations">
   <h4 id={`destinations-${props.project}`}>Notification destinations</h4>
   <p>Destinations belong to the organization: every enabled destination receives the notifications of every project of it. A secret is sealed when saved and is never shown.{props.policy.manage_destinations ? '' : ' Only organization administrators change destinations.'}</p>
   {ds.length === 0 ? <p role="status" data-state="empty">No destination is configured: notifications stay in the product queue and are never sent.</p> : <ul>{ds.map((d) => <DestinationRow key={d.id} {...props} destination={d} />)}</ul>}
   {props.policy.manage_destinations && <NewDestination {...props} />}
  </section>
 );
}

function RetentionSection(props: SectionProps): React.JSX.Element {
 const [signal, setSignal] = React.useState('metrics');
 const [days, setDays] = React.useState('');
 const current = props.policy.retention;
 return (
  <section aria-labelledby={`retention-${props.project}`} data-section="policy-retention">
   <h4 id={`retention-${props.project}`}>Retention</h4>
   <p>Days of data kept for new telemetry, by signal. A change applies to what is admitted from then on: existing receipts keep their deadlines. A signal with no setting here keeps the source policy's retention.</p>
   <table aria-label="Retention settings">
    <thead><tr><th scope="col">Signal</th><th scope="col">Days</th></tr></thead>
    <tbody>{RETENTION_SIGNALS.map((s) => { const row = current.find((r) => r.signal === s.id); return <tr key={s.id} data-retention={s.id}><th scope="row">{s.label}</th><td>{row ? row.days : 'Not set'}</td></tr>; })}</tbody>
   </table>
   <WriteForm name="retention" label="Change retention" context={props.context} project={props.project} policy={props.policy} submitLabel="Save retention" onCommitted={(v) => { setDays(''); props.onCommitted(v); }} onStale={props.onStale}
    build={() => { const built = buildRetention(signal, days); return built.ok ? { ok: true, value: { kind: 'retention', retention: built.value } } : built; }}>
    <label>Signal <select value={signal} onChange={(e) => setSignal(e.target.value)}>{RETENTION_SIGNALS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}</select></label>
    <label>Days (1 to 3650) <input inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} /></label>
   </WriteForm>
  </section>
 );
}

/** One project's notification policy, destinations and retention, read and changed through C11 /api/v1/policies under the caller's own
 * policy.write grant or organization administration. Every change is an audited command; a stale page is told so and reloaded. */
export function PolicySettings(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const c = props.context;
 const key = `${scopeKey(c)}|${props.project}|${c.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<PolicyView> }>({ key: '', load: { kind: 'loading' } });
 const [reload, setReload] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  getPolicies(c.org, props.project, ctl.signal).then(
   (view) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: view } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, reload]);
 const load: LoadState<PolicyView> = held.key === key ? held.load : { kind: 'loading' };
 const policy = load.kind === 'ready' ? load.data : undefined;
 const section: SectionProps | undefined = policy ? { context: c, project: props.project, policy, onCommitted: (view) => setHeld({ key, load: { kind: 'ready', data: view } }), onStale: () => setReload((n) => n + 1) } : undefined;
 return (
  <div data-section="policies" data-project-policies={props.project}>
   <h4>Policies for this project</h4>
   {load.kind !== 'ready' && <StatusPanel state={load} />}
   {section && policy && (
    <>
     <p data-testid="policy-revision" data-revision={policy.revision}>Settings read at organization revision {policy.revision}. {policy.manage_destinations ? 'You administer this organization.' : 'You hold policy.write on this project: you change its retention and notification policy; destinations are changed by organization administrators.'}</p>
     <NotificationSection {...section} />
     <DestinationsSection {...section} />
     <RetentionSection {...section} />
    </>
   )}
  </div>
 );
}
