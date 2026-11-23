// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getPolicies, isAbort, stateOfFault, writePolicy } from '../api/client';
import type { Id, LoadState, PolicyChange, PolicyView, PolicyWriteAnswer } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { Icon, type IconName } from '../ui/Icon';
import { Pill } from '../ui/primitives';
import { AuditedForm } from './AuditedForm';
import { PlainTable, Panel } from './SettingsUi';
import { RETENTION_SIGNALS, buildNotification, buildRetention, describeWriteFailure, durationWords, notificationChanged, notificationDraft, secondsToNs, urgencySteps, type Built, type NotificationDraft, type UrgencyStep } from './policy';

/** One project's policies (C11 /api/v1/policies), keyed to the scope they were asked for. A save answers the committed view, which replaces the held one; a stale page reloads. */
export function usePolicy(context: ViewContext, project: Id): { load: LoadState<PolicyView>; policy: PolicyView | undefined; commit: (view: PolicyView) => void; reload: () => void } {
 const key = `${scopeKey(context)}|${project}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<PolicyView> }>({ key: '', load: { kind: 'loading' } });
 const [tick, setTick] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  getPolicies(context.org, project, ctl.signal).then(
   (view) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: view } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, tick]);
 const load: LoadState<PolicyView> = held.key === key ? held.load : { kind: 'loading' };
 return { load, policy: load.kind === 'ready' ? load.data : undefined, commit: (view) => setHeld({ key, load: { kind: 'ready', data: view } }), reload: () => setTick((n) => n + 1) };
}

interface FormProps { context: ViewContext; project: Id; policy: PolicyView; onCommitted: (view: PolicyView) => void; onStale: () => void }

/** One audited policy change over POST /api/v1/policies, based on the organization revision the page read. */
function PolicyForm(props: FormProps & { name: string; label: string; submitLabel: string; build: () => Built<PolicyChange>; children: React.ReactNode }): React.JSX.Element {
 return (
  <AuditedForm<PolicyWriteAnswer>
   name={props.name} label={props.label} submitLabel={props.submitLabel} describe={describeWriteFailure} onStale={props.onStale} onCommitted={(answer) => props.onCommitted(answer.policy)}
   check={() => { const built = props.build(); return built.ok ? null : built.error; }}
   fingerprint={() => { const built = props.build(); return JSON.stringify([built.ok ? built.value : built.error, props.policy.revision]); }}
   run={async (command, reason, signal) => {
    const built = props.build();
    if (!built.ok) throw new Error(built.error);
    return writePolicy({ org: props.context.org, project_id: props.project, command_id: command, expected_revision: props.policy.revision, reason, change: built.value }, signal);
   }}
   saved={(answer) => `Saved. The server committed this change at control revision ${answer.revision}; the settings above are the committed ones.`}>
   {props.children}
  </AuditedForm>
 );
}

const STEP_ICON: Record<UrgencyStep['id'], IconName> = { urgent: 'bell', reminders: 'clock', suppression: 'snooze', digest: 'calendar' };

function NotificationForm(props: FormProps): React.JSX.Element {
 const p = props.policy.notification;
 const [draft, setDraft] = React.useState<NotificationDraft>(() => notificationDraft(p));
 const set = (key: keyof NotificationDraft) => (e: React.ChangeEvent<HTMLInputElement>): void => setDraft((d) => ({ ...d, [key]: e.target.value }));
 const words = (text: string): string => { const ns = secondsToNs(text); return ns === null ? '' : ` = ${durationWords(ns)}`; };
 return (
  <PolicyForm {...props} name="notification_policy" label="Change the notification policy" submitLabel="Save notification policy"
   build={() => { const built = buildNotification(draft); if (built.ok && !notificationChanged(draft, p)) return { ok: false, error: 'Nothing to save: the policy shown is already the committed one.' }; return built.ok ? { ok: true, value: { kind: 'notification_policy', notification: built.value } } : built; }}>
   <div className="set-grid">
    <label>Minimum operations <input inputMode="numeric" value={draft.minOperations} onChange={set('minOperations')} /></label>
    <label>Minimum failures <input inputMode="numeric" value={draft.minFailures} onChange={set('minFailures')} /></label>
    <label>Failure rate (%) <input inputMode="decimal" value={draft.ratePercent} onChange={set('ratePercent')} /></label>
    <label>Regression minimum occurrences <input inputMode="numeric" value={draft.regressionMin} onChange={set('regressionMin')} /></label>
    <label>First reminder (seconds){words(draft.firstReminderSeconds)} <input inputMode="decimal" value={draft.firstReminderSeconds} onChange={set('firstReminderSeconds')} /></label>
    <label>Reminder interval (seconds){words(draft.reminderEverySeconds)} <input inputMode="decimal" value={draft.reminderEverySeconds} onChange={set('reminderEverySeconds')} /></label>
    <label>Longest snooze or maintenance window (seconds){words(draft.maxSuppressionSeconds)} <input inputMode="decimal" value={draft.maxSuppressionSeconds} onChange={set('maxSuppressionSeconds')} /></label>
    <label>Digest time zone (empty is UTC) <input value={draft.defaultZone} onChange={set('defaultZone')} autoComplete="off" spellCheck={false} /></label>
   </div>
   <label>Critical operation codes (comma separated) <input value={draft.criticalCodes} onChange={set('criticalCodes')} autoComplete="off" spellCheck={false} /></label>
  </PolicyForm>
 );
}

/** The urgency policy of one project, told as steps and changed as a whole (the server holds one notification policy per project). A policy is adopted by the notification worker at its
 * next pass. Routes by rule or severity, maintenance window lists and escalation are not part of the policy contract and are not drawn. */
export function NotificationPolicyPanel(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const { load, policy, commit, reload } = usePolicy(props.context, props.project);
 const p = policy?.notification;
 return (
  <div data-section="policy-notification" data-project-policies={props.project}>
   <Panel title="Urgency policy" actions={p ? <Pill tone={p.source === 'default' ? 'line' : 'acc'}>{p.source === 'default' ? 'Default policy' : 'Own policy'}</Pill> : undefined}>
    <div className="col g12">
     {load.kind !== 'ready' && <StatusPanel state={load} />}
     {policy && p && (
      <>
       <p className="small t2" data-testid="policy-revision" data-revision={policy.revision}>Settings read at organization revision {policy.revision}. {policy.manage_destinations ? 'You administer this organization.' : 'You hold policy.write on this project: you change its retention and notification policy; destinations are changed by organization administrators.'}</p>
       <p data-policy-source={p.source} className="small t2">{p.source === 'default' ? 'This project runs on the approved default policy (revision 1). Saving a change creates a project policy.' : `This project has its own policy, revision ${p.revision}.`} A policy is adopted by the notification worker at its next pass.</p>
       <ol className="steps set-steps" aria-label="Urgency policy steps">
        {urgencySteps(p).map((s) => (
         <li key={s.id} data-urgency-step={s.id}>
          <span className="no"><Icon name={STEP_ICON[s.id]} size="xs" /></span>
          <div className="col g4"><b>{s.title}</b><span className="small t2">{s.text}</span></div>
          <span className="small t3">{s.badge}</span>
         </li>
        ))}
       </ol>
       <NotificationForm context={props.context} project={props.project} policy={policy} onCommitted={commit} onStale={reload} />
      </>
     )}
    </div>
   </Panel>
  </div>
 );
}

function RetentionForm(props: FormProps): React.JSX.Element {
 const [signal, setSignal] = React.useState('metrics');
 const [days, setDays] = React.useState('');
 return (
  <PolicyForm {...props} name="retention" label="Change retention" submitLabel="Save retention" onCommitted={(v) => { setDays(''); props.onCommitted(v); }}
   build={() => { const built = buildRetention(signal, days); return built.ok ? { ok: true, value: { kind: 'retention', retention: built.value } } : built; }}>
   <div className="set-grid">
    <label>Signal <select value={signal} onChange={(e) => setSignal(e.target.value)}>{RETENTION_SIGNALS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}</select></label>
    <label>Days (1 to 3650) <input inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} /></label>
   </div>
  </PolicyForm>
 );
}

/** Days of data kept for new telemetry, by signal, for one project. A change applies to what is admitted from then on: existing receipts keep their deadlines. */
export function RetentionPanel(props: { context: ViewContext; project: Id; name: string }): React.JSX.Element {
 const { load, policy, commit, reload } = usePolicy(props.context, props.project);
 return (
  <div data-section="policy-retention" data-project-policies={props.project}>
   <Panel title={`Retention of ${props.name}`}>
    <div className="col g12">
     {load.kind !== 'ready' && <StatusPanel state={load} />}
     {policy && (
      <>
       <p className="small t2" data-testid="policy-revision" data-revision={policy.revision}>Settings read at organization revision {policy.revision}. Days of data kept for new telemetry, by signal. A change applies to what is admitted from then on: existing receipts keep their deadlines. A signal with no setting here keeps the source policy&apos;s retention.</p>
       <PlainTable label={`Retention settings of ${props.name}`} columns={['Signal', 'Days']}
        rows={RETENTION_SIGNALS.map((s) => { const row = policy.retention.find((r) => r.signal === s.id); return [s.label, row ? String(row.days) : 'Not set']; })} empty="No signal."
        tableAttrs={{ 'data-retention-table': props.project }} rowAttrs={(i) => ({ 'data-retention': RETENTION_SIGNALS[i]?.id ?? '' })} />
       <RetentionForm context={props.context} project={props.project} policy={policy} onCommitted={commit} onStale={reload} />
      </>
     )}
    </div>
   </Panel>
  </div>
 );
}
