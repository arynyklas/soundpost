// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { describeWriteFailure } from './policy';
import { MISSING_DATA, RULE_KINDS, RULE_SEVERITIES, buildRuleSpec, declareReplay, emptyRuleDraft, listRules, retireRule, ruleDraftOf, saveRule, utcToNs, validRuleReason, type RuleDraft, type RuleList, type RuleView } from './rules';

type Phase = { kind: 'idle' } | { kind: 'pending' } | { kind: 'saved' } | { kind: 'failed'; text: string; failure: string };

/** One audited rule command: a reason, and a result that shows nothing as done until the server says committed. A failed or refused command
 * says nothing was changed. A command whose outcome is unknown keeps its command ID, so sending again applies it once. */
function AuditedForm(props: { name: string; label: string; submitLabel: string; check: () => string | null; fingerprint: () => string; run: (command: Id, reason: string) => Promise<void>; onStale: () => void; children: React.ReactNode }): React.JSX.Element {
 const [reason, setReason] = React.useState('');
 const [phase, setPhase] = React.useState<Phase>({ kind: 'idle' });
 const command = React.useRef<{ fingerprint: string; id: Id } | null>(null);
 const live = React.useRef(true);
 React.useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (phase.kind === 'pending') return;
  const problem = props.check();
  if (problem !== null) { setPhase({ kind: 'failed', text: problem, failure: 'local' }); return; }
  if (!validRuleReason(reason)) { setPhase({ kind: 'failed', text: 'A reason of 1 to 512 bytes, without control characters, is required: it is kept in the audit record.', failure: 'local' }); return; }
  const fingerprint = JSON.stringify([props.fingerprint(), reason]);
  if (command.current === null || command.current.fingerprint !== fingerprint) command.current = { fingerprint, id: newCommandId() };
  const sent = command.current;
  setPhase({ kind: 'pending' });
  props.run(sent.id, reason).then(
   () => { command.current = null; if (!live.current) return; setPhase({ kind: 'saved' }); setReason(''); },
   (error: unknown) => {
    if (isAbort(error)) return;
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
   {phase.kind === 'saved' && <p role="status" data-write-result="committed">Done. The server committed this change; the rules above are the committed ones.</p>}
   {phase.kind === 'failed' && <p role="alert" className="error" data-write-result={phase.failure}>{phase.text}</p>}
  </form>
 );
}

interface FormProps { context: ViewContext; project: Id; list: RuleList; onChanged: (view: RuleView) => void; onStale: () => void }

/** Create a rule (no `existing`) or save the next version of one. */
function RuleForm(props: FormProps & { existing?: RuleView }): React.JSX.Element {
 const existing = props.existing;
 const [draft, setDraft] = React.useState<RuleDraft>(() => existing ? ruleDraftOf(existing) : emptyRuleDraft(props.list.profiles));
 const ruleId = React.useRef<Id>(existing?.rule_id ?? newCommandId());
 const set = (key: keyof RuleDraft) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>): void => setDraft((d) => ({ ...d, [key]: e.target.value }));
 const profile = props.list.profiles.find((p) => p.id === draft.profile);
 const alert = draft.kind === 'alert';
 const heading = existing ? `New version of rule ${existing.rule_id}` : 'New rule';
 return (
  <section aria-label={heading} data-section={existing ? 'rule-edit' : 'rule-new'}>
   <h5>{heading}</h5>
   <AuditedForm name={existing ? `rule-${existing.rule_id}` : 'rule-new'} label={existing ? `Save the next version of rule ${existing.rule_id}` : 'Save a new rule'} submitLabel="Save rule" onStale={props.onStale}
    check={() => { const built = buildRuleSpec(draft, props.list.profiles); return built.ok ? (draft.kind === 'recording' && !props.list.recording_available ? 'This node has no recording source for this project: a recording rule cannot be saved.' : null) : built.error; }}
    fingerprint={() => JSON.stringify([draft, ruleId.current, existing?.revision ?? '0'])}
    run={async (command, reason) => {
     const built = buildRuleSpec(draft, props.list.profiles);
     if (!built.ok) return;
     props.onChanged(await saveRule({ org: props.context.org, project: props.project, command, rule: ruleId.current, expected_revision: existing?.revision ?? '0', reason, spec: built.value }, new AbortController().signal));
    }}>
    <label>Kind <select value={draft.kind} onChange={set('kind')}>{RULE_KINDS.map((k) => <option key={k} value={k}>{k === 'alert' ? 'Alert' : 'Recording'}</option>)}</select></label>
    <label>Profile <select value={draft.profile} onChange={(e) => { const next = props.list.profiles.find((p) => p.id === e.target.value); setDraft((d) => ({ ...d, profile: e.target.value, featureSet: next?.feature_sets[0] ?? '' })); }}>{props.list.profiles.map((p) => <option key={p.id} value={p.id}>{p.id}</option>)}</select></label>
    <label>Feature set <select value={draft.featureSet} onChange={set('featureSet')}>{(profile?.feature_sets ?? []).map((f) => <option key={f} value={f}>{f}</option>)}</select></label>
    <label>Expression (must evaluate to an instant vector) <textarea value={draft.expression} onChange={set('expression')} rows={3} spellCheck={false} autoComplete="off" /></label>
    <label>Evaluate every (seconds) <input inputMode="numeric" value={draft.intervalSeconds} onChange={set('intervalSeconds')} /></label>
    {alert && (
     <>
      <label>Fire after a series is present for (seconds) <input inputMode="numeric" value={draft.forSeconds} onChange={set('forSeconds')} /></label>
      <label>Recover after it is absent for (seconds) <input inputMode="numeric" value={draft.holdSeconds} onChange={set('holdSeconds')} /></label>
      <label>Severity <select value={draft.severity} onChange={set('severity')}>{RULE_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
      <label>Incomplete input is reported as <select value={draft.missingData} onChange={set('missingData')}>{MISSING_DATA.map((m) => <option key={m} value={m}>{m}</option>)}</select></label>
     </>
    )}
    {!alert && (
     <>
      <label>Metric name written <input value={draft.recordName} onChange={set('recordName')} autoComplete="off" spellCheck={false} /></label>
      <label>Labels set on every series (one name=value per line; the source policy must list each value) <textarea value={draft.labels} onChange={set('labels')} rows={3} spellCheck={false} autoComplete="off" /></label>
      {!props.list.recording_available && <p role="status" data-state="empty">This node has no recording source for this project, so a recording rule cannot be saved.</p>}
     </>
    )}
   </AuditedForm>
  </section>
 );
}

function RetireForm(props: FormProps & { rule: RuleView }): React.JSX.Element {
 const r = props.rule;
 return (
  <AuditedForm name={`retire-${r.rule_id}`} label={`Retire rule ${r.rule_id}`} submitLabel="Retire rule" onStale={props.onStale} check={() => null} fingerprint={() => JSON.stringify([r.rule_id, r.revision])}
   run={async (command, reason) => { props.onChanged(await retireRule({ org: props.context.org, project: props.project, command, rule: r.rule_id, expected_revision: r.revision, reason }, new AbortController().signal)); }}>
   <p>A retired rule is no longer evaluated; its history stays and saving a new version brings it back.</p>
  </AuditedForm>
 );
}

/** The operator's replay declaration: late evaluations of the rule's grid points inside the window may notify. */
function ReplayForm(props: FormProps & { rule: RuleView }): React.JSX.Element {
 const r = props.rule;
 const [from, setFrom] = React.useState('');
 const [to, setTo] = React.useState('');
 return (
  <AuditedForm name={`replay-${r.rule_id}`} label={`Declare an operator replay of rule ${r.rule_id}`} submitLabel="Declare replay" onStale={props.onStale}
   check={() => { const a = utcToNs(from), b = utcToNs(to); return a === null || b === null || BigInt(b) < BigInt(a) ? 'Give the window as UTC times such as 2026-11-15T10:00Z, the end not before the start.' : null; }}
   fingerprint={() => JSON.stringify([r.rule_id, from, to])}
   run={async (_command, reason) => {
    const a = utcToNs(from), b = utcToNs(to);
    if (a === null || b === null) return;
    await declareReplay({ org: props.context.org, project: props.project, rule: r.rule_id, reason, from_ns: a, to_ns: b }, new AbortController().signal);
   }}>
   <p>Evaluations that ran late (after an outage) never notify. Declaring a window here lets the late evaluations inside it notify; the declaration is audited.</p>
   <label>From (UTC) <input value={from} onChange={(e) => setFrom(e.target.value)} placeholder="2026-11-15T10:00Z" autoComplete="off" /></label>
   <label>To (UTC) <input value={to} onChange={(e) => setTo(e.target.value)} placeholder="2026-11-15T11:00Z" autoComplete="off" /></label>
  </AuditedForm>
 );
}

function RuleRow(props: FormProps & { rule: RuleView }): React.JSX.Element {
 const r = props.rule;
 const [open, setOpen] = React.useState(false);
 return (
  <li data-rule={r.rule_id} data-rule-state={r.retired ? 'retired' : 'active'} data-rule-version={r.version} data-rule-revision={r.revision}>
   <strong>{r.rule.kind === 'alert' ? 'Alert' : 'Recording'}</strong> <code>{r.rule_id}</code> — <code>{r.rule.expression}</code>, every {r.rule.interval_seconds} s{r.rule.kind === 'alert' ? `, severity ${r.rule.severity ?? ''}` : `, writes ${r.rule.record_name ?? ''}`}; version {r.version}, {r.retired ? 'retired' : 'active'}.
   {props.list.can_author && <button type="button" aria-expanded={open} onClick={() => setOpen((o) => !o)}>{open ? 'Close' : 'Change'}</button>}
   {open && props.list.can_author && (
    <>
     <RuleForm {...props} existing={r} />
     {!r.retired && <RetireForm {...props} rule={r} />}
     {r.rule.kind === 'alert' && <ReplayForm {...props} rule={r} />}
    </>
   )}
  </li>
 );
}

/** One project's rule catalogue (POST /api/v1/rules): the rules the leader-only background workers evaluate. Readers of the project see the
 * rules; organization administrators save, retire and declare replays. Every change is an audited command; a stale page is told so and reloaded. */
export function RuleSettings(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const c = props.context;
 const key = `${scopeKey(c)}|${props.project}|${c.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<RuleList> }>({ key: '', load: { kind: 'loading' } });
 const [reload, setReload] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  listRules(c.org, props.project, ctl.signal).then(
   (view) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: view } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, reload]);
 const load: LoadState<RuleList> = held.key === key ? held.load : { kind: 'loading' };
 const list = load.kind === 'ready' ? load.data : undefined;
 const form: FormProps | undefined = list ? { context: c, project: props.project, list, onChanged: () => setReload((n) => n + 1), onStale: () => setReload((n) => n + 1) } : undefined;
 return (
  <div data-section="rules" data-project-rules={props.project}>
   <h4>Rules for this project</h4>
   <p>A rule is evaluated by the node's background workers on its own fixed grid: an alert rule opens a condition for each series that stays present and notifies the organization's destinations; a recording rule writes its result back as a metric. A saved rule is checked first: an expression that does not parse or does not give an instant vector is refused and nothing is saved.</p>
   {load.kind !== 'ready' && <StatusPanel state={load} />}
   {list && form && (
    <>
     {list.rules.length === 0 ? <p role="status" data-state="empty">No rule is defined: nothing is evaluated for this project.</p> : <ul>{list.rules.map((r) => <RuleRow key={`${r.rule_id}:${r.revision}`} {...form} rule={r} />)}</ul>}
     {list.can_author ? <RuleForm key={`new:${list.rules.map((r) => `${r.rule_id}:${r.revision}`).join(',')}`} {...form} /> : <p>Only organization administrators change rules.</p>}
    </>
   )}
  </div>
 );
}
