// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import { newCommandId } from '../incidents/model';
import { AuditedForm } from '../settings/AuditedForm';
import { describeWriteFailure } from '../settings/policy';
import { MISSING_DATA, RULE_KINDS, RULE_SEVERITIES, buildRuleSpec, declareReplay, emptyRuleDraft, retireRule, ruleDraftOf, saveRule, utcToNs, type RuleDraft, type RuleList, type RuleView } from '../settings/rules';

export interface RuleFormProps { org: Id; project: Id; list: RuleList; onChanged: () => void; onStale: () => void }

const SAVED = 'Done. The server committed this change; the rules shown are the committed ones.';

/** Create a rule (no `existing`) or save the next version of one. The server checks the expression under the pinned profile: one that does not parse, or does not give an instant vector, is refused. */
export function RuleForm(props: RuleFormProps & { existing?: RuleView }): React.JSX.Element {
 const existing = props.existing;
 const [draft, setDraft] = React.useState<RuleDraft>(() => existing ? ruleDraftOf(existing) : emptyRuleDraft(props.list.profiles));
 const ruleId = React.useRef<Id>(existing?.rule_id ?? newCommandId());
 const set = (key: keyof RuleDraft) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>): void => setDraft((d) => ({ ...d, [key]: e.target.value }));
 const profile = props.list.profiles.find((p) => p.id === draft.profile);
 const alert = draft.kind === 'alert';
 return (
  <AuditedForm<RuleView>
   name={existing ? `rule-${existing.rule_id}` : 'rule-new'} label={existing ? `Save the next version of rule ${existing.rule_id}` : 'Save a new rule'} submitLabel="Save rule" describe={describeWriteFailure} onStale={props.onStale}
   saved={() => SAVED} onCommitted={props.onChanged}
   check={() => { const built = buildRuleSpec(draft, props.list.profiles); return built.ok ? (draft.kind === 'recording' && !props.list.recording_available ? 'This node has no recording source for this project: a recording rule cannot be saved.' : null) : built.error; }}
   fingerprint={() => JSON.stringify([draft, ruleId.current, existing?.revision ?? '0'])}
   run={async (command, reason, signal) => {
    const built = buildRuleSpec(draft, props.list.profiles);
    if (!built.ok) throw new Error(built.error);
    return saveRule({ org: props.org, project: props.project, command, rule: ruleId.current, expected_revision: existing?.revision ?? '0', reason, spec: built.value }, signal);
   }}>
   <div className="set-grid">
    <label>Kind <select value={draft.kind} onChange={set('kind')} data-autofocus>{RULE_KINDS.map((k) => <option key={k} value={k}>{k === 'alert' ? 'Alert' : 'Recording'}</option>)}</select></label>
    <label>Profile <select value={draft.profile} onChange={(e) => { const next = props.list.profiles.find((p) => p.id === e.target.value); setDraft((d) => ({ ...d, profile: e.target.value, featureSet: next?.feature_sets[0] ?? '' })); }}>{props.list.profiles.map((p) => <option key={p.id} value={p.id}>{p.id}</option>)}</select></label>
    <label>Feature set <select value={draft.featureSet} onChange={set('featureSet')}>{(profile?.feature_sets ?? []).map((f) => <option key={f} value={f}>{f}</option>)}</select></label>
    <label>Evaluate every (seconds) <input inputMode="numeric" value={draft.intervalSeconds} onChange={set('intervalSeconds')} /></label>
   </div>
   <label>Expression (must evaluate to an instant vector) <textarea className="mono" value={draft.expression} onChange={set('expression')} rows={3} spellCheck={false} autoComplete="off" /></label>
   {alert && (
    <div className="set-grid">
     <label>Fire after a series is present for (seconds) <input inputMode="numeric" value={draft.forSeconds} onChange={set('forSeconds')} /></label>
     <label>Recover after it is absent for (seconds) <input inputMode="numeric" value={draft.holdSeconds} onChange={set('holdSeconds')} /></label>
     <label>Severity <select value={draft.severity} onChange={set('severity')}>{RULE_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
     <label>Incomplete input is reported as <select value={draft.missingData} onChange={set('missingData')}>{MISSING_DATA.map((m) => <option key={m} value={m}>{m}</option>)}</select></label>
    </div>
   )}
   {!alert && (
    <>
     <label>Metric name written <input value={draft.recordName} onChange={set('recordName')} autoComplete="off" spellCheck={false} /></label>
     <label>Labels set on every series (one name=value per line; the source policy must list each value) <textarea className="mono" value={draft.labels} onChange={set('labels')} rows={3} spellCheck={false} autoComplete="off" /></label>
     {!props.list.recording_available && <p role="status" data-state="empty" className="set-empty">This node has no recording source for this project, so a recording rule cannot be saved.</p>}
    </>
   )}
  </AuditedForm>
 );
}

export function RetireForm(props: RuleFormProps & { rule: RuleView }): React.JSX.Element {
 const r = props.rule;
 return (
  <AuditedForm<RuleView>
   name={`retire-${r.rule_id}`} label={`Retire rule ${r.rule_id}`} submitLabel="Retire rule" describe={describeWriteFailure} onStale={props.onStale} saved={() => SAVED} onCommitted={props.onChanged}
   check={() => null} fingerprint={() => JSON.stringify([r.rule_id, r.revision])}
   run={(command, reason, signal) => retireRule({ org: props.org, project: props.project, command, rule: r.rule_id, expected_revision: r.revision, reason }, signal)}>
   <p className="small t2">A retired rule is no longer evaluated; its history stays and saving a new version brings it back.</p>
  </AuditedForm>
 );
}

/** The operator's replay declaration: late evaluations of the rule's grid points inside the window may notify. */
export function ReplayForm(props: RuleFormProps & { rule: RuleView }): React.JSX.Element {
 const r = props.rule;
 const [from, setFrom] = React.useState('');
 const [to, setTo] = React.useState('');
 return (
  <AuditedForm<void>
   name={`replay-${r.rule_id}`} label={`Declare an operator replay of rule ${r.rule_id}`} submitLabel="Declare replay" describe={describeWriteFailure} onStale={props.onStale} saved={() => SAVED} onCommitted={() => undefined}
   check={() => { const a = utcToNs(from), b = utcToNs(to); return a === null || b === null || BigInt(b) < BigInt(a) ? 'Give the window as UTC times such as 2026-11-15T10:00Z, the end not before the start.' : null; }}
   fingerprint={() => JSON.stringify([r.rule_id, from, to])}
   run={async (_command, reason, signal) => {
    const a = utcToNs(from), b = utcToNs(to);
    if (a === null || b === null) throw new Error('window');
    await declareReplay({ org: props.org, project: props.project, rule: r.rule_id, reason, from_ns: a, to_ns: b }, signal);
   }}>
   <p className="small t2">Evaluations that ran late (after an outage) never notify. Declaring a window here lets the late evaluations inside it notify; the declaration is audited.</p>
   <div className="set-grid">
    <label>From (UTC) <input value={from} onChange={(e) => setFrom(e.target.value)} placeholder="2026-11-15T10:00Z" autoComplete="off" /></label>
    <label>To (UTC) <input value={to} onChange={(e) => setTo(e.target.value)} placeholder="2026-11-15T11:00Z" autoComplete="off" /></label>
   </div>
  </AuditedForm>
 );
}
