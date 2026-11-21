// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { apiFault, isAbort, jsonPost } from '../api/client';
import { ApiFault, OutcomeUnknown, type Id } from '../api/types';
import type { Built } from './policy';

/** The rule catalogue of one project (POST /api/v1/rules): the rules the leader-only background workers evaluate. Saving is an audited
 * command of an organization administrator; the server checks the expression under the pinned profile and assigns the version. */

export const RULE_KINDS = ['alert', 'recording'] as const;
export type RuleKind = (typeof RULE_KINDS)[number];
export const RULE_SEVERITIES = ['info', 'warning', 'error', 'critical'] as const;
export const MISSING_DATA = ['unknown', 'error'] as const;
export const MAX_EXPRESSION_CHARS = 65536;
export const MAX_INTERVAL_SECONDS = 24 * 3600;
export const MAX_HOLD_SECONDS = 30 * 24 * 3600;
const MAX_LABELS = 64;

export interface RuleLabel { name: string; value: string }
export interface RuleSpec {
 kind: RuleKind; profile: string; feature_set: string; expression: string; interval_seconds: number;
 for_seconds?: number; recovery_hold_seconds?: number; missing_data?: string; severity?: string; record_name?: string; labels?: RuleLabel[];
}
export interface RuleView { rule_id: Id; revision: string; version: string; retired: boolean; created_ns: string; updated_ns: string; rule: RuleSpec }
export interface RuleProfile { id: string; feature_sets: string[] }
export interface RuleList { org: Id; project_id: Id; can_author: boolean; recording_available: boolean; profiles: RuleProfile[]; rules: RuleView[] }

const ID = /^[0-9a-f]{32}$/;
const DEC = /^(0|[1-9][0-9]*)$/;
const METRIC = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

function bad(): never { throw new ApiFault(502, 'bad_response', '', ''); }
function rec(v: unknown): Record<string, unknown> { return typeof v === 'object' && v !== null && !Array.isArray(v) ? v as Record<string, unknown> : bad(); }
function str(v: unknown, max = 1 << 20): string { return typeof v === 'string' && v.length <= max ? v : bad(); }
function dec(v: unknown): string { return typeof v === 'string' && DEC.test(v) ? v : bad(); }
function id(v: unknown): Id { return typeof v === 'string' && ID.test(v) ? v : bad(); }
function uint(v: unknown, max: number): number { return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max ? v : bad(); }

/** One rule as the server answers it; a field the page does not show is dropped and an out-of-shape one refuses the whole answer. */
export function parseRuleView(raw: unknown): RuleView {
 const r = rec(raw), s = rec(r.rule);
 const kind = RULE_KINDS.find((k) => k === s.kind);
 if (kind === undefined || typeof r.retired !== 'boolean') return bad();
 const labels = s.labels === undefined ? undefined : (Array.isArray(s.labels) && s.labels.length <= MAX_LABELS ? s.labels.map((l: unknown): RuleLabel => { const x = rec(l); return { name: str(x.name, 256), value: str(x.value, 1024) }; }) : bad());
 return {
  rule_id: id(r.rule_id), revision: dec(r.revision), version: dec(r.version), retired: r.retired, created_ns: dec(r.created_ns), updated_ns: dec(r.updated_ns),
  rule: {
   kind, profile: str(s.profile, 128), feature_set: str(s.feature_set, 128), expression: str(s.expression, MAX_EXPRESSION_CHARS * 4), interval_seconds: uint(s.interval_seconds, MAX_INTERVAL_SECONDS),
   ...(s.for_seconds !== undefined ? { for_seconds: uint(s.for_seconds, MAX_HOLD_SECONDS) } : {}),
   ...(s.recovery_hold_seconds !== undefined ? { recovery_hold_seconds: uint(s.recovery_hold_seconds, MAX_HOLD_SECONDS) } : {}),
   ...(s.missing_data !== undefined ? { missing_data: str(s.missing_data, 16) } : {}),
   ...(s.severity !== undefined ? { severity: str(s.severity, 16) } : {}),
   ...(s.record_name !== undefined ? { record_name: str(s.record_name, 256) } : {}),
   ...(labels !== undefined ? { labels } : {}),
  },
 };
}

/** The catalogue of the project the page asked for, and nothing of another one. */
export function parseRuleList(raw: unknown, want: { org: Id; project: Id }): RuleList {
 const r = rec(raw);
 if (r.org !== want.org || r.project_id !== want.project || typeof r.can_author !== 'boolean' || typeof r.recording_available !== 'boolean' || !Array.isArray(r.profiles) || !Array.isArray(r.rules)) return bad();
 const profiles = r.profiles.map((p: unknown): RuleProfile => { const x = rec(p); return { id: str(x.id, 128), feature_sets: Array.isArray(x.feature_sets) ? x.feature_sets.map((f: unknown) => str(f, 128)) : bad() }; });
 return { org: want.org, project_id: want.project, can_author: r.can_author, recording_available: r.recording_available, profiles, rules: r.rules.map(parseRuleView) };
}

/** What a person types: every field is text, converted and checked by buildRuleSpec. */
export interface RuleDraft {
 kind: RuleKind; profile: string; featureSet: string; expression: string; intervalSeconds: string; forSeconds: string; holdSeconds: string;
 missingData: string; severity: string; recordName: string; labels: string;
}

export function emptyRuleDraft(profiles: readonly RuleProfile[]): RuleDraft {
 const profile = profiles.find((p) => p.id.startsWith('promql-')) ?? profiles[0];
 return { kind: 'alert', profile: profile?.id ?? '', featureSet: profile?.feature_sets[0] ?? '', expression: '', intervalSeconds: '60', forSeconds: '0', holdSeconds: '0', missingData: 'unknown', severity: 'warning', recordName: '', labels: '' };
}

export function ruleDraftOf(v: RuleView): RuleDraft {
 const s = v.rule;
 return {
  kind: s.kind, profile: s.profile, featureSet: s.feature_set, expression: s.expression, intervalSeconds: String(s.interval_seconds), forSeconds: String(s.for_seconds ?? 0), holdSeconds: String(s.recovery_hold_seconds ?? 0),
  missingData: s.missing_data ?? 'unknown', severity: s.severity ?? 'warning', recordName: s.record_name ?? '', labels: (s.labels ?? []).map((l) => `${l.name}=${l.value}`).join('\n'),
 };
}

function wholeSeconds(text: string, max: number, min = 0): number | null {
 const t = text.trim();
 if (!/^\d{1,8}$/.test(t)) return null;
 const n = Number(t);
 return n >= min && n <= max ? n : null;
}

/** Labels of a recording rule, one `name=value` per line. */
export function parseLabelLines(text: string): Built<RuleLabel[]> {
 const out: RuleLabel[] = [];
 for (const raw of text.split('\n')) {
  const line = raw.trim();
  if (line === '') continue;
  const cut = line.indexOf('=');
  const name = cut < 0 ? '' : line.slice(0, cut).trim(), value = cut < 0 ? '' : line.slice(cut + 1).trim();
  if (!LABEL.test(name) || name === '__name__' || name.length > 256 || value.length > 1024) return { ok: false, error: `A label is written name=value with a name of letters, digits and underscores: "${line.slice(0, 40)}" is not.` };
  if (out.some((l) => l.name === name)) return { ok: false, error: `The label ${name} is given twice.` };
  out.push({ name, value });
 }
 if (out.length > MAX_LABELS) return { ok: false, error: `At most ${MAX_LABELS} labels.` };
 return { ok: true, value: out.sort((a, b) => (a.name < b.name ? -1 : 1)) };
}

/** The wire definition of a draft, or the one sentence that says what to fix. The server checks everything again (the expression is parsed
 * and type-checked under the pinned profile there); this only spares a round trip for what is plainly wrong. */
export function buildRuleSpec(d: RuleDraft, profiles: readonly RuleProfile[]): Built<RuleSpec> {
 const profile = profiles.find((p) => p.id === d.profile);
 if (!profile || !profile.feature_sets.includes(d.featureSet)) return { ok: false, error: 'Choose one of the pinned profiles and one of its feature sets.' };
 const expression = d.expression.trim();
 if (expression === '' || expression.length > MAX_EXPRESSION_CHARS) return { ok: false, error: `An expression of 1 to ${MAX_EXPRESSION_CHARS} characters is required.` };
 const interval = wholeSeconds(d.intervalSeconds, MAX_INTERVAL_SECONDS, 1);
 if (interval === null) return { ok: false, error: 'The evaluation interval is a whole number of seconds from 1 to 86400.' };
 const base = { profile: d.profile, feature_set: d.featureSet, expression, interval_seconds: interval };
 if (d.kind === 'alert') {
  const hold = wholeSeconds(d.forSeconds, MAX_HOLD_SECONDS), recovery = wholeSeconds(d.holdSeconds, MAX_HOLD_SECONDS);
  if (hold === null || recovery === null) return { ok: false, error: 'How long a series must be present before it fires, and absent before it recovers, are whole numbers of seconds up to 30 days.' };
  if (!(RULE_SEVERITIES as readonly string[]).includes(d.severity)) return { ok: false, error: 'Choose a severity: info, warning, error or critical.' };
  if (!(MISSING_DATA as readonly string[]).includes(d.missingData)) return { ok: false, error: 'Choose how incomplete input is reported: unknown or error.' };
  return { ok: true, value: { kind: 'alert', ...base, for_seconds: hold, recovery_hold_seconds: recovery, missing_data: d.missingData, severity: d.severity } };
 }
 const name = d.recordName.trim();
 if (!METRIC.test(name) || name.length > 256) return { ok: false, error: 'A recording rule needs the metric name it writes: letters, digits, underscores and colons, not starting with a digit.' };
 const labels = parseLabelLines(d.labels);
 if (!labels.ok) return labels;
 return { ok: true, value: { kind: 'recording', ...base, record_name: name, ...(labels.value.length > 0 ? { labels: labels.value } : {}) } };
}

/** The saved reason for the audit record: 1 to 512 bytes without control characters. */
export function validRuleReason(reason: string): boolean {
 const bytes = new TextEncoder().encode(reason).length;
 return bytes >= 1 && bytes <= 512 && !/\p{Cc}/u.test(reason);
}

/** Nanoseconds since the epoch, exactly, of a UTC date-time a person typed (`2026-11-15T10:00:00Z`); null when it is not one. */
export function utcToNs(text: string): string | null {
 const t = text.trim();
 if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z$/.test(t)) return null;
 const ms = Date.parse(t);
 return Number.isFinite(ms) && ms >= 0 ? (BigInt(ms) * 1000000n).toString() : null;
}

export interface RuleWriteRequest { org: Id; project: Id; command: Id; rule: Id; expected_revision: string; reason: string }

async function post(body: unknown, signal: AbortSignal): Promise<unknown> {
 let response: Response;
 try {
  response = await jsonPost('/api/v1/rules', body, signal);
 } catch (error) {
  if (isAbort(error)) throw error;
  throw new OutcomeUnknown();
 }
 if (!response.ok) throw await apiFault(response);
 return await response.json() as unknown;
}

/** POST /api/v1/rules {operation: list}: the project's catalogue and what the caller may do with it. */
export async function listRules(org: Id, project: Id, signal: AbortSignal): Promise<RuleList> {
 const response = await jsonPost('/api/v1/rules', { org, project_id: project, operation: 'list' }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseRuleList(await response.json() as unknown, { org, project });
}

function committed(raw: unknown): RuleView {
 const r = rec(raw);
 if (r.state !== 'committed') return bad();
 return parseRuleView(r.rule);
}

/** One audited save. Only a committed answer for this rule is a save; a transport failure is OutcomeUnknown and the same command ID may be resent. */
export async function saveRule(req: RuleWriteRequest & { spec: RuleSpec }, signal: AbortSignal): Promise<RuleView> {
 const view = committed(await post({ org: req.org, project_id: req.project, operation: 'save', command_id: req.command, rule_id: req.rule, expected_revision: req.expected_revision, reason: req.reason, rule: req.spec }, signal));
 return view.rule_id === req.rule ? view : bad();
}

export async function retireRule(req: RuleWriteRequest, signal: AbortSignal): Promise<RuleView> {
 const view = committed(await post({ org: req.org, project_id: req.project, operation: 'retire', command_id: req.command, rule_id: req.rule, expected_revision: req.expected_revision, reason: req.reason }, signal));
 return view.rule_id === req.rule ? view : bad();
}

/** The operator's replay declaration: late evaluations of the rule's grid points in [from_ns, to_ns] may notify. */
export async function declareReplay(req: { org: Id; project: Id; rule: Id; reason: string; from_ns: string; to_ns: string }, signal: AbortSignal): Promise<void> {
 const r = rec(await post({ org: req.org, project_id: req.project, operation: 'replay', rule_id: req.rule, reason: req.reason, replay: { from_ns: req.from_ns, to_ns: req.to_ns } }, signal));
 if (r.state !== 'committed' || r.rule_id !== req.rule) bad();
}
