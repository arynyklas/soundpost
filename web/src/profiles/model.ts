// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Strict wire parser and pure view mapping for the profile page. Every state of a profile is turned into words here, so no
// state is carried by colour or position alone. Nanoseconds and counts are decimal strings on the wire and BigInt here,
// never `number`. Lost time is shown as a gap: nothing in this file interpolates a stack, a sample or an interval.
import { ApiFault, type Id, type ViewState } from '../api/types';
import { durationText } from '../traces/model';
import {
 CAPABILITY_STATUSES, COVERAGE_LEVELS, INTERVAL_KINDS, LINK_RELATIONS, NATIVE_LOSS_REASONS, PROFILE_METHODS, PROFILE_UNITS,
 type Capability, type CapabilityRecord, type Correlation, type IntervalKind, type ProfileFrame, type ProfileInterval, type ProfileResponse, type ProfileSample, type ProfileView, type ResolvedReference,
} from './types';

const ID32 = /^[0-9a-f]{32}$/;
const UDEC = /^(0|[1-9][0-9]{0,19})$/;
const IDEC = /^(0|-?[1-9][0-9]{0,18})$/;
const CODE = /^[a-z0-9_]{1,64}$/;
const U64_MAX = 18446744073709551615n;
const I64_MIN = -9223372036854775808n;
const I64_MAX = 9223372036854775807n;
const STATES: readonly ViewState[] = ['ready', 'empty', 'incomplete', 'stale', 'not_available'];

/** Bounds on what a profile response may carry; the server caps a page at the same order of magnitude (internal/profiles). */
export const MAX_FRAMES = 8192;
export const MAX_STACKS = 8192;
export const MAX_STACK_DEPTH = 128;
export const MAX_OBSERVATIONS = 8192;
export const MAX_CAPABILITIES = 512;
export const MAX_LOSS_REPORTS = 1024;
export const MAX_NATIVE_LOSS = 256;
export const MAX_LINKS = 128;
export const MAX_WATERMARKS = 1024;
export const MAX_REASONS = 64;
const MAX_SECTIONS = 32;
const MAX_TEXT = 1024;
const MAX_CURSOR = 16384;

const fault = (): ApiFault => new ApiFault(200, 'invalid_response', '', 'response does not match the request');
function need(ok: boolean): asserts ok { if (!ok) throw fault(); }
const isRec = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown, max = MAX_TEXT): v is string => typeof v === 'string' && v.length <= max;
const id = (v: unknown): v is string => typeof v === 'string' && ID32.test(v);
const code = (v: unknown): v is string => typeof v === 'string' && CODE.test(v);
const udec = (v: unknown): v is string => typeof v === 'string' && UDEC.test(v) && BigInt(v) <= U64_MAX;
const idec = (v: unknown): v is string => typeof v === 'string' && IDEC.test(v) && BigInt(v) >= I64_MIN && BigInt(v) <= I64_MAX;
const uint = (v: unknown, max = 0xffffffff): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
/** A list that may be JSON null (Go encodes a nil slice as null) and is never longer than `max`; null is an empty list. */
function listOf(v: unknown, max: number): unknown[] {
 const a = v === null ? [] : v;
 need(Array.isArray(a) && a.length <= max);
 return a;
}

function parseDomain(v: unknown): void { need(isRec(v) && id(v.host) && id(v.boot) && id(v.runtime)); }
function parseTask(v: unknown): void {
 need(isRec(v) && text(v.boot_id, 128) && udec(v.pid_namespace) && uint(v.tgid) && uint(v.tid) && udec(v.process_start_ns) && udec(v.generation));
}
function parseNativeSample(v: unknown): void {
 need(isRec(v) && code(v.method) && code(v.unit) && uint(v.requested_hz) && udec(v.period));
 parseTask(v.task);
 for (const k of ['truncation', 'coverage', 'throttle_reason']) need(v[k] === undefined || code(v[k]));
 for (const k of ['throttle_event_id', 'throttle_stream_id']) need(v[k] === undefined || udec(v[k]));
}
function parseCursor(v: unknown): void { need(isRec(v) && id(v.group) && udec(v.index)); }

function parseCapability(v: unknown): void {
 need(isRec(v) && id(v.id) && isRec(v.value));
 const c = v.value;
 need(text(c.runtime, 128) && text(c.version, 128) && text(c.build, 256) && text(c.os, 64) && text(c.arch, 64) && text(c.signal, 64) && text(c.method, 128) && text(c.reason, 128));
 need(CAPABILITY_STATUSES.includes(c.status as never) && idec(c.expires_ns));
 need(isRec(c.coverage) && ['frames', 'threads', 'workers', 'tasks'].every((k) => COVERAGE_LEVELS.includes((c.coverage as Record<string, unknown>)[k] as never)));
 parseDomain(c.clock_domain);
}
function parseLossReport(v: unknown): void {
 need(isRec(v) && id(v.source) && id(v.producer) && id(v.producer_epoch) && idec(v.start_ns) && idec(v.end_ns) && text(v.signal, 64) && code(v.reason) && udec(v.count) && udec(v.queue_bytes) && udec(v.queue_records));
 need(BigInt(v.end_ns) >= BigInt(v.start_ns));
 if (v.last_ack !== null) parseCursor(v.last_ack);
}
function parseLink(v: unknown): void {
 need(isRec(v) && typeof v.available === 'boolean');
 if (!v.available) { need(v.reference === undefined); return; }
 const r = v.reference;
 need(isRec(r) && id(r.project_id) && id(r.build_id) && id(r.id) && code(r.kind) && LINK_RELATIONS.includes(r.relation as never));
}

function parseView(raw: unknown, want: { project: Id; profile: Id }): ProfileView {
 need(isRec(raw) && raw.profile_id === want.profile && raw.project_id === want.project && id(raw.process_id));
 need(PROFILE_METHODS.includes(raw.method as never) && PROFILE_UNITS.includes(raw.units as never));
 parseClock(raw.clock);
 if (raw.native_domain !== undefined) {
  const d = raw.native_domain;
  need(isRec(d) && text(d.host_id, 128) && d.host_id !== '' && text(d.boot_id, 128) && d.boot_id !== '');
  // internal/model validateNativeProfile: native CPU is counted in samples, native off-CPU in nanoseconds.
  need(raw.method === 'runtime_cpu' ? false : raw.method === 'native_cpu' ? raw.units === 'samples' : raw.units === 'nanoseconds');
 }
 const frames = listOf(raw.frames, MAX_FRAMES);
 for (const f of frames) {
  need(isRec(f) && text(f.module_id) && text(f.function) && text(f.artifact_id) && udec(f.offset) && text(f.reason, 64));
  need(f.reason === '' || code(f.reason));
 }
 const stacks = listOf(raw.stacks, MAX_STACKS).map((s) => {
  need(isRec(s));
  const refs = listOf(s.frames, MAX_STACK_DEPTH);
  need(refs.every((i) => uint(i, frames.length - 1)));
  return { frames: refs as number[] };
 });
 const samples = listOf(raw.samples, MAX_OBSERVATIONS);
 const intervals = listOf(raw.intervals, MAX_OBSERVATIONS);
 need(samples.length + intervals.length <= MAX_OBSERVATIONS);
 for (const s of samples) {
  need(isRec(s) && udec(s.at_ns) && uint(s.stack, stacks.length - 1) && udec(s.count) && BigInt(s.count) > 0n && udec(s.thread));
  if (s.native !== undefined) parseNativeSample(s.native);
 }
 for (const i of intervals) {
  need(isRec(i) && udec(i.start_ns) && udec(i.end_ns) && BigInt(i.end_ns) >= BigInt(i.start_ns) && uint(i.stack, stacks.length - 1) && INTERVAL_KINDS.includes(i.kind as never) && udec(i.thread) && typeof i.censored === 'boolean');
  if (i.native_task !== undefined) parseTask(i.native_task);
  need(i.unit === undefined || code(i.unit));
  need(i.reason === undefined || code(i.reason));
  need(i.correction === undefined || typeof i.correction === 'boolean');
 }
 const capabilities = listOf(raw.capabilities, MAX_CAPABILITIES);
 capabilities.forEach(parseCapability);
 const loss = listOf(raw.loss, MAX_LOSS_REPORTS);
 loss.forEach(parseLossReport);
 need(udec(raw.loss_count) && typeof raw.truncated === 'boolean');
 if (raw.native_loss !== undefined) {
  const nl = listOf(raw.native_loss, MAX_NATIVE_LOSS);
  for (const l of nl) {
   need(isRec(l) && udec(l.at_ns) && uint(l.cpu) && udec(l.count) && NATIVE_LOSS_REASONS.includes(l.reason as never));
   for (const k of ['throttle_event_id', 'throttle_stream_id']) need(l[k] === undefined || udec(l[k]));
  }
 }
 for (const k of ['blocked_ns', 'runnable_ns', 'unknown_ns']) need(raw[k] === undefined || udec(raw[k]));
 const links = listOf(raw.links, MAX_LINKS);
 links.forEach(parseLink);
 const watermarks = listOf(raw.watermarks, MAX_WATERMARKS);
 watermarks.forEach(parseCursor);
 need(raw.completeness === 'complete' || raw.completeness === 'partial');
 const reasons = listOf(raw.reasons, MAX_REASONS);
 need(reasons.every(code));
 need(raw.next_cursor === undefined || (typeof raw.next_cursor === 'string' && raw.next_cursor.length >= 1 && raw.next_cursor.length <= MAX_CURSOR));
 return { ...raw, frames, stacks, samples, intervals, capabilities, loss, links, watermarks, reasons } as unknown as ProfileView;
}
function parseClock(v: unknown): void {
 need(isRec(v) && idec(v.wall_ns) && udec(v.mono_ns) && udec(v.uncertainty_ns));
 parseDomain(v.domain);
}

/** Accepts a profile response only for exactly the requested organization, project and profile. A response for another one, a nanosecond JSON number, an out-of-range stack or frame index, an unknown enum or an oversized list is a fault and is never rendered. A nil list on the wire (JSON null) is read as an empty list. */
export function parseProfileResponse(raw: unknown, want: { org: Id; project: Id; profile: Id }): ProfileResponse {
 need(isRec(raw) && raw.org === want.org && raw.project === want.project && raw.profile === want.profile && STATES.includes(raw.state as ViewState) && typeof raw.partial === 'boolean');
 const state = raw.state as ViewState;
 need(raw.reason === undefined || code(raw.reason));
 const sections = listOf(raw.sections, MAX_SECTIONS);
 need(sections.every((s) => isRec(s) && text(s.name, 64) && s.name !== '' && STATES.includes(s.state as ViewState) && (s.reason === undefined || code(s.reason))));
 const view = raw.view === undefined ? undefined : parseView(raw.view, want);
 // ready and incomplete always carry a view; empty and not_available never do. The partial flag says exactly what the view says.
 need((state === 'ready' || state === 'incomplete') ? view !== undefined : (state === 'empty' || state === 'not_available') ? view === undefined : true);
 if (view === undefined) need(!raw.partial);
 else {
  need(raw.partial === (view.completeness === 'partial' || view.truncated));
  need(state !== 'ready' || !raw.partial);
  need(state !== 'incomplete' || raw.partial);
 }
 return {
  org: want.org, project: want.project, profile: want.profile, state, ...(raw.reason === undefined ? {} : { reason: raw.reason as string }), partial: raw.partial,
  ...(view === undefined ? {} : { view }), sections: sections as ProfileResponse['sections'],
 };
}

// ---- numbers and times ---------------------------------------------------------------------------------------------
const big = (s: string): bigint => BigInt(s);
/** A decimal integer with thousands separators; exact for any size. */
export function groupDigits(n: bigint | string | number): string {
 const s = String(n);
 const neg = s.startsWith('-');
 const d = neg ? s.slice(1) : s;
 return `${neg ? '-' : ''}${d.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}`;
}
const NS_PER_MS = 1_000_000n;
const MIN_MS = -62_167_219_200_000n; // 0000-01-01T00:00:00Z
const MAX_MS = 253_402_300_799_999n; // 9999-12-31T23:59:59.999Z
/** A nanosecond Unix timestamp as exact UTC text (nine fractional digits), computed from BigInt. Years outside 0000..9999 are given as a plain count. */
export function utcText(ns: bigint): string {
 let ms = ns / NS_PER_MS;
 let rem = ns % NS_PER_MS;
 if (rem < 0n) { rem += NS_PER_MS; ms -= 1n; }
 if (ms < MIN_MS || ms > MAX_MS) return `${groupDigits(ns)} ns since the Unix epoch`;
 const iso = new Date(Number(ms)).toISOString();
 return `${iso.slice(0, 19)}.${iso.slice(20, 23)}${rem.toString().padStart(6, '0')} UTC`;
}
const monoText = (ns: bigint): string => `${groupDigits(ns)} ns`;

// ---- words ---------------------------------------------------------------------------------------------------------
const REASONS: Record<string, string> = {
 profile_service_not_wired: 'This installation has no profile reader wired, so no profile can be shown. That is not an empty profile',
 profile_partial: 'The profile is partial',
 missing_capability_or_page: 'A page or a capability record that the profile needs is missing',
 missing_chunk: 'A chunk of the profile is missing; the sequence of chunks has a hole',
 coverage_incomplete: 'Coverage is incomplete: data was lost, truncated or never completed',
 no_observations_in_window: 'No sample or interval was observed in the selected window',
 platform_unsupported: 'the platform does not support this collection',
 permission_denied: 'permission to collect was denied',
 tracefs_unavailable: 'the kernel trace filesystem is unavailable',
 event_unavailable: 'a needed kernel event is unavailable',
 coverage_unmeasured: 'coverage was not measured, so the observation is unknown',
 acquisition_pending: 'acquisition had not completed',
 callchain_truncated: 'the call chain was cut short',
 records_lost: 'kernel records were lost',
 samples_lost: 'samples were lost',
 generation_changed: 'the process generation changed',
 clock_uncertain: 'the clock is uncertain',
 frame_unresolved: 'a frame could not be resolved',
 missing_switch_callchain: 'the switch-out recorded no call chain',
 missing_callchain: 'no call chain was recorded',
 throttled: 'the kernel throttled sampling',
 unthrottled: 'the kernel resumed sampling after throttling',
 missing_frame_pointer_or_callchain: 'no frame pointer or call chain was available',
 build_not_approved: 'the build is not approved for symbol lookup',
 deleted_executable: 'the executable was deleted',
 jit_or_anonymous_map_unavailable: 'no map for jitted or anonymous code was available',
 jit_map_expired: 'the map for jitted code expired',
 artifact_unavailable: 'the artifact is not available',
 artifact_denied: 'the artifact is not available to this account',
 invalid_elf_artifact: 'the artifact is not a valid executable',
 unresolved: 'the frame was not resolved',
 not_captured: 'the frame was not captured',
 unsupported: 'the collection is not supported',
 missing_artifact: 'the artifact is missing',
 queue_full: 'the sender queue was full',
 expired: 'the record expired before it could be sent',
 policy: 'the capture policy dropped it',
 ring_overflow: 'the collector ring overflowed',
 reorder_gap: 'records arrived out of order beyond the reorder window',
 transport: 'the transport failed',
 shutdown: 'the collector shut down',
 truncated: 'the profile was cut short',
};
/** A reason code as a phrase that keeps the code itself visible. */
export function reasonWords(c: string): string {
 const w = REASONS[c];
 return w === undefined ? `reason ${c}` : `${w} (${c})`;
}

const STATE_WORD: Record<ViewState, string> = { ready: 'Ready', empty: 'Empty', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };
/** The state of a response in words: its state, its reason and the completeness the server computed. */
export function stateWords(r: ProfileResponse): string {
 const parts = [`State: ${STATE_WORD[r.state]}.`];
 if (r.reason !== undefined) parts.push(`${reasonWords(r.reason)}.`);
 if (r.view !== undefined) parts.push(completenessWords(r.view));
 else if (r.state === 'not_available') parts.push('No profile is shown. Not available is not an empty profile and not zero.');
 else if (r.state === 'empty') parts.push('No profile was found in this window. Nothing is missing.');
 return parts.join(' ');
}
export function completenessWords(v: ProfileView): string {
 const head = v.completeness === 'complete'
  ? 'Completeness: complete. Every expected chunk and capability record was present.'
  : 'Completeness: partial. Some expected data is missing or lost, and what is missing is not estimated.';
 return v.reasons.length === 0 ? head : `${head} Reasons: ${v.reasons.map(reasonWords).join('; ')}.`;
}

const METHOD_WORD: Record<string, string> = {
 native_cpu: 'native_cpu: OS on-CPU samples taken by the operating system',
 runtime_cpu: 'runtime_cpu: samples reported by the language engine (runtime profiler)',
 native_offcpu: 'native_offcpu: OS off-CPU scheduler intervals (blocked, runnable, unknown)',
};
export const methodWords = (m: string): string => METHOD_WORD[m] ?? m;
const STATUS_WORD: Record<string, string> = {
 supported: 'supported',
 denied: 'denied (the collector was refused permission)',
 unsupported: 'unsupported (this runtime or platform cannot collect it)',
 error: 'error (probing the capability failed)',
};
export const statusWords = (s: string): string => STATUS_WORD[s] ?? s;
const COVERAGE_WORD: Record<string, string> = { complete: 'complete', partial: 'partial (some are missing)', none: 'none (not covered)', unknown: 'unknown (not measured)' };
export const coverageWords = (c: string): string => COVERAGE_WORD[c] ?? c;

// ---- observations ----------------------------------------------------------------------------------------------------
export interface Observations { samples: number; intervals: number; total: number }
export function observations(v: ProfileView): Observations {
 return { samples: v.samples.length, intervals: v.intervals.length, total: v.samples.length + v.intervals.length };
}
const sumCounts = (samples: ProfileSample[]): bigint => samples.reduce((n, s) => n + big(s.count), 0n);
const ofKind = (v: ProfileView, kind: IntervalKind): ProfileInterval[] => v.intervals.filter((i) => i.kind === kind);
const hasUnknown = (v: ProfileView): boolean => v.unknown_ns !== undefined || v.intervals.some((i) => i.kind === 'unknown_offcpu');

function capFor(v: ProfileView, method: string): Capability | undefined {
 const rows = v.capabilities.filter((c) => c.value.method === method);
 return (rows.find((c) => c.value.status === 'supported') ?? rows[0])?.value;
}
/** An engine or browser sampling capability: the SDKs name theirs by runtime method (runtime_engine_samples, browser_js_self_profile), not by the chunk method runtime_cpu, so every capability that is not a native_* method describes the engine side. */
function engineCapability(v: ProfileView): Capability | undefined {
 const rows = v.capabilities.filter((c) => !c.value.method.startsWith('native_'));
 return (rows.find((c) => c.value.status === 'supported') ?? rows[0])?.value;
}
/** The capability that describes how this profile was collected: the row for its own method, else the first row. */
export function primaryCapability(v: ProfileView): Capability | undefined {
 return capFor(v, v.method) ?? v.capabilities[0]?.value;
}

// ---- requested versus achieved sampling --------------------------------------------------------------------------
export interface Sampling { requested: string; achieved: string }
/** Requested is the native requested_hz; achieved is only what the profile reports (the native period). Nothing is derived for an engine profile: its sampling interval is not reported. */
export function sampling(v: ProfileView): Sampling {
 const natives = v.samples.flatMap((s) => (s.native === undefined ? [] : [s.native]));
 if (natives.length === 0) return { requested: 'not reported', achieved: 'not reported' };
 const hz = [...new Set(natives.map((n) => n.requested_hz).filter((h) => h > 0))].sort((a, b) => a - b);
 const periods = new Map<string, number>();
 for (const n of natives) { const k = `${n.period} ${n.unit}`; periods.set(k, (periods.get(k) ?? 0) + 1); }
 const ordered = [...periods.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
 const shown = ordered.slice(0, 5).map(([k]) => { const [p, u] = k.split(' ') as [string, string]; return `period ${groupDigits(p)} ${u} per sample`; });
 const more = ordered.length > 5 ? `; ${ordered.length - 5} other period values` : '';
 return {
  requested: hz.length === 0 ? 'not reported' : `${hz.join(', ')} Hz`,
  achieved: `${shown.join('; ')}${more} (as reported by the collector)`,
 };
}
const nativeUnits = (v: ProfileView): string => {
 const u = [...new Set(v.samples.flatMap((s) => (s.native === undefined ? [] : [s.native.unit])))].sort();
 return u.length === 0 ? 'not reported' : u.join(', ');
};

// ---- the five readings that are never added together ---------------------------------------------------------------
export type UnitState = 'measured' | 'not_measured' | 'no_observations' | 'unknown_split' | 'unsupported' | 'denied' | 'error';
export interface UnitRow { id: 'oscpu' | 'engine' | 'blocked' | 'runnable' | 'unknown-split'; label: string; meaning: string; state: UnitState; text: string }

function unavailable(c: Capability, method: string): { state: UnitState; text: string } {
 const state = c.status as UnitState;
 return { state, text: `${c.status}: ${c.runtime === '' ? 'the collector' : c.runtime} reported ${method} as ${c.status}${c.reason === '' ? '' : ` (reason ${c.reason})`}. Nothing was measured by this method.` };
}
function intervalDetail(list: ProfileInterval[]): string {
 const censored = list.filter((i) => i.censored).length;
 const n = `${groupDigits(list.length)} ${list.length === 1 ? 'interval' : 'intervals'}`;
 return censored === 0 ? n : `${n}, ${groupDigits(censored)} censored: the end of a censored wait was not observed, so it is not a completed measurement`;
}

/** OS on-CPU sample units, engine sample deltas, blocked time, runnable delay and the unknown off-CPU split: five separate readings. None is a sum of the others and none is presented as one CPU duration. An absent blocked/runnable/unknown figure reads `not measured`, never 0; off-CPU time without wake evidence reads `unknown split`; an unavailable method reads its capability word. */
export function unitRows(v: ProfileView): UnitRow[] {
 const rows: UnitRow[] = [];
 const s = sampling(v);

 const nativeCap = capFor(v, 'native_cpu');
 const osMeasured = v.method === 'native_cpu' && v.samples.length > 0;
 {
  const base = { id: 'oscpu', label: 'OS on-CPU samples', meaning: 'Samples the operating system took while a thread ran. A count of samples in the unit the sampler reports; not a duration.' } as const;
  if (osMeasured) rows.push({ ...base, state: 'measured', text: `${groupDigits(sumCounts(v.samples))} on-CPU samples; unit ${nativeUnits(v)}; ${s.achieved}; requested ${s.requested}` });
  else if (nativeCap !== undefined && nativeCap.status !== 'supported') rows.push({ ...base, ...unavailable(nativeCap, 'native_cpu') });
  else rows.push({ ...base, state: v.method === 'native_cpu' ? 'no_observations' : 'not_measured', text: v.method === 'native_cpu' ? 'no observations' : 'not measured' });
 }

 const engineCap = engineCapability(v);
 {
  const base = { id: 'engine', label: 'Engine-reported samples', meaning: 'Samples or deltas reported by the language engine, in the unit the engine reports. Not OS CPU time and not comparable to the OS sample count.' } as const;
  if (v.method === 'runtime_cpu' && v.samples.length > 0) {
   const sum = sumCounts(v.samples);
   rows.push({ ...base, state: 'measured', text: v.units === 'nanoseconds' ? `${groupDigits(sum)} ns, engine-reported deltas` : `${groupDigits(sum)} samples, engine-reported` });
  } else if (engineCap !== undefined && engineCap.status !== 'supported') rows.push({ ...base, ...unavailable(engineCap, 'runtime_cpu') });
  else rows.push({ ...base, state: v.method === 'runtime_cpu' ? 'no_observations' : 'not_measured', text: v.method === 'runtime_cpu' ? 'no observations' : 'not measured' });
 }

 const offCap = capFor(v, 'native_offcpu');
 const unknownPresent = hasUnknown(v);
 const offRow = (idv: 'blocked' | 'runnable', label: string, meaning: string, total: string | undefined, kind: IntervalKind): UnitRow => {
  const base = { id: idv, label, meaning } as const;
  if (total !== undefined) return { ...base, state: 'measured', text: `${durationText(big(total))} (exactly ${groupDigits(total)} ns); ${intervalDetail(ofKind(v, kind))}` };
  if (offCap !== undefined && offCap.status !== 'supported') return { ...base, ...unavailable(offCap, 'native_offcpu') };
  if (unknownPresent) return { ...base, state: 'unknown_split', text: 'unknown split: off-CPU time was observed, but without wake evidence it cannot be divided into blocked and runnable' };
  if (v.method === 'native_offcpu' && v.intervals.length === 0) return { ...base, state: 'no_observations', text: 'no observations' };
  return { ...base, state: 'not_measured', text: 'not measured' };
 };
 rows.push(offRow('blocked', 'Blocked time', 'Wall time a thread waited before its wakeup was observed (for example on I/O or a lock). Not CPU time.', v.blocked_ns, 'blocked'));
 rows.push(offRow('runnable', 'Runnable delay', 'Wall time a thread was ready to run but had no CPU, from its wakeup until it ran again. Not CPU time.', v.runnable_ns, 'runnable'));
 {
  const base = { id: 'unknown-split', label: 'Off-CPU time with an unknown split', meaning: 'Wall time off the CPU where wake evidence is missing, so it is not divided into blocked and runnable. It is never assigned to either.' } as const;
  if (v.unknown_ns !== undefined) rows.push({ ...base, state: 'measured', text: `${durationText(big(v.unknown_ns))} (exactly ${groupDigits(v.unknown_ns)} ns) with an unknown split between blocked and runnable; ${intervalDetail(ofKind(v, 'unknown_offcpu'))}` });
  else if (unknownPresent) rows.push({ ...base, state: 'unknown_split', text: `unknown split: ${intervalDetail(ofKind(v, 'unknown_offcpu'))}; no total was reported` });
  else if (offCap !== undefined && offCap.status !== 'supported') rows.push({ ...base, ...unavailable(offCap, 'native_offcpu') });
  else rows.push({ ...base, state: v.method === 'native_offcpu' && v.intervals.length === 0 ? 'no_observations' : 'not_measured', text: v.method === 'native_offcpu' && v.intervals.length === 0 ? 'no observations' : 'not measured' });
 }
 return rows;
}

// ---- header facts ----------------------------------------------------------------------------------------------------
export interface Fact { label: string; value: string; testId?: string }
/** Method, units, engine and build, operating system, and the clock the times are read against. Anything the profile does not report reads `not reported`. */
export function headerFacts(v: ProfileView): Fact[] {
 const c = primaryCapability(v);
 const or = (s: string | undefined): string => (s === undefined || s === '' ? 'not reported' : s);
 const facts: Fact[] = [
  { label: 'Method', value: methodWords(v.method), testId: 'profile-method' },
  { label: 'Units', value: v.units === 'samples' ? 'samples (a count of observations)' : 'nanoseconds' },
  { label: 'Engine or runtime', value: c === undefined ? 'not reported' : `${or(c.runtime)} ${or(c.version)}` },
  { label: 'Build', value: or(c?.build) },
  { label: 'Operating system and architecture', value: c === undefined ? 'not reported' : `${or(c.os)} / ${or(c.arch)}` },
  { label: 'Clock domain', value: `host ${v.clock.domain.host}, boot ${v.clock.domain.boot}, runtime ${v.clock.domain.runtime}` },
  { label: 'Clock uncertainty', value: `plus or minus ${durationText(big(v.clock.uncertainty_ns))} (exactly ${groupDigits(v.clock.uncertainty_ns)} ns)` },
  { label: 'Reference instant', value: `${utcText(big(v.clock.wall_ns))} on the wall clock is ${monoText(big(v.clock.mono_ns))} on the monotonic clock of this domain` },
  { label: 'Process', value: v.process_id },
 ];
 if (v.native_domain !== undefined) facts.push({ label: 'Native domain', value: `host ${v.native_domain.host_id}, boot ${v.native_domain.boot_id}` });
 return facts;
}

// ---- capabilities --------------------------------------------------------------------------------------------------
export interface CapabilityRow {
 key: string; id: string; engine: string; platform: string; method: string; status: string; statusWord: string; reason: string; expires: string; observations: string;
}
function obsFor(v: ProfileView, method: string): number | null {
 if (method === v.method) return method === 'native_offcpu' ? v.intervals.length : v.samples.length;
 if (method === 'native_offcpu') return v.intervals.length > 0 ? v.intervals.length : null;
 return null;
}
export function capabilityRows(v: ProfileView): CapabilityRow[] {
 return v.capabilities.map((r: CapabilityRecord, i) => {
  const c = r.value;
  const n = obsFor(v, c.method);
  let observations: string;
  if (c.status !== 'supported') observations = `${c.status}: nothing was measured by this method`;
  else if (n === null) observations = `not part of this view (this view is ${v.method})`;
  else observations = n === 0 ? 'no observations' : `${groupDigits(n)} ${n === 1 ? 'observation' : 'observations'}`;
  return {
   key: `${i}:${r.id}`, id: r.id, engine: `${c.runtime} ${c.version}, build ${c.build}`, platform: `${c.os} / ${c.arch}`, method: c.method, status: c.status, statusWord: statusWords(c.status),
   reason: c.reason === '' ? 'none given' : c.reason, expires: `expires ${utcText(big(c.expires_ns))}`, observations,
  };
 });
}

export interface CoverageRow { key: string; label: string; frames: string; threads: string; workers: string; tasks: string }
export function coverageRows(v: ProfileView): CoverageRow[] {
 return v.capabilities.map((r, i) => ({
  key: `${i}:${r.id}`, label: `${r.value.runtime} ${r.value.method}`, frames: coverageWords(r.value.coverage.frames), threads: coverageWords(r.value.coverage.threads),
  workers: coverageWords(r.value.coverage.workers), tasks: coverageWords(r.value.coverage.tasks),
 }));
}
/** What the samples themselves say about their frames: unresolved, truncated or throttled, counted by reason. */
export function sampleCoverageLines(v: ProfileView): string[] {
 const tally = (pick: (s: NonNullable<ProfileSample['native']>) => string | undefined): Map<string, number> => {
  const m = new Map<string, number>();
  for (const s of v.samples) { const k = s.native === undefined ? undefined : pick(s.native); if (k !== undefined && k !== '') m.set(k, (m.get(k) ?? 0) + 1); }
  return m;
 };
 const lines: string[] = [];
 for (const [k, n] of tally((x) => x.coverage)) lines.push(`${groupDigits(n)} ${n === 1 ? 'sample has' : 'samples have'} incomplete frame coverage: ${reasonWords(k)}`);
 for (const [k, n] of tally((x) => x.truncation)) lines.push(`${groupDigits(n)} ${n === 1 ? 'sample was' : 'samples were'} truncated: ${reasonWords(k)}`);
 for (const [k, n] of tally((x) => x.throttle_reason)) lines.push(`${groupDigits(n)} ${n === 1 ? 'sample was' : 'samples were'} taken at a throttle boundary: ${reasonWords(k)}`);
 return lines;
}

// ---- loss --------------------------------------------------------------------------------------------------------
export interface LossRow { key: string; signal: string; reason: string; count: string; span: string; queue: string }
export interface LossFacts { lines: string[]; reports: LossRow[] }
/** Loss in words. Lost time is a gap: no stack, sample or interval is invented for it. */
export function lossFacts(v: ProfileView): LossFacts {
 const lines: string[] = [];
 lines.push(v.loss_count === '0' ? 'Lost records counted for this profile: none were counted.' : `Lost records counted for this profile: ${groupDigits(v.loss_count)}.`);
 lines.push(v.truncated ? 'Truncated: yes. The collector cut this profile short; what was cut is not shown and is not estimated.' : 'Truncated: no.');
 const byReason = new Map<string, { n: bigint; events: number; cpus: Set<number> }>();
 for (const l of v.native_loss ?? []) {
  const e = byReason.get(l.reason) ?? { n: 0n, events: 0, cpus: new Set<number>() };
  e.n += big(l.count); e.events += 1; e.cpus.add(l.cpu);
  byReason.set(l.reason, e);
 }
 for (const [r, e] of byReason) {
  const cpus = `on ${[...e.cpus].sort((a, b) => a - b).map((c) => `cpu ${c}`).join(', ')}`;
  if (r === 'records_lost') lines.push(`Kernel records lost: ${groupDigits(e.n)} ${cpus}.`);
  else if (r === 'samples_lost') lines.push(`Samples lost: ${groupDigits(e.n)} ${cpus}.`);
  else if (r === 'throttled') lines.push(`Sampling was throttled by the kernel ${e.events} ${e.events === 1 ? 'time' : 'times'} ${cpus}; samples are missing for the throttled time.`);
  else lines.push(`Sampling resumed after throttling ${e.events} ${e.events === 1 ? 'time' : 'times'} ${cpus}.`);
 }
 if (v.loss.length === 0 && byReason.size === 0 && v.loss_count === '0' && !v.truncated) lines.push('No loss was reported. That does not prove that nothing was lost outside what the collector could observe.');
 lines.push('Lost time appears as a gap. No stack, sample or interval is invented for it, and no figure is interpolated across it.');
 const reports: LossRow[] = v.loss.map((l, i) => ({
  key: `${i}:${l.source}:${l.start_ns}`, signal: l.signal, reason: reasonWords(l.reason), count: groupDigits(l.count),
  span: `${utcText(big(l.start_ns))} to ${utcText(big(l.end_ns))}`, queue: `${groupDigits(l.queue_records)} records, ${groupDigits(l.queue_bytes)} bytes queued`,
 }));
 return { lines, reports };
}

// ---- links and correlation ---------------------------------------------------------------------------------------
const RELATION_WORD: Record<string, string> = { explicit: 'explicit link', time_overlap_inference: 'inferred from overlap in time; not a causal link' };
export interface LinkLine { key: string; text: string }
/** Links as text only. A link the account may not open reads `not available to this account` and names nothing. Nothing here is fetched or turned into an address. */
export function linkLines(v: ProfileView): LinkLine[] {
 return v.links.map((l: ResolvedReference, i) => {
  if (!l.available || l.reference === undefined) return { key: `${i}`, text: 'A linked item: not available to this account' };
  const r = l.reference;
  return { key: `${i}:${r.id}`, text: `${r.kind} ${r.id} (${RELATION_WORD[r.relation] ?? r.relation}): available` };
 });
}
/** The profile's relation to a request. Only an explicit, available link to a trace is an exact request link; an overlap in time is never attributed to a request. */
export function correlationOf(v: ProfileView): Correlation {
 for (const l of v.links) if (l.available && l.reference !== undefined && l.reference.relation === 'explicit' && l.reference.kind === 'trace') return { kind: 'exact', request: l.reference.id };
 for (const l of v.links) if (l.available && l.reference !== undefined && l.reference.relation === 'time_overlap_inference') return { kind: 'thread_overlap' };
 return { kind: 'none' };
}
export function correlationWords(c: Correlation): string {
 switch (c.kind) {
  case 'exact': return `exact request link: ${c.request}`;
  case 'thread_overlap': return 'overlaps in time on a thread; not attributed to a request';
  case 'none': return 'no request link';
 }
}

// ---- frames ------------------------------------------------------------------------------------------------------------
/** One frame as text. A frame with a reason reads `unresolved frame (<reason>)`; module, function, offset and artifact are text only, never an address. */
export function frameText(f: ProfileFrame): string {
 const parts: string[] = [];
 if (f.reason !== '') {
  parts.push(`unresolved frame (${f.reason})`);
  if (f.function !== '') parts.push(`function ${f.function}`);
 } else parts.push(f.function !== '' ? f.function : 'unnamed function');
 if (f.module_id !== '') parts.push(`module ${f.module_id}`, `offset ${groupDigits(f.offset)}`);
 if (f.artifact_id !== '') parts.push(`artifact ${f.artifact_id}`);
 return parts.join(', ');
}
/** The index of the first frame identical to each frame, so a frame repeated across chunks is one frame. */
function canonicalFrames(v: ProfileView): number[] {
 const first = new Map<string, number>();
 return v.frames.map((f, i) => {
  const k = JSON.stringify([f.module_id, f.function, f.artifact_id, f.offset, f.reason]);
  const known = first.get(k);
  if (known !== undefined) return known;
  first.set(k, i);
  return i;
 });
}

/** Weights of different kinds are kept apart and never added: samples are counts, the others are nanoseconds of different off-CPU kinds. */
export interface Weights { samples: bigint; blocked: bigint; runnable: bigint; unknown: bigint }
const zero = (): Weights => ({ samples: 0n, blocked: 0n, runnable: 0n, unknown: 0n });
function add(into: Weights, w: Weights): void { into.samples += w.samples; into.blocked += w.blocked; into.runnable += w.runnable; into.unknown += w.unknown; }
export interface Present { samples: boolean; blocked: boolean; runnable: boolean; unknown: boolean }
export const presentOf = (v: ProfileView): Present => ({
 samples: v.samples.length > 0, blocked: v.intervals.some((i) => i.kind === 'blocked'), runnable: v.intervals.some((i) => i.kind === 'runnable'), unknown: v.intervals.some((i) => i.kind === 'unknown_offcpu'),
});
interface Obs { stack: number; w: Weights }
function observedWeights(v: ProfileView): Obs[] {
 const out: Obs[] = [];
 for (const s of v.samples) out.push({ stack: s.stack, w: { ...zero(), samples: big(s.count) } });
 for (const i of v.intervals) {
  const d = big(i.end_ns) - big(i.start_ns);
  out.push({ stack: i.stack, w: { ...zero(), ...(i.kind === 'blocked' ? { blocked: d } : i.kind === 'runnable' ? { runnable: d } : { unknown: d }) } });
 }
 return out;
}
function heavier(a: Weights, b: Weights): number {
 for (const k of ['samples', 'blocked', 'runnable', 'unknown'] as const) if (a[k] !== b[k]) return a[k] > b[k] ? -1 : 1;
 return 0;
}

export interface FrameRow { key: string; text: string; stacks: number; w: Weights }
export interface FrameList { rows: FrameRow[]; total: number; present: Present }
/** Every frame with the weight of the observations whose stack contains it (once per stack), heaviest first. Independent of the order a stack is recorded in. */
export function frameList(v: ProfileView, max: number): FrameList {
 const canon = canonicalFrames(v);
 const byFrame = new Map<number, { w: Weights; stacks: Set<number> }>();
 const perStack = new Map<number, number[]>();
 for (const o of observedWeights(v)) {
  let uniq = perStack.get(o.stack);
  if (uniq === undefined) { uniq = [...new Set((v.stacks[o.stack]?.frames ?? []).map((i) => canon[i] ?? i))]; perStack.set(o.stack, uniq); }
  for (const f of uniq) {
   const e = byFrame.get(f) ?? { w: zero(), stacks: new Set<number>() };
   add(e.w, o.w); e.stacks.add(o.stack);
   byFrame.set(f, e);
  }
 }
 const all = [...byFrame.entries()].map(([f, e]): FrameRow & { f: number } => ({ f, key: `${f}`, text: v.frames[f] === undefined ? 'frame missing' : frameText(v.frames[f]), stacks: e.stacks.size, w: e.w }));
 all.sort((a, b) => heavier(a.w, b.w) || a.f - b.f);
 return { rows: all.slice(0, max).map(({ f: _f, ...row }) => row), total: all.length, present: presentOf(v) };
}

export interface FlameRow { key: string; depth: number; text: string; w: Weights }
export interface Flame { rows: FlameRow[]; total: number; present: Present }
interface Node { frame: number; w: Weights; kids: Map<number, Node> }
/** The stacks nested in the order they were recorded: the first recorded frame is the top level. The profile does not say whether that is the outermost or the innermost frame, so no frame is called a caller or a callee. */
export function flame(v: ProfileView, max: number): Flame {
 const canon = canonicalFrames(v);
 const root: Node = { frame: -1, w: zero(), kids: new Map() };
 const empty = zero();
 let emptyStacks = 0;
 for (const o of observedWeights(v)) {
  const refs = v.stacks[o.stack]?.frames ?? [];
  if (refs.length === 0) { add(empty, o.w); emptyStacks += 1; continue; }
  let at = root;
  for (const r of refs) {
   const f = canon[r] ?? r;
   let next = at.kids.get(f);
   if (next === undefined) { next = { frame: f, w: zero(), kids: new Map() }; at.kids.set(f, next); }
   add(next.w, o.w);
   at = next;
  }
 }
 const rows: FlameRow[] = [];
 let total = 0;
 const order = (n: Node): Node[] => [...n.kids.values()].sort((a, b) => heavier(a.w, b.w) || a.frame - b.frame);
 const stack: { node: Node; depth: number }[] = order(root).reverse().map((node) => ({ node, depth: 0 }));
 while (stack.length > 0) {
  const { node, depth } = stack.pop() as { node: Node; depth: number };
  total += 1;
  if (rows.length < max) rows.push({ key: `${total}:${node.frame}`, depth, text: v.frames[node.frame] === undefined ? 'frame missing' : frameText(v.frames[node.frame] as ProfileFrame), w: node.w });
  for (const k of order(node).reverse()) stack.push({ node: k, depth: depth + 1 });
 }
 if (emptyStacks > 0) { total += 1; if (rows.length < max) rows.push({ key: 'empty', depth: 0, text: 'no frames recorded', w: empty }); }
 return { rows, total, present: presentOf(v) };
}

// ---- timeline ----------------------------------------------------------------------------------------------------
export type TimelineKind = 'sample' | 'blocked' | 'runnable' | 'unknown_offcpu' | 'loss' | 'gap';
export interface TimelineRow { key: string; kind: TimelineKind; label: string; offset: string; thread: string; quantity: string; stack: string; notes: string[] }
export interface Timeline { rows: TimelineRow[]; total: number; counts: Record<TimelineKind, number> }
const KIND_RANK: Record<TimelineKind, number> = { sample: 0, blocked: 1, runnable: 2, unknown_offcpu: 3, loss: 4, gap: 5 };
const INTERVAL_LABEL: Record<IntervalKind, string> = { blocked: 'blocked', runnable: 'runnable', unknown_offcpu: 'unknown off-CPU (split unknown)' };

function stackText(v: ProfileView, index: number): string {
 const refs = v.stacks[index]?.frames ?? [];
 const first = refs[0] === undefined ? undefined : v.frames[refs[0]];
 if (first === undefined) return 'no frames recorded';
 return refs.length > 1 ? `${frameText(first)} (first of ${refs.length} frames)` : frameText(first);
}
function sampleQuantity(v: ProfileView, s: ProfileSample): string {
 const n = big(s.count);
 if (s.native !== undefined || v.method === 'native_cpu') return `${groupDigits(n)} OS on-CPU ${n === 1n ? 'sample' : 'samples'}`;
 return v.units === 'nanoseconds' ? `${groupDigits(n)} ns, engine-reported` : `${groupDigits(n)} ${n === 1n ? 'sample' : 'samples'}, engine-reported`;
}
function sampleNotes(s: ProfileSample): string[] {
 const n = s.native;
 if (n === undefined) return [];
 const notes: string[] = [];
 if (n.truncation !== undefined && n.truncation !== '') notes.push(`truncated: ${reasonWords(n.truncation)}`);
 if (n.coverage !== undefined && n.coverage !== '') notes.push(`frame coverage: ${reasonWords(n.coverage)}`);
 if (n.throttle_reason !== undefined && n.throttle_reason !== '') notes.push(`throttle boundary: ${reasonWords(n.throttle_reason)}`);
 return notes;
}

/** Samples, intervals and recorded losses in time order, with the gaps between them stated as gaps. A gap row says that nothing was recorded; it is never filled, and no row is invented for lost time. Times are offsets from the earliest observation on the monotonic clock of the profile's domain. At most `max` rows are returned; `total` is the full count. */
export function timeline(v: ProfileView, max: number): Timeline {
 interface Item { at: bigint; row: TimelineRow }
 const items: Item[] = [];
 const starts: bigint[] = [...v.samples.map((s) => big(s.at_ns)), ...v.intervals.map((i) => big(i.start_ns)), ...(v.native_loss ?? []).map((l) => big(l.at_ns))];
 const base = starts.length === 0 ? 0n : starts.reduce((m, x) => (x < m ? x : m));
 const off = (at: bigint): string => `+${durationText(at - base)}`;

 v.samples.forEach((s, i) => {
  const at = big(s.at_ns);
  items.push({ at, row: { key: `s${i}`, kind: 'sample', label: s.native !== undefined || v.method === 'native_cpu' ? 'OS on-CPU sample' : 'engine sample', offset: off(at), thread: s.thread, quantity: sampleQuantity(v, s), stack: stackText(v, s.stack), notes: sampleNotes(s) } });
 });
 v.intervals.forEach((x, i) => {
  const at = big(x.start_ns);
  const d = big(x.end_ns) - at;
  const notes: string[] = [];
  if (x.censored) notes.push('censored: the end of this wait was not observed, so its duration is not a completed measurement');
  if (x.reason !== undefined && x.reason !== '') notes.push(reasonWords(x.reason));
  if (x.correction === true) notes.push('a correction record, not an observation');
  items.push({ at, row: { key: `i${i}`, kind: x.kind, label: INTERVAL_LABEL[x.kind], offset: off(at), thread: x.thread, quantity: `${durationText(d)} (exactly ${groupDigits(d)} ns)`, stack: stackText(v, x.stack), notes } });
 });
 (v.native_loss ?? []).forEach((l, i) => {
  const at = big(l.at_ns);
  const quantity = l.reason === 'records_lost' || l.reason === 'samples_lost' ? `${groupDigits(l.count)} lost` : l.reason === 'throttled' ? 'sampling throttled' : 'sampling resumed';
  items.push({ at, row: { key: `l${i}`, kind: 'loss', label: `loss: ${l.reason}`, offset: off(at), thread: `cpu ${l.cpu}`, quantity, stack: 'none: nothing was recorded for this time', notes: [reasonWords(l.reason)] } });
 });

 // Gaps, per thread, between what was recorded. Intervals: any space between the end of one and the start of the next. Samples: spacing above three times the median spacing of that thread (needs three samples).
 const byThread = new Map<string, { samples: bigint[]; intervals: { start: bigint; end: bigint }[] }>();
 const slot = (t: string): { samples: bigint[]; intervals: { start: bigint; end: bigint }[] } => {
  let e = byThread.get(t);
  if (e === undefined) { e = { samples: [], intervals: [] }; byThread.set(t, e); }
  return e;
 };
 for (const s of v.samples) slot(s.thread).samples.push(big(s.at_ns));
 for (const i of v.intervals) slot(i.thread).intervals.push({ start: big(i.start_ns), end: big(i.end_ns) });
 const cmp = (a: bigint, b: bigint): number => (a < b ? -1 : a > b ? 1 : 0);
 let g = 0;
 const gap = (thread: string, from: bigint, to: bigint, what: string): void => {
  items.push({ at: from, row: { key: `g${g++}`, kind: 'gap', label: 'gap', offset: off(from), thread, quantity: `${durationText(to - from)} (exactly ${groupDigits(to - from)} ns)`, stack: 'none', notes: [what] } });
 };
 for (const [thread, e] of byThread) {
  e.intervals.sort((a, b) => cmp(a.start, b.start));
  let end: bigint | undefined;
  for (const i of e.intervals) {
   if (end !== undefined && i.start > end) gap(thread, end, i.start, `no interval recorded from ${off(end)} to ${off(i.start)}; the state of the thread in this gap is not stated by this profile, and nothing is filled in`);
   if (end === undefined || i.end > end) end = i.end;
  }
  e.samples.sort(cmp);
  if (e.samples.length >= 3) {
   const spacing = e.samples.slice(1).map((t, k) => t - (e.samples[k] as bigint));
   const median = [...spacing].sort(cmp)[Math.floor(spacing.length / 2)] as bigint;
   if (median > 0n) spacing.forEach((d, k) => { if (d > 3n * median) gap(thread, e.samples[k] as bigint, e.samples[k + 1] as bigint, `no samples recorded from ${off(e.samples[k] as bigint)} to ${off(e.samples[k + 1] as bigint)}; nothing is filled in`); });
  }
 }
 items.sort((a, b) => cmp(a.at, b.at) || KIND_RANK[a.row.kind] - KIND_RANK[b.row.kind] || (a.row.key < b.row.key ? -1 : a.row.key > b.row.key ? 1 : 0));
 const counts: Record<TimelineKind, number> = { sample: 0, blocked: 0, runnable: 0, unknown_offcpu: 0, loss: 0, gap: 0 };
 for (const it of items) counts[it.row.kind] += 1;
 return { rows: items.slice(0, max).map((i) => i.row), total: items.length, counts };
}
