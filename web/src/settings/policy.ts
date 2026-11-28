// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { ApiFault, OutcomeUnknown } from '../api/types';
import type { DestinationChange, Id, NotificationChange, NotificationPolicyView, RetentionView } from '../api/types';

/** The pure half of the project settings pages: drafts are text, builders turn them into the wire change or say why not.
 * Nothing here talks to the server, and nothing here is shown as committed. */
export type Built<T> = { ok: true; value: T } | { ok: false; error: string };

export const RETENTION_SIGNALS: readonly { id: string; label: string }[] = [
 { id: 'metrics', label: 'Metrics' }, { id: 'logs', label: 'Logs' }, { id: 'traces', label: 'Traces' }, { id: 'errors', label: 'Errors, conditions and job attempts' },
 { id: 'replay', label: 'Replays' }, { id: 'profiles', label: 'Profiles' }, { id: 'audit', label: 'Audit records' },
];
export const MAX_RETENTION_DAYS = 3650;
export const MAX_SUPPRESSION_SECONDS = 90 * 24 * 3600;
const SECOND_NS = 1_000_000_000n;

export const REASON_MAX_BYTES = 512;
export function validReason(reason: string): boolean {
 const bytes = new TextEncoder().encode(reason).length;
 return bytes >= 1 && bytes <= REASON_MAX_BYTES && !/\p{Cc}/u.test(reason);
}

/** Exact decimal seconds of a nanosecond count (no floating point): "900", "0.5". */
export function secondsText(ns: string): string {
 const v = BigInt(ns);
 const whole = v / SECOND_NS, rest = v % SECOND_NS;
 return rest === 0n ? whole.toString() : `${whole}.${rest.toString().padStart(9, '0').replace(/0+$/, '')}`;
}
/** Exact nanoseconds of a non-negative decimal amount of seconds, or null when it is not one (a sign, an exponent, more places than a nanosecond). */
export function secondsToNs(text: string): string | null {
 const m = /^(0|[1-9][0-9]{0,9})(?:\.([0-9]{1,9}))?$/.exec(text.trim());
 if (!m) return null;
 const ns = BigInt(m[1] ?? '0') * SECOND_NS + BigInt((m[2] ?? '').padEnd(9, '0') || '0');
 return ns > 9223372036854775807n ? null : ns.toString();
}
/** A duration in the largest whole units that state it exactly: "15 minutes", "7 days", "1 hour 30 minutes", else seconds. */
export function durationWords(ns: string): string {
 const v = BigInt(ns);
 if (v === 0n || v % SECOND_NS !== 0n) return `${secondsText(ns)} seconds`;
 let s = v / SECOND_NS;
 const parts: string[] = [];
 for (const [unit, size] of [['day', 86400n], ['hour', 3600n], ['minute', 60n], ['second', 1n]] as const) {
  const n = s / size;
  if (n > 0n) { parts.push(`${n} ${unit}${n === 1n ? '' : 's'}`); s -= n * size; }
 }
 return parts.join(' ');
}

/** Basis points as percent text with at most two places: 500 -> "5", 725 -> "7.25". */
export function basisPointsText(bp: number): string {
 const whole = Math.floor(bp / 100), rest = bp % 100;
 return rest === 0 ? String(whole) : `${whole}.${String(rest).padStart(2, '0').replace(/0+$/, '')}`;
}
export function percentToBasisPoints(text: string): number | null {
 const m = /^(0|[1-9][0-9]{0,2})(?:\.([0-9]{1,2}))?$/.exec(text.trim());
 if (!m) return null;
 const bp = Number(m[1]) * 100 + Number((m[2] ?? '').padEnd(2, '0') || '0');
 return bp >= 1 && bp <= 10000 ? bp : null;
}

const CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
const MAX_CODES = 32;

/** The notification policy as the form holds it. */
export interface NotificationDraft {
 minOperations: string; minFailures: string; ratePercent: string; regressionMin: string;
 criticalCodes: string; firstReminderSeconds: string; reminderEverySeconds: string; maxSuppressionSeconds: string; defaultZone: string;
}
export function notificationDraft(p: NotificationPolicyView): NotificationDraft {
 return {
  minOperations: String(p.min_operations), minFailures: String(p.min_failures), ratePercent: basisPointsText(p.rate_basis_points), regressionMin: String(p.regression_min),
  criticalCodes: p.critical_codes.join(', '), firstReminderSeconds: secondsText(p.first_reminder_ns), reminderEverySeconds: secondsText(p.reminder_every_ns), maxSuppressionSeconds: secondsText(p.max_suppression_ns), defaultZone: p.default_zone,
 };
}
const positiveInt = (text: string): number | null => { const t = text.trim(); return /^[1-9][0-9]{0,8}$/.test(t) ? Number(t) : null; };

function validZone(tz: string): boolean {
 if (tz === '') return true;
 if (tz.length > 64) return false;
 try { new Intl.DateTimeFormat('en', { timeZone: tz }); return true; } catch { return false; }
}

/** Builds the whole-policy change; the first problem found is the message. The server validates again: this only spares a round trip. */
export function buildNotification(d: NotificationDraft): Built<NotificationChange> {
 const ops = positiveInt(d.minOperations), failures = positiveInt(d.minFailures), regression = positiveInt(d.regressionMin);
 if (ops === null) return { ok: false, error: 'Minimum operations must be a whole number of at least 1.' };
 if (failures === null) return { ok: false, error: 'Minimum failures must be a whole number of at least 1.' };
 const rate = percentToBasisPoints(d.ratePercent);
 if (rate === null) return { ok: false, error: 'Failure rate must be a percentage above 0 and at most 100, with at most two decimal places.' };
 if (regression === null) return { ok: false, error: 'Regression minimum must be a whole number of at least 1.' };
 const codes = [...new Set(d.criticalCodes.split(/[\s,]+/).filter((c) => c !== ''))].sort();
 if (codes.length > MAX_CODES || !codes.every((c) => CODE.test(c))) return { ok: false, error: `Critical codes are up to ${MAX_CODES} names of letters, digits and _ . : - (each at most 64 characters), separated by commas.` };
 const first = secondsToNs(d.firstReminderSeconds), every = secondsToNs(d.reminderEverySeconds), most = secondsToNs(d.maxSuppressionSeconds);
 if (first === null || first === '0') return { ok: false, error: 'First reminder must be a positive number of seconds.' };
 if (every === null || every === '0') return { ok: false, error: 'Reminder interval must be a positive number of seconds.' };
 if (most === null || most === '0' || BigInt(most) > BigInt(MAX_SUPPRESSION_SECONDS) * SECOND_NS) return { ok: false, error: `Longest snooze or maintenance window must be a positive number of seconds, at most ${MAX_SUPPRESSION_SECONDS} (90 days).` };
 const zone = d.defaultZone.trim();
 if (!validZone(zone)) return { ok: false, error: 'Digest time zone must be empty (UTC) or a valid IANA name such as Europe/Berlin.' };
 return { ok: true, value: { min_operations: ops, min_failures: failures, rate_basis_points: rate, regression_min: regression, critical_codes: codes, first_reminder_ns: first, reminder_every_ns: every, max_suppression_ns: most, default_zone: zone } };
}

/** Whether a draft differs from the policy the server holds. An invalid draft counts as changed so its error is shown. */
export function notificationChanged(d: NotificationDraft, p: NotificationPolicyView): boolean {
 const built = buildNotification(d);
 if (!built.ok) return true;
 const v = built.value;
 return v.min_operations !== p.min_operations || v.min_failures !== p.min_failures || v.rate_basis_points !== p.rate_basis_points || v.regression_min !== p.regression_min
  || v.critical_codes.join('\n') !== [...p.critical_codes].sort().join('\n') || v.first_reminder_ns !== p.first_reminder_ns || v.reminder_every_ns !== p.reminder_every_ns || v.max_suppression_ns !== p.max_suppression_ns || v.default_zone !== p.default_zone;
}

export function buildRetention(signal: string, days: string): Built<RetentionView> {
 if (!RETENTION_SIGNALS.some((s) => s.id === signal)) return { ok: false, error: 'Choose one of the listed signals.' };
 const n = positiveInt(days);
 if (n === null || n > MAX_RETENTION_DAYS) return { ok: false, error: `Retention must be a whole number of days from 1 to ${MAX_RETENTION_DAYS}.` };
 return { ok: true, value: { signal, days: n } };
}

export const DESTINATION_TYPES: readonly { id: string; label: string }[] = [{ id: 'webhook', label: 'Webhook' }, { id: 'smtp', label: 'Email (SMTP)' }, { id: 'telegram', label: 'Telegram' }];
export interface DestinationDraft { id: Id; type: string; endpoint: string; address: string; enabled: boolean; secret: string }

/** An https endpoint with no credentials, query or fragment: a token belongs in the write-only secret, never in the URL. */
export function validEndpoint(endpoint: string): boolean {
 try {
  const u = new URL(endpoint);
  return u.protocol === 'https:' && u.hostname !== '' && u.username === '' && u.password === '' && u.search === '' && u.hash === '' && !endpoint.includes('?') && !endpoint.includes('#');
 } catch { return false; }
}
export function buildDestination(d: DestinationDraft): Built<DestinationChange> {
 if (!DESTINATION_TYPES.some((t) => t.id === d.type)) return { ok: false, error: 'Choose a destination type.' };
 const endpoint = d.endpoint.trim(), address = d.address.trim();
 if (d.type === 'webhook' && !validEndpoint(endpoint)) return { ok: false, error: 'A webhook needs an https endpoint without credentials, query or fragment. Put a token in the secret field, not in the address.' };
 if (d.type === 'smtp' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) return { ok: false, error: 'An email destination needs a recipient address.' };
 if (d.type === 'telegram' && endpoint !== '' && !validEndpoint(endpoint)) return { ok: false, error: 'A Telegram endpoint, when given, must be an https address without credentials, query or fragment.' };
 if (d.secret.length > 4096) return { ok: false, error: 'The secret is too long.' };
 return { ok: true, value: { id: d.id, type: d.type, enabled: d.enabled, ...(d.type === 'smtp' ? { address } : endpoint !== '' ? { endpoint } : {}), ...(d.secret !== '' ? { secret: d.secret } : {}) } };
}

export type FailureKind = 'conflict' | 'forbidden' | 'not_found' | 'invalid' | 'signed_out' | 'unknown_outcome' | 'rate_limited' | 'failed';
/** What a refused or unconfirmed write means for the person, in words. Every kind but unknown_outcome says nothing was changed. */
export function describeWriteFailure(error: unknown): { kind: FailureKind; text: string } {
 if (error instanceof OutcomeUnknown) return { kind: 'unknown_outcome', text: 'The request left this browser but its outcome is unknown. It may or may not have been applied. Save again to resend the same command: the server applies a command once and returns the original result.' };
 if (error instanceof ApiFault) {
  switch (error.status) {
   case 409: return { kind: 'conflict', text: 'The settings changed after this page read them, so nothing was changed. The current settings are shown below; review them and apply your change again.' };
   case 403: return { kind: 'forbidden', text: 'This change needs a sign-in within the last five minutes and an account allowed to make it. Nothing was changed. Sign in again, then retry.' };
   case 404: return { kind: 'not_found', text: 'This project or setting was not found or is not available to this account. Nothing was changed.' };
   case 400: return { kind: 'invalid', text: `The server refused these values${error.detail && error.detail !== error.code ? ` (${error.detail.replace(/_/g, ' ')})` : ''}. Nothing was changed.` };
   case 401: return { kind: 'signed_out', text: 'Your session has ended. Sign in again. Nothing was changed.' };
   case 429: return { kind: 'rate_limited', text: 'Too many requests. Wait and retry. Nothing was changed.' };
  }
 }
 return { kind: 'failed', text: 'The change could not be confirmed. Nothing is shown as saved; reload to see the current settings.' };
}

export interface UrgencyStep { id: 'urgent' | 'reminders' | 'suppression' | 'digest'; title: string; text: string; badge: string }
/** The notification policy the server holds, told as the steps a person reads. Every number is the committed one; nothing the policy contract does not carry (routes, escalation, windows) is stated. */
export function urgencySteps(p: NotificationPolicyView): UrgencyStep[] {
 const codes = p.critical_codes.length === 0 ? 'no critical operation code is set' : `critical codes ${p.critical_codes.join(', ')}`;
 return [
  { id: 'urgent', title: 'What is urgent', text: `A change is urgent when a critical code occurs (${codes}), a regression reaches ${p.regression_min} occurrence${p.regression_min === 1 ? '' : 's'}, or the window has at least ${p.min_operations} operations and ${p.min_failures} failures at a failure rate of at least ${basisPointsText(p.rate_basis_points)}%.`, badge: p.source === 'default' ? 'default policy' : `own policy, revision ${p.revision}` },
  { id: 'reminders', title: 'Reminders', text: `The first reminder comes after ${durationWords(p.first_reminder_ns)}, then one every ${durationWords(p.reminder_every_ns)}.`, badge: `${durationWords(p.first_reminder_ns)} · ${durationWords(p.reminder_every_ns)}` },
  { id: 'suppression', title: 'Snooze and maintenance', text: `A snooze or a maintenance window lasts at most ${durationWords(p.max_suppression_ns)}.`, badge: `at most ${durationWords(p.max_suppression_ns)}` },
  { id: 'digest', title: 'Digest', text: `Digests are cut in the time zone ${p.default_zone === '' ? 'UTC' : p.default_zone}.`, badge: p.default_zone === '' ? 'UTC' : p.default_zone },
 ];
}
