// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The incident list: every figure is computed from the entries the queue answered with, never invented. A number the answer cannot state is
// reported as not stated, never as 0.
import type { Id, IncidentView } from '../api/types';
import { shortId } from '../ui/primitives';

/** The incident's title, or the console's own fallback when none was ever set. */
export function incidentTitle(v: Pick<IncidentView, 'incident_id' | 'title'>): string {
 const t = v.title?.trim() ?? '';
 return t !== '' ? t : `Incident ${shortId(v.incident_id)}`;
}

const windowActive = (v: IncidentView): boolean => v.snooze?.active === true || v.maintenance?.active === true;
const deliveryAttention = (v: IncidentView): string | undefined => (v.notification.delivery.state === 'ready' ? v.notification.delivery.attention : undefined);

/** Open, and nothing currently covers the impact: no current acknowledgement, no snooze and no maintenance window. */
export function isUnacknowledged(v: IncidentView): boolean { return v.status === 'open' && !(v.ack?.current === true) && !windowActive(v); }
/** An acknowledgement exists but a worse impact came after it. */
export function hasOutdatedAck(v: IncidentView): boolean { return v.status === 'open' && v.ack !== undefined && !v.ack.current && !windowActive(v); }
export function hasDeliveryProblem(v: IncidentView): boolean { const a = deliveryAttention(v); return v.status === 'open' && (a === 'failed' || a === 'uncertain'); }

export type StepId = 'acknowledge' | 'delivery' | 'resolve';
export interface Step { id: StepId; label: string }
/** What a person should do next, or null. Acknowledging comes first, then a notification that may not have reached anyone, then closing the response of a recovered source. */
export function nextStep(v: IncidentView): Step | null {
 if (v.status !== 'open') return null;
 if (isUnacknowledged(v)) return { id: 'acknowledge', label: 'Acknowledge' };
 if (hasDeliveryProblem(v)) return { id: 'delivery', label: 'Check delivery' };
 if (v.condition.state === 'recovered' && v.condition.freshness === 'fresh') return { id: 'resolve', label: 'Resolve' };
 return null;
}

export interface DeliveryProblems { failed: number; uncertain: number; /** Open incidents whose delivery state the answer does not state. */ unstated: number }
export interface Summary { open: number; needsAction: number; unacknowledged: number; outdatedAck: number; delivery: DeliveryProblems; loaded: number }

export function summarize(entries: readonly IncidentView[]): Summary {
 const open = entries.filter((v) => v.status === 'open');
 let failed = 0, uncertain = 0, unstated = 0;
 for (const v of open) {
  const a = deliveryAttention(v);
  if (a === 'failed') failed++; else if (a === 'uncertain') uncertain++; else if (v.notification.delivery.state !== 'ready') unstated++;
 }
 return { open: open.length, needsAction: open.filter((v) => nextStep(v) !== null).length, unacknowledged: open.filter(isUnacknowledged).length, outdatedAck: open.filter(hasOutdatedAck).length, delivery: { failed, uncertain, unstated }, loaded: entries.length };
}

export type ChipId = 'all' | 'open' | 'needs' | 'critical' | 'mine' | 'unassigned' | 'delivery' | 'resolved';
export const CHIPS: readonly { id: ChipId; label: string }[] = [
 { id: 'all', label: 'All' }, { id: 'open', label: 'Open' }, { id: 'needs', label: 'Needs action' }, { id: 'critical', label: 'Critical' }, { id: 'mine', label: 'Assigned to me' },
 { id: 'unassigned', label: 'Unassigned' }, { id: 'delivery', label: 'Delivery problems' }, { id: 'resolved', label: 'Resolved' },
];

export function matchesChip(v: IncidentView, chip: ChipId, me: Id | undefined): boolean {
 switch (chip) {
  case 'all': return true;
  case 'open': return v.status === 'open';
  case 'needs': return nextStep(v) !== null;
  case 'critical': return v.status === 'open' && v.severity === 'critical';
  case 'mine': return v.status === 'open' && me !== undefined && v.owner === me;
  case 'unassigned': return v.status === 'open' && v.owner === undefined;
  case 'delivery': return hasDeliveryProblem(v);
  case 'resolved': return v.status === 'resolved';
 }
}
export function chipCounts(entries: readonly IncidentView[], me: Id | undefined): Record<ChipId, number> {
 const out: Record<ChipId, number> = { all: 0, open: 0, needs: 0, critical: 0, mine: 0, unassigned: 0, delivery: 0, resolved: 0 };
 for (const c of CHIPS) out[c.id] = entries.filter((v) => matchesChip(v, c.id, me)).length;
 return out;
}

/** Case-insensitive search over what the row shows: title, incident ID, project and owner (name or ID), severity and status words. */
export function matchesSearch(v: IncidentView, query: string, labels: { project: string; owner: string }): boolean {
 const q = query.trim().toLowerCase();
 if (q === '') return true;
 const hay = [incidentTitle(v), v.incident_id, v.project_id, labels.project, v.owner ?? '', labels.owner, v.severity, v.status === 'open' ? 'open' : 'resolved'];
 return q.split(/\s+/).every((word) => hay.some((h) => h.toLowerCase().includes(word)));
}

/** "4 min ago", "1 h 12 min ago", "3 d ago" for an instant in nanoseconds; a clock ahead of the server is "just now", never a negative time. */
export function agoWords(ns: string, nowMs: number): string {
 const sec = Math.max(0, Math.floor((nowMs - Number(BigInt(ns) / 1_000_000n)) / 1000));
 if (sec < 60) return 'just now';
 const min = Math.floor(sec / 60);
 if (min < 60) return `${min} min ago`;
 const h = Math.floor(min / 60);
 if (h < 24) return min % 60 === 0 ? `${h} h ago` : `${h} h ${min % 60} min ago`;
 return `${Math.floor(h / 24)} d ago`;
}
