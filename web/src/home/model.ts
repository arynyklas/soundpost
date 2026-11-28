// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// What the home screen ("what is burning now") derives from the real answers. Nothing here invents a figure: a rate is never computed (an incident
// records no denominator), a service whose health is not stated is "not assessed", and an unreadable list is not an empty one.
import type { HealthStatus, IncidentView, JobHealthStatus, JobSummaryView, ServiceHealth, ViewState, VisibleService } from '../api/types';
import type { IssueListItem } from '../api/console';

/** An open incident needs the team's action when nobody has acknowledged its current impact, or a notification about it failed or may not have arrived. A snoozed
 * or in-maintenance incident is already handled. */
export function needsAction(e: IncidentView): boolean {
 if (e.status !== 'open') return false;
 if (e.snooze?.active || e.maintenance?.active) return false;
 const attention = e.notification.delivery.attention;
 const delivery = attention === 'failed' || attention === 'uncertain' || attention === 'held';
 return e.ack === undefined || !e.ack.current || delivery;
}

export type NextStep = 'Acknowledge' | 'Investigate' | 'Resolve';
/** The one thing the person is asked to do about an incident: acknowledge it, open it (acknowledged but its notifications are failing), or resolve it (the source recovered). */
export function nextStep(e: IncidentView): NextStep {
 if (e.status === 'open' && !e.source_firing) return 'Resolve';
 if (e.ack === undefined || !e.ack.current) return e.source_firing && e.severity === 'critical' ? 'Investigate' : 'Acknowledge';
 return 'Investigate';
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, major: 1, minor: 2 };
/** The server orders the queue (open first, then urgency tier, severity, activity). The most urgent incident is the first open one whose source is still firing, else the first open one. */
export function leadIncident(entries: readonly IncidentView[]): IncidentView | undefined {
 const open = entries.filter((e) => e.status === 'open');
 return open.find((e) => e.source_firing) ?? open[0];
}
export function byUrgency(entries: readonly IncidentView[]): IncidentView[] {
 return entries.map((e, i) => ({ e, i })).sort((a, b) => (SEVERITY_RANK[a.e.severity] ?? 3) - (SEVERITY_RANK[b.e.severity] ?? 3) || a.i - b.i).map((x) => x.e);
}

/** The title of an incident when the server states one, else the console's own fallback built from its identifier. */
export function incidentTitle(e: IncidentView & { title?: string }): string {
 const t = typeof e.title === 'string' ? e.title.trim() : '';
 return t !== '' ? t : `Incident ${e.incident_id.slice(0, 8)}`;
}

export type JobTone = 'crit' | 'high' | 'unk' | 'ok';
const JOB_WORDS: Record<JobHealthStatus, { word: string; tone: JobTone; attention: boolean }> = {
 failed: { word: 'Failing', tone: 'crit', attention: true },
 missed: { word: 'Missed', tone: 'crit', attention: true },
 late: { word: 'Late', tone: 'high', attention: true },
 running_too_long: { word: 'Running too long', tone: 'high', attention: true },
 unknown: { word: 'Unknown', tone: 'unk', attention: true },
 cancelled: { word: 'Cancelled', tone: 'unk', attention: false },
 running: { word: 'Running', tone: 'ok', attention: false },
 succeeded: { word: 'Succeeded', tone: 'ok', attention: false },
};
export function jobWords(status: JobHealthStatus): { word: string; tone: JobTone } { const j = JOB_WORDS[status]; return { word: j.word, tone: j.tone }; }
export function jobNeedsAttention(job: JobSummaryView): boolean { return !job.erased && JOB_WORDS[job.health.status].attention; }

export type ServiceHealthWord = HealthStatus | 'not_assessed';
export interface ServiceRow { id: string; project_id: string; status: ServiceHealthWord; openIncidents: number; conditions: number }
const SERVICE_RANK: Record<ServiceHealthWord, number> = { failing: 0, degraded: 1, not_assessed: 2, healthy: 3 };
export function serviceRow(s: VisibleService, health: ServiceHealth | undefined): ServiceRow {
 return { id: s.id, project_id: s.project_id, status: health ? health.status : 'not_assessed', openIncidents: health?.incidents.length ?? 0, conditions: health?.conditions.length ?? 0 };
}
/** Failing first, then degraded, then those whose health is not stated; healthy services are not "not healthy" and are counted instead of listed. */
export function unhealthyServices(rows: readonly ServiceRow[]): { listed: ServiceRow[]; healthy: number } {
 return { listed: rows.filter((r) => r.status !== 'healthy').sort((a, b) => SERVICE_RANK[a.status] - SERVICE_RANK[b.status]), healthy: rows.filter((r) => r.status === 'healthy').length };
}

export type DataHealth = { word: 'Fresh' | 'Partial' | 'Stale' | 'No readable source' | 'Not available'; tone: 'ok' | 'high' | 'unk' | 'warn' };
/** The data health of one project from what the service investigation reports about it: its readable sources and the view's completeness. */
export function dataHealth(sourceCount: number, view: { state: ViewState; freshness?: { completeness: string } | undefined }): DataHealth {
 if (view.state === 'not_available') return { word: 'Not available', tone: 'unk' };
 if (sourceCount === 0) return { word: 'No readable source', tone: 'unk' };
 if (view.state === 'stale') return { word: 'Stale', tone: 'warn' };
 if (view.state === 'incomplete' || (view.freshness !== undefined && view.freshness.completeness !== 'complete')) return { word: 'Partial', tone: 'high' };
 return { word: 'Fresh', tone: 'ok' };
}

export type ChangeWord = 'Regressed' | 'New';
export interface ErrorChange { change: ChangeWord; issue: IssueListItem }
/** The error changes of the window: issues the server lists as regressed, then issues first seen inside the window; an issue in both lists is one row, marked regressed. Newest first. */
export function errorChanges(regressed: readonly IssueListItem[], recent: readonly IssueListItem[], windowStartNs: string, limit: number): ErrorChange[] {
 const seen = new Set<string>();
 const out: ErrorChange[] = [];
 for (const i of regressed) { const k = `${i.project_id}:${i.issue_id}`; if (!seen.has(k)) { seen.add(k); out.push({ change: 'Regressed', issue: i }); } }
 for (const i of recent) {
  const k = `${i.project_id}:${i.issue_id}`;
  if (seen.has(k) || i.firstSeen === null || BigInt(i.firstSeen) < BigInt(windowStartNs)) continue;
  seen.add(k);
  out.push({ change: 'New', issue: i });
 }
 return out.slice(0, limit);
}
