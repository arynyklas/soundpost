// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IssueListItem } from '../api/console';
import type { IncidentView, JobSummaryView, VisibleService } from '../api/types';
import { byUrgency, dataHealth, errorChanges, incidentTitle, jobNeedsAttention, jobWords, leadIncident, needsAction, nextStep, serviceRow, unhealthyServices } from './model';

const A = 'a'.repeat(32), P = '1'.repeat(32);
const incident = (over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: 'b'.repeat(32), org: A, project_id: P, version: '3', status: 'open', condition: { id: 'c'.repeat(32), state: 'firing', freshness: 'fresh', observed_at: '1' }, episode_id: 'd'.repeat(32),
 severity: 'major', impact_revision: '1', source_firing: true, notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'ready' }, delivery: { state: 'ready', attention: 'none' }, digest: { state: 'ready', sent: 0 }, unread_change: { state: 'ready', changed: false, queue_revision: '1', seen_revision: '1' } },
 links: [], observed_impacts: 2, last_activity: '1', ...over,
});

describe('incident triage on the home screen', () => {
 test('an unacknowledged open incident needs action; an acknowledged one does not, unless a delivery failed or may not have arrived', () => {
  expect(needsAction(incident())).toBe(true);
  const ack = { actor: A, at: '1', impact_revision: '1', version: '2', current: true };
  expect(needsAction(incident({ ack }))).toBe(false);
  for (const attention of ['failed', 'uncertain', 'held'] as const) expect(needsAction(incident({ ack, notification: { ...incident().notification, delivery: { state: 'ready', attention } } }))).toBe(true);
  expect(needsAction(incident({ ack: { ...ack, current: false } }))).toBe(true);
 });
 test('a resolved, snoozed or in-maintenance incident is already handled', () => {
  expect(needsAction(incident({ status: 'resolved' }))).toBe(false);
  expect(needsAction(incident({ snooze: { actor: A, reason: 'r', from: '1', until: '2', version: '2', active: true } }))).toBe(false);
  expect(needsAction(incident({ maintenance: { actor: A, reason: 'r', from: '1', until: '2', version: '2', active: true } }))).toBe(false);
 });
 test('the next step: resolve once the source recovered, investigate a critical firing one, else acknowledge', () => {
  expect(nextStep(incident({ source_firing: false }))).toBe('Resolve');
  expect(nextStep(incident({ severity: 'critical' }))).toBe('Investigate');
  expect(nextStep(incident())).toBe('Acknowledge');
 });
 test('the lead incident is the first open one that is still firing; a resolved one is never lead', () => {
  const resolved = incident({ incident_id: '1'.repeat(32), status: 'resolved' });
  const recovered = incident({ incident_id: '2'.repeat(32), source_firing: false });
  const firing = incident({ incident_id: '3'.repeat(32) });
  expect(leadIncident([resolved, recovered, firing])?.incident_id).toBe('3'.repeat(32));
  expect(leadIncident([resolved, recovered])?.incident_id).toBe('2'.repeat(32));
  expect(leadIncident([resolved])).toBeUndefined();
 });
 test('urgency order keeps the server order inside one severity', () => {
  const a = incident({ incident_id: '1'.repeat(32), severity: 'minor' }), b = incident({ incident_id: '2'.repeat(32), severity: 'critical' }), c = incident({ incident_id: '3'.repeat(32), severity: 'critical' });
  expect(byUrgency([a, b, c]).map((e) => e.incident_id[0])).toEqual(['2', '3', '1']);
 });
 test('the title is the stated one, else a fallback from the identifier, never empty', () => {
  expect(incidentTitle({ ...incident(), title: ' Checkout slow ' })).toBe('Checkout slow');
  expect(incidentTitle({ ...incident(), title: '' })).toBe(`Incident ${'b'.repeat(8)}`);
  expect(incidentTitle(incident())).toBe(`Incident ${'b'.repeat(8)}`);
 });
});

describe('jobs, services and data health are worded, never zero', () => {
 const job = (status: JobSummaryView['health']['status'], erased = false): JobSummaryView => ({ job: A, version: '1', erased, health: { status, as_of_ns: '1', complete: true, reasons: [], evidence: {} }, runs: 1, attempts: 1 });
 test('failing, missed, late, too long and unknown jobs need attention; succeeded, running and cancelled do not; an erased job is not listed', () => {
  for (const s of ['failed', 'missed', 'late', 'running_too_long', 'unknown'] as const) expect(jobNeedsAttention(job(s))).toBe(true);
  for (const s of ['succeeded', 'running', 'cancelled'] as const) expect(jobNeedsAttention(job(s))).toBe(false);
  expect(jobNeedsAttention(job('failed', true))).toBe(false);
  expect(jobWords('unknown')).toEqual({ word: 'Unknown', tone: 'unk' });
 });
 test('a service whose health is not stated is not assessed; healthy ones are counted, not listed', () => {
  const svc = (id: string): VisibleService => ({ id, project_id: P, sources: [], environments: [], builds: [], dependencies: [] });
  const rows = [
   serviceRow(svc('1'), { status: 'healthy', incidents: [], conditions: [] }),
   serviceRow(svc('2'), undefined),
   serviceRow(svc('3'), { status: 'failing', incidents: [{ project_id: P, incident_id: A, severity: 'critical', version: '1' }], conditions: [] }),
   serviceRow(svc('4'), { status: 'degraded', incidents: [], conditions: [{ project_id: P, condition_id: A, phase: 'firing', severity: 'major', freshness: 'fresh' }] }),
  ];
  const r = unhealthyServices(rows);
  expect(r.listed.map((x) => x.status)).toEqual(['failing', 'degraded', 'not_assessed']);
  expect(r.healthy).toBe(1);
  expect(rows[2]?.openIncidents).toBe(1);
 });
 test('data health: no readable source and not available are their own words, partial and stale are not fresh', () => {
  expect(dataHealth(0, { state: 'ready' }).word).toBe('No readable source');
  expect(dataHealth(2, { state: 'not_available' }).word).toBe('Not available');
  expect(dataHealth(2, { state: 'stale' }).word).toBe('Stale');
  expect(dataHealth(2, { state: 'incomplete' }).word).toBe('Partial');
  expect(dataHealth(2, { state: 'ready', freshness: { completeness: 'partial' } }).word).toBe('Partial');
  expect(dataHealth(2, { state: 'ready', freshness: { completeness: 'complete' } }).word).toBe('Fresh');
 });
});

describe('error changes', () => {
 const issue = (id: string, firstSeen: string | null): IssueListItem => ({ project_id: P, issue_id: id.repeat(32), workflow: 'open', revision: '1', title: null, titleState: 'not_available', firstSeen, lastSeen: firstSeen, occurrences: null, compacted: false, releases: [] });
 test('regressed first, then issues first seen inside the window; an issue in both is one regressed row; an unknown first-seen is not new', () => {
  const out = errorChanges([issue('1', '5')], [issue('1', '5'), issue('2', '20'), issue('3', '1'), issue('4', null)], '10', 10);
  expect(out.map((c) => [c.change, c.issue.issue_id[0]])).toEqual([['Regressed', '1'], ['New', '2']]);
  expect(errorChanges([], [issue('2', '20'), issue('5', '30')], '10', 1)).toHaveLength(1);
 });
});
