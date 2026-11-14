// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The job views are accepted only for the request that was sent and only when their parts agree: a response that does not is a fault
// (ApiFault 200 invalid_response) and is never rendered.
import { afterEach, describe, expect, test } from 'bun:test';
import { getJob, listJobs, parseJobsList, parseJobView } from './client';
import { ApiFault } from './types';

const ORG = 'a'.repeat(32), PROJECT = 'b'.repeat(32), JOB = 'c'.repeat(32), JOB2 = 'd'.repeat(32), RUN = '1'.repeat(32), RUN2 = '2'.repeat(32);
const A1 = '3'.repeat(32), A2 = '4'.repeat(32), A3 = '5'.repeat(32), OBS = '6'.repeat(32), ACTOR = '7'.repeat(32), CMD = '8'.repeat(32), GAP = '9'.repeat(32), GROUP = 'e'.repeat(32), TRACE = 'f'.repeat(32);
const ns = (seconds: number): string => String(BigInt(seconds) * 1_000_000_000n);
const T = 1_730_000_000;
const KEY = 's.1730000000000000000.f0.abcdefgh';
const refused = (fn: () => unknown): void => { expect(fn).toThrow(ApiFault); };
const asRecord = (v: unknown): Record<string, unknown> => v as Record<string, unknown>;

const definition = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ revision: '1', effective_from_ns: ns(T - 86400), schedule: { cron: '0 * * * *', timezone: 'UTC' }, grace_ns: '300000000000', max_runtime_ns: '0', observer_stale_after_ns: '600000000000', overlap: 'allow', ...over });
const observerEvidence = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ observer: OBS, observed_at_ns: ns(T + 3600), complete_through_ns: ns(T + 3600), healthy: true, stale: false, ...over });
const health = (over: Record<string, unknown> = {}, evidence: Record<string, unknown> = {}): Record<string, unknown> => ({
 status: 'failed', as_of_ns: ns(T + 3600), complete: true, reasons: ['attempt_failed'],
 evidence: { occurrence: KEY, run: RUN, attempt: A2, attempt_state: 'failed', attempt_count: 2, definition_revision: '1', observer: observerEvidence(), ...evidence }, ...over,
});
const summary = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ job: JOB, version: '7', erased: false, definition: definition(), health: health(), runs: 1, attempts: 2, ...over });
const listView = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ org: ORG, project: PROJECT, state: 'ready', permission: 'telemetry.read', evaluated_at_ns: ns(T + 3600), jobs: [summary()], more: false, sections: [{ name: 'jobs', state: 'ready' }], ...over });
const listWant = { org: ORG, project: PROJECT, limit: 25 };

describe('a job listing is accepted only for the request that was sent', () => {
 test('the matching page is accepted', () => { expect(parseJobsList(listView(), listWant).jobs).toHaveLength(1); });
 test('another organization or project is a fault', () => {
  for (const other of [{ org: PROJECT }, { project: ORG }]) refused(() => parseJobsList(listView(other), listWant));
 });
 test('an unknown state, another permission or a missing state is a fault', () => {
  for (const other of [{ state: 'healthy' }, { permission: 'raw.read' }, { state: undefined }]) refused(() => parseJobsList(listView(other), listWant));
 });
 test('jobs must be in strictly ascending job ID order and strictly after the cursor', () => {
  refused(() => parseJobsList(listView({ jobs: [summary({ job: JOB2 }), summary({ job: JOB })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary(), summary()] }), listWant));
  refused(() => parseJobsList(listView(), { ...listWant, after: JOB }));
  expect(parseJobsList(listView({ jobs: [summary({ job: JOB2 })] }), { ...listWant, after: JOB }).jobs[0]?.job).toBe(JOB2);
 });
 test('a page larger than the limit asked for, or than the server maximum, is a fault', () => {
  refused(() => parseJobsList(listView({ jobs: [summary(), summary({ job: JOB2 })] }), { ...listWant, limit: 1 }));
  const many = Array.from({ length: 51 }, (_, i) => summary({ job: i.toString(16).padStart(32, '0').replace(/^0/, '1') }));
  refused(() => parseJobsList(listView({ jobs: many }), { ...listWant, limit: 100 }));
 });
 test('more pages exist exactly when a page_limit truncation resumes at the last job', () => {
  const more = { more: true, truncation: { reason: 'page_limit', shown: 1, next: JOB } };
  expect(parseJobsList(listView(more), listWant).truncation?.next).toBe(JOB);
  refused(() => parseJobsList(listView({ more: true }), listWant));
  refused(() => parseJobsList(listView({ ...more, truncation: { reason: 'page_limit', shown: 1, next: JOB2 } }), listWant));
  refused(() => parseJobsList(listView({ ...more, truncation: { reason: 'runs_limit', shown: 1, next: JOB } }), listWant));
  refused(() => parseJobsList(listView({ truncation: { reason: 'page_limit', shown: 1, next: JOB } }), listWant));
 });
 test('ready needs jobs, empty needs none, and not_available is a typed refusal that carries no job', () => {
  refused(() => parseJobsList(listView({ jobs: [] }), listWant));
  expect(parseJobsList(listView({ state: 'empty', reason: 'no_jobs', jobs: [], sections: [{ name: 'jobs', state: 'empty', reason: 'no_jobs' }] }), listWant).state).toBe('empty');
  refused(() => parseJobsList(listView({ state: 'empty', reason: 'no_jobs' }), listWant));
  const unavailable = { state: 'not_available', reason: 'job_service_not_wired', jobs: [], sections: [{ name: 'jobs', state: 'not_available', reason: 'job_service_not_wired' }] };
  expect(parseJobsList(listView(unavailable), listWant).reason).toBe('job_service_not_wired');
  refused(() => parseJobsList(listView({ ...unavailable, reason: 'something_else' }), listWant));
  refused(() => parseJobsList(listView({ ...unavailable, jobs: [summary()] }), listWant));
  refused(() => parseJobsList(listView({ ...unavailable, reason: undefined }), listWant));
 });
 test('versions and counters are canonical decimals and counts never lie about attempts', () => {
  for (const version of ['007', '1e3', ' 7', '-1', '18446744073709551616', 7]) refused(() => parseJobsList(listView({ jobs: [summary({ version })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary({ runs: 3, attempts: 2 })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary({ runs: -1 })] }), listWant));
 });
 test('a job that cannot be scheduled is never late or missed, and a missed job needs external observer evidence', () => {
  const missed = (def: Record<string, unknown>, evidence: Record<string, unknown>): Record<string, unknown> => summary({ definition: def, health: health({ status: 'missed', reasons: ['expected_occurrence_not_started'] }, evidence) });
  expect(parseJobsList(listView({ jobs: [missed(definition(), {})] }), listWant).jobs[0]?.health.status).toBe('missed');
  refused(() => parseJobsList(listView({ jobs: [missed(definition(), { observer: undefined })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [missed(definition({ schedule: undefined }), {})] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary({ health: health({ status: 'late' }, { observer: undefined }) })] }), listWant));
 });
 test('a succeeded verdict with incomplete evidence and an unknown health status are faults', () => {
  refused(() => parseJobsList(listView({ jobs: [summary({ health: health({ status: 'succeeded', complete: false }) })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary({ health: health({ status: 'healthy' }) })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary({ health: health({ reasons: null }) })] }), listWant));
 });
});

// ---- one job ----
const attempt = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: A1, ordinal: '1', started: true, observed_ns: ns(T), terminal: { state: 'failed', at_ns: ns(T + 10) }, effective: 'failed', corrections: [], events_accepted: 2, final: false, after_newer_occurrence: false, ...over });
const run = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 id: RUN, occurrence: { key: KEY, scheduled: true, at_ns: ns(T), fold: 0 }, status: 'failed', recovered: false, first_started_ns: ns(T), final_attempt: A2, attempt_count: 2, failed_attempts: 2, basis_of_health: true, overlaps: [], overlap_count: 0, ...over,
});
const detail = (over: Record<string, unknown> = {}, attempts: Record<string, unknown>[] = [attempt(), attempt({ id: A2, ordinal: '2', observed_ns: ns(T + 60), terminal: { state: 'failed', at_ns: ns(T + 70) }, final: true })]): Record<string, unknown> => ({ ...run(over), attempts });
const jobView = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 org: ORG, project: PROJECT, job: JOB, state: 'ready', permission: 'telemetry.read', evaluated_at_ns: ns(T + 3601), source: { version: '7', cursor: { group: GROUP, index: '4' } }, erased: false, definition: definition(), definition_revisions: 1,
 health: health(), observer: { state: 'fresh', expected_schedule: true, evidence: observerEvidence() }, loss: { intervals: [], total: 0, affects_current_health: false }, total_runs: 1, total_attempts: 2,
 compaction: { runs: '0', through_ns: '0' }, latest_occurrence: KEY, runs: [run()],
 sections: [{ name: 'attempts', state: 'ready' }, { name: 'health', state: 'ready' }, { name: 'observer', state: 'ready' }, { name: 'loss', state: 'ready' }], ...over,
});
const want = { org: ORG, project: PROJECT, job: JOB };
const wantRun = { ...want, run: RUN };

describe('a job view is accepted only for the request that was sent', () => {
 test('the matching view, with and without a run, is accepted', () => {
  expect(parseJobView(jobView(), want).health?.status).toBe('failed');
  expect(parseJobView(jobView({ run: detail() }), wantRun).run?.attempts).toHaveLength(2);
 });
 test('another organization, project or job is a fault', () => {
  for (const other of [{ org: PROJECT }, { project: ORG }, { job: JOB2 }]) refused(() => parseJobView(jobView(other), want));
 });
 test('the run must be the one asked for, and no run may arrive unasked', () => {
  refused(() => parseJobView(jobView({ run: detail({ id: RUN2, basis_of_health: false }) }), wantRun));
  refused(() => parseJobView(jobView(), wantRun));
  refused(() => parseJobView(jobView({ run: detail() }), want));
 });
 test('unknown enums are faults: view state, health status, observer state, run status, attempt state', () => {
  refused(() => parseJobView(jobView({ state: 'fine' }), want));
  refused(() => parseJobView(jobView({ health: health({ status: 'exploded' }) }), want));
  refused(() => parseJobView(jobView({ observer: { state: 'sleeping', expected_schedule: true, evidence: observerEvidence() } }), want));
  refused(() => parseJobView(jobView({ runs: [run({ status: 'done' })] }), want));
  refused(() => parseJobView(jobView({ run: detail({}, [attempt({ effective: 'passed' })]) }), wantRun));
 });
 test('decimal strings must be canonical: leading zeros, exponents, floats, numbers and out-of-range values are faults', () => {
  for (const bad of ['01', '1e18', '1.5', ' 5', '9223372036854775808', 12]) refused(() => parseJobView(jobView({ health: health({ as_of_ns: bad }) }), want));
  for (const bad of ['01', '1e18', '1.5', ' 5', '18446744073709551616', '-1', 12]) refused(() => parseJobView(jobView({ source: { version: bad } }), want));
  refused(() => parseJobView(jobView({ compaction: { runs: '-1', through_ns: '0' } }), want));
  refused(() => parseJobView(jobView({ run: detail({}, [attempt({ ordinal: '01' }), attempt({ id: A2, ordinal: '2', final: true })]) }), wantRun));
  expect(parseJobView(jobView({ health: health({ as_of_ns: '-5' }) }), want).health?.as_of_ns).toBe('-5');
 });
 test('IDs are exactly 32 lowercase hexadecimal characters', () => {
  for (const bad of ['G'.repeat(32), 'A'.repeat(32), 'a'.repeat(31), '<img src=x onerror=1>']) {
   refused(() => parseJobView(jobView({ runs: [run({ id: bad })] }), want));
   refused(() => parseJobView(jobView({ source: { version: '7', cursor: { group: bad, index: '4' } } }), want));
  }
 });
 test('lists are bounded: runs by the limit asked for, overlaps at 8, loss at 64, attempts at 256', () => {
  const runs = Array.from({ length: 26 }, (_, i) => run({ id: `${i.toString(16).padStart(2, '0')}${'9'.repeat(30)}`, basis_of_health: false, final_attempt: A2 }));
  refused(() => parseJobView(jobView({ runs, total_runs: 26 }), want));
  refused(() => parseJobView(jobView({ runs: [run({ overlaps: Array.from({ length: 9 }, (_, i) => `${i}`.repeat(32)), overlap_count: 9 })] }), want));
  const loss = Array.from({ length: 65 }, (_, i) => ({ id: `${i.toString(16).padStart(2, '0')}${'7'.repeat(30)}`, start_ns: ns(1), end_ns: ns(2), reason: 'source_loss' }));
  refused(() => parseJobView(jobView({ loss: { intervals: loss, total: 65, affects_current_health: false, truncation: { reason: 'loss_limit', shown: 65, total: 65 } } }), want));
  const attempts = Array.from({ length: 257 }, (_, i) => attempt({ id: `${i.toString(16).padStart(2, '0')}${'5'.repeat(30)}`, ordinal: String(i + 1), final: i === 256 }));
  refused(() => parseJobView(jobView({ run: detail({ attempt_count: 257 }, attempts), total_attempts: 257 }), wantRun));
 });
 test('a text field beyond its bound, or a reason that is not a code, is a fault', () => {
  refused(() => parseJobView(jobView({ health: health({}, { occurrence: 'x'.repeat(513) }) }), want));
  refused(() => parseJobView(jobView({ health: health({ reasons: ['not a code'] }) }), want));
  refused(() => parseJobView(jobView({ sections: [{ name: 'job', state: 'ready', reason: '<b>' }] }), want));
 });
});

describe('a view whose parts disagree is refused', () => {
 test('ready needs its health and the evidence behind it: a missing health, or an incomplete one, is not ready', () => {
  refused(() => parseJobView(jobView({ health: undefined }), want));
  refused(() => parseJobView(jobView({ observer: undefined }), want));
  refused(() => parseJobView(jobView({ health: health({ complete: false }) }), want));
  refused(() => parseJobView(jobView({ state: 'ready', reason: 'job_evidence_incomplete' }), want));
 });
 test('incomplete evidence is its own state with its own reason', () => {
  const v = parseJobView(jobView({ state: 'incomplete', reason: 'job_evidence_incomplete', health: health({ complete: false }) }), want);
  expect(v.state).toBe('incomplete');
  refused(() => parseJobView(jobView({ state: 'incomplete', reason: 'job_evidence_incomplete' }), want));
 });
 test('erased history is the empty state and only the empty state', () => {
  const erased = { state: 'empty', reason: 'job_history_erased', erased: true, runs: [], total_runs: 0, total_attempts: 0, health: health({}, { run: undefined }) };
  expect(parseJobView(jobView(erased), want).erased).toBe(true);
  refused(() => parseJobView(jobView({ ...erased, erased: false }), want));
  refused(() => parseJobView(jobView({ erased: true }), want));
 });
 test('missed needs the external observer: without observer evidence (state none) it is refused as inconsistent', () => {
  const missed = { status: 'missed', reasons: ['expected_occurrence_not_started', 'occurrence_window_closed_without_run'] };
  expect(parseJobView(jobView({ health: health(missed, { run: undefined }), runs: [run({ basis_of_health: false })] }), want).health?.status).toBe('missed');
  refused(() => parseJobView(jobView({ health: health(missed, { run: undefined, observer: undefined }), observer: { state: 'none', expected_schedule: true }, runs: [run({ basis_of_health: false })] }), want));
  refused(() => parseJobView(jobView({ health: health(missed, { run: undefined }), definition: definition({ schedule: undefined }), observer: { state: 'fresh', expected_schedule: false, evidence: observerEvidence() }, runs: [run({ basis_of_health: false })] }), want));
 });
 test('the observer state is derived from its own evidence and from the health evidence, never invented', () => {
  refused(() => parseJobView(jobView({ observer: { state: 'none', expected_schedule: true, evidence: observerEvidence() } }), want));
  refused(() => parseJobView(jobView({ observer: { state: 'fresh', expected_schedule: true } }), want));
  refused(() => parseJobView(jobView({ observer: { state: 'fresh', expected_schedule: true, evidence: observerEvidence({ stale: true }) } }), want));
  refused(() => parseJobView(jobView({ observer: { state: 'fresh', expected_schedule: false, evidence: observerEvidence() } }), want));
  refused(() => parseJobView(jobView({ observer: { state: 'fresh', expected_schedule: true, evidence: observerEvidence({ observed_at_ns: ns(T + 1) }) } }), want));
  refused(() => parseJobView(jobView({ health: health({}, { observer: observerEvidence({ complete_through_ns: ns(T + 4000) }) }) }), want));
  expect(parseJobView(jobView({ observer: { state: 'unhealthy', expected_schedule: true, evidence: observerEvidence({ healthy: false }) }, health: health({}, { observer: observerEvidence({ healthy: false }) }) }), want).observer?.state).toBe('unhealthy');
 });
 test('loss agrees with the evidence the health rests on, and its truncation says what is missing', () => {
  const interval = { id: GAP, start_ns: ns(T), end_ns: ns(T + 5), reason: 'source_loss' };
  const overlapping = { loss: { intervals: [interval], total: 1, affects_current_health: true }, health: health({ complete: false, status: 'unknown', reasons: ['evidence_gap_overlaps'] }, { gaps: [GAP], run: undefined }), state: 'incomplete', reason: 'job_evidence_incomplete', runs: [run({ basis_of_health: false })] };
  expect(parseJobView(jobView(overlapping), want).loss?.affects_current_health).toBe(true);
  refused(() => parseJobView(jobView({ ...overlapping, loss: { intervals: [interval], total: 1, affects_current_health: false } }), want));
  refused(() => parseJobView(jobView({ loss: { intervals: [interval], total: 1, affects_current_health: true } }), want));
  refused(() => parseJobView(jobView({ loss: { intervals: [{ ...interval, end_ns: interval.start_ns }], total: 1, affects_current_health: false } }), want));
  refused(() => parseJobView(jobView({ loss: { intervals: [interval], total: 3, affects_current_health: false } }), want));
  expect(parseJobView(jobView({ loss: { intervals: [interval], total: 3, affects_current_health: false, truncation: { reason: 'loss_limit', shown: 1, total: 3 } } }), want).loss?.total).toBe(3);
 });
 test('the runs truncation names exactly what is shown and what is not', () => {
  const two = [run(), run({ id: RUN2, basis_of_health: false })];
  expect(parseJobView(jobView({ runs: [run()], total_runs: 2, runs_truncation: { reason: 'runs_limit', shown: 1, total: 2 } }), { ...want, runsLimit: 1 }).runs_truncation?.total).toBe(2);
  refused(() => parseJobView(jobView({ runs: [run()], total_runs: 2 }), want));
  refused(() => parseJobView(jobView({ runs: two, total_runs: 2, runs_truncation: { reason: 'runs_limit', shown: 2, total: 2 } }), want));
  refused(() => parseJobView(jobView({ runs: [run()], total_runs: 5, runs_truncation: { reason: 'runs_limit', shown: 1, total: 4 } }), { ...want, runsLimit: 1 }));
  refused(() => parseJobView(jobView({ runs: two, total_runs: 2 }), { ...want, runsLimit: 1 }));
 });
 test('a run is the basis of health exactly when the health evidence names it; superseded names the newest occurrence', () => {
  refused(() => parseJobView(jobView({ runs: [run({ basis_of_health: false })] }), want));
  refused(() => parseJobView(jobView({ runs: [run({ id: RUN2, basis_of_health: true })] }), want));
  refused(() => parseJobView(jobView({ runs: [run({ superseded_by: 's.other.f0.abcdefgh', basis_of_health: false }), run({ id: RUN2 })] }), want));
  expect(parseJobView(jobView({ health: health({}, { run: RUN2 }), runs: [run({ basis_of_health: false, superseded_by: KEY, occurrence: { key: 's.older.f0.abcdefgh', scheduled: true, at_ns: ns(T - 3600), fold: 0 } }), run({ id: RUN2 })], total_runs: 2, total_attempts: 4 }), want).runs).toHaveLength(2);
 });
 test('overlaps list exactly min(count, 8) other runs, never the run itself', () => {
  expect(parseJobView(jobView({ runs: [run({ overlaps: [RUN2], overlap_count: 1 }), run({ id: RUN2, basis_of_health: false })], total_runs: 2 }), want).runs[0]?.overlap_count).toBe(1);
  refused(() => parseJobView(jobView({ runs: [run({ overlaps: [], overlap_count: 2 })] }), want));
  refused(() => parseJobView(jobView({ runs: [run({ overlaps: [RUN], overlap_count: 1 })] }), want));
  refused(() => parseJobView(jobView({ runs: [run({ overlaps: [RUN2, RUN2], overlap_count: 2 })] }), want));
 });
 test('not_available carries no job at all and is never an empty or ready job', () => {
  const unavailable = { state: 'not_available', reason: 'job_store_not_readable', erased: false, runs: [], total_runs: 0, total_attempts: 0, definition_revisions: 0, sections: [{ name: 'job', state: 'not_available', reason: 'job_store_not_readable' }], source: undefined, definition: undefined, health: undefined, observer: undefined, loss: undefined, compaction: undefined, latest_occurrence: undefined };
  expect(parseJobView(jobView(unavailable), want).reason).toBe('job_store_not_readable');
  expect(parseJobView(jobView(unavailable), wantRun).health).toBeUndefined();
  refused(() => parseJobView(jobView({ ...unavailable, health: health() }), want));
  refused(() => parseJobView(jobView({ ...unavailable, runs: [run()], total_runs: 1, total_attempts: 2 }), want));
  refused(() => parseJobView(jobView({ ...unavailable, reason: 'no_jobs' }), want));
  refused(() => parseJobView(jobView({ ...unavailable, state: 'empty', reason: 'job_history_erased' }), want));
 });
});

describe('attempts: the original result stays and a cancelled attempt is never a success', () => {
 const correction = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ version: '1', state: 'succeeded', reason: 'the data owner confirmed the output', actor: ACTOR, at_ns: ns(T + 500), command: CMD, ...over });
 const withAttempts = (attempts: Record<string, unknown>[], over: Record<string, unknown> = {}): Record<string, unknown> => jobView({ run: detail(over, attempts), runs: [run(over)] });
 const last = (over: Record<string, unknown> = {}): Record<string, unknown> => attempt({ id: A2, ordinal: '2', observed_ns: ns(T + 60), terminal: { state: 'failed', at_ns: ns(T + 70) }, final: true, ...over });
 test('a corrected attempt keeps its original terminal result and takes the correction as its effective result', () => {
  const corrected = last({ corrections: [correction()], effective: 'succeeded' });
  const v = parseJobView(withAttempts([attempt(), corrected], { status: 'recovered', recovered: true, failed_attempts: 1, basis_of_health: true }), wantRun);
  expect(v.run?.attempts[1]?.terminal?.state).toBe('failed');
  expect(v.run?.attempts[1]?.effective).toBe('succeeded');
 });
 test('an effective result that is not the newest correction (or the terminal result without one) is refused', () => {
  refused(() => parseJobView(withAttempts([attempt(), last({ corrections: [correction()] })]), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last({ effective: 'succeeded' })]), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last({ corrections: [correction(), correction({ version: '2', state: 'cancelled' })], effective: 'succeeded' })]), wantRun));
 });
 test('cancelled is cancelled: a cancelled attempt reading succeeded without a correction is refused, a real cancellation is accepted', () => {
  refused(() => parseJobView(withAttempts([attempt({ terminal: { state: 'cancelled', at_ns: ns(T + 10) }, effective: 'succeeded' }), last()]), wantRun));
  const cancelled = last({ terminal: { state: 'cancelled', at_ns: ns(T + 70) }, effective: 'cancelled' });
  const v = parseJobView(withAttempts([attempt(), cancelled], { status: 'cancelled', failed_attempts: 1, basis_of_health: true }), wantRun);
  expect(v.run?.attempts[1]?.effective).toBe('cancelled');
 });
 test('corrections need a terminal attempt and strictly increasing versions', () => {
  refused(() => parseJobView(withAttempts([attempt(), last({ terminal: undefined, corrections: [correction()], effective: 'succeeded' })], { status: 'recovered', recovered: true, failed_attempts: 1 }), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last({ corrections: [correction({ version: '2' }), correction({ version: '2', state: 'failed' })], effective: 'failed' })]), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last({ corrections: [correction({ state: 'started' })], effective: 'started' })]), wantRun));
 });
 test('a started attempt has no terminal result and the run is running', () => {
  const started = last({ terminal: undefined, effective: 'started' });
  expect(parseJobView(withAttempts([attempt(), started], { status: 'running', failed_attempts: 1 }), wantRun).run?.status).toBe('running');
  refused(() => parseJobView(withAttempts([attempt(), started], { status: 'failed', failed_attempts: 1 }), wantRun));
 });
 test('recovered needs a failed earlier attempt and a succeeded final one; the flag and the status agree', () => {
  const ok = last({ terminal: { state: 'succeeded', at_ns: ns(T + 70) }, effective: 'succeeded' });
  const recovered = { status: 'recovered', recovered: true, failed_attempts: 1 };
  expect(parseJobView(withAttempts([attempt(), ok], recovered), wantRun).run?.recovered).toBe(true);
  refused(() => parseJobView(withAttempts([attempt({ terminal: { state: 'succeeded', at_ns: ns(T + 10) }, effective: 'succeeded' }), ok], { ...recovered, failed_attempts: 0 }), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), ok], { ...recovered, recovered: false }), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), ok], { status: 'succeeded', recovered: true, failed_attempts: 1 }), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), ok], { status: 'succeeded', failed_attempts: 1 }), wantRun)); // a failed attempt in the history cannot read as an ordinary success
 });
 test('the failed-attempt count, the attempt count and the final marker must match the attempts that are listed', () => {
  refused(() => parseJobView(withAttempts([attempt(), last()], { failed_attempts: 1 }), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last()], { attempt_count: 3 }), wantRun));
  refused(() => parseJobView(withAttempts([attempt({ final: true }), last({ final: false })]), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last({ id: A3 })]), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), attempt({ id: A1, final: true })]), wantRun));
  refused(() => parseJobView(withAttempts([last({ ordinal: '3' }), attempt({ ordinal: '2' })]), wantRun));
 });
 test('a late result needs a terminal result; causes are IDs only', () => {
  refused(() => parseJobView(withAttempts([attempt({ terminal: undefined, effective: 'started', after_newer_occurrence: true }), last()], { failed_attempts: 1 }), wantRun));
  expect(parseJobView(withAttempts([attempt({ cause_trace: TRACE, cause_error: ACTOR }), last()]), wantRun).run?.attempts[0]?.cause_trace).toBe(TRACE);
  refused(() => parseJobView(withAttempts([attempt({ cause_trace: '<img src=x>' }), last()]), wantRun));
 });
 test('a correction reason is bounded text, an actor an ID', () => {
  refused(() => parseJobView(withAttempts([attempt(), last({ corrections: [correction({ reason: 'x'.repeat(1025) })], effective: 'succeeded' })], { status: 'recovered', recovered: true, failed_attempts: 1 }), wantRun));
  refused(() => parseJobView(withAttempts([attempt(), last({ corrections: [correction({ actor: 'someone' })], effective: 'succeeded' })], { status: 'recovered', recovered: true, failed_attempts: 1 }), wantRun));
 });
 test('the listed summary of the selected run and its detail agree', () => {
  refused(() => parseJobView(jobView({ run: detail(), runs: [run({ failed_attempts: 1 })] }), wantRun));
  expect(parseJobView(jobView({ run: detail() }), wantRun).run?.id).toBe(RUN);
 });
});

describe('the client sends only the selectors and refuses a response for anything else', () => {
 const real = globalThis.fetch;
 afterEach(() => { globalThis.fetch = real; });
 const serve = (answer: unknown, status = 200): { bodies: unknown[]; paths: string[] } => {
  const seen = { bodies: [] as unknown[], paths: [] as string[] };
  globalThis.fetch = (async (path: string | URL | Request, init?: RequestInit) => {
   seen.paths.push(String(path));
   seen.bodies.push(JSON.parse(String(init?.body ?? 'null')) as unknown);
   return new Response(JSON.stringify(answer), { status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
  return seen;
 };
 const signal = new AbortController().signal;
 test('listJobs sends org, project and limit, and the cursor only when there is one', async () => {
  const first = serve(listView());
  await listJobs(ORG, PROJECT, '', 25, signal);
  expect(first.paths).toEqual(['/api/v1/jobs/list']);
  expect(first.bodies).toEqual([{ org: ORG, project: PROJECT, limit: 25 }]);
  const next = serve(listView({ jobs: [summary({ job: JOB2 })] }));
  await listJobs(ORG, PROJECT, JOB, 25, signal);
  expect(next.bodies).toEqual([{ org: ORG, project: PROJECT, after: JOB, limit: 25 }]);
 });
 test('getJob sends the run and the run limit only when asked, and refuses a view of another job', async () => {
  const plain = serve(jobView());
  await getJob(ORG, PROJECT, JOB, {}, signal);
  expect(plain.paths).toEqual(['/api/v1/jobs/view']);
  expect(plain.bodies).toEqual([{ org: ORG, project: PROJECT, job: JOB }]);
  const asked = serve(jobView({ run: detail() }));
  await getJob(ORG, PROJECT, JOB, { run: RUN, runsLimit: 50 }, signal);
  expect(asked.bodies).toEqual([{ org: ORG, project: PROJECT, job: JOB, run: RUN, runs_limit: 50 }]);
  serve(jobView({ job: JOB2 }));
  let fault: unknown;
  await getJob(ORG, PROJECT, JOB, {}, signal).catch((e: unknown) => { fault = e; });
  expect(fault).toBeInstanceOf(ApiFault);
  expect(asRecord(fault).code).toBe('invalid_response');
  expect(asRecord(fault).status).toBe(200);
 });
 test('a typed refusal of the server is a fault with its status, not a view', async () => {
  serve({ code: 'not_found' }, 404);
  let fault: unknown;
  await getJob(ORG, PROJECT, JOB, { run: RUN }, signal).catch((e: unknown) => { fault = e; });
  expect(fault).toBeInstanceOf(ApiFault);
  expect(asRecord(fault).status).toBe(404);
 });
});

describe('a job with only attempt evidence has no definition', () => {
 const attemptOnly = { definition: undefined, definition_revisions: 0, observer: { state: 'none', expected_schedule: false }, health: health({ status: 'unknown', complete: false, reasons: ['no_evidence'] }, { observer: undefined, definition_revision: undefined, run: undefined }), state: 'incomplete', reason: 'job_evidence_incomplete' };
 test('the list accepts an item without a definition, and a present one stays strict', () => {
  const item = summary({ definition: undefined, health: health({}, { observer: undefined }) });
  expect(parseJobsList(listView({ jobs: [item] }), listWant).jobs[0]?.definition).toBeUndefined();
  refused(() => parseJobsList(listView({ jobs: [summary({ definition: definition({ revision: '0' }) })] }), listWant));
  refused(() => parseJobsList(listView({ jobs: [summary({ definition: undefined, health: health({ status: 'missed' }) })] }), listWant));
 });
 test('the view accepts absence only with zero revisions, no calendar schedule and no observer expectation', () => {
  expect(parseJobView(jobView({ ...attemptOnly, runs: [run({ basis_of_health: false })] }), want).definition).toBeUndefined();
  refused(() => parseJobView(jobView({ ...attemptOnly, definition_revisions: 1, runs: [run({ basis_of_health: false })] }), want));
  refused(() => parseJobView(jobView({ ...attemptOnly, observer: { state: 'none', expected_schedule: true }, runs: [run({ basis_of_health: false })] }), want));
  refused(() => parseJobView(jobView({ definition: definition({ revision: '0' }) }), want));
  refused(() => parseJobView(jobView({ definition: undefined }), want));
 });
});
