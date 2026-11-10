// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { JobDefinition, JobHealthStatus, JobSummaryView } from '../api/types';
import {
 CANCELLED_NOTE, JOBS_PAGE_LIMIT, MISSED_RULE_TEXT, appendJobs, attemptHeadline, attemptWord, chooseProject, compactionText, completenessWord, correctionText, cursorText, dedupText, definitionLines, durationText, expectedText, finalOrdinal, foldText,
 graceText, healthBasisText, healthLine, healthReasonText, healthWord, jobReasonText, jobsShownText, lossIntervalText, lossOverlapText, lossReasonText, nextRunsLimit, observerExplanation, observerLine, originalResultText, overlapPolicyText,
 overlapText, readChange, runRecoveryText, runStatusWord, runsShownText, scheduledText, skippedText, sourceVersionText, supersededText,
} from './model';

const at = (ns: string): string => `T(${ns})`;
const STATUSES: JobHealthStatus[] = ['succeeded', 'failed', 'cancelled', 'running', 'running_too_long', 'late', 'missed', 'unknown'];

describe('current health in words', () => {
 test('every status reads as its own word, and no two statuses read alike', () => {
  const words = STATUSES.map(healthWord);
  expect(words).toEqual(['Succeeded', 'Failed', 'Cancelled', 'Running', 'Running too long', 'Late', 'Missed (external schedule observer evidence)', 'Unknown']);
  expect(new Set(words).size).toBe(STATUSES.length);
 });
 test('missed always names its only source, and cancelled and unknown are never worded as success', () => {
  expect(healthWord('missed')).toContain('external schedule observer evidence');
  expect(healthWord('cancelled')).not.toMatch(/succe/i);
  expect(healthWord('unknown')).not.toMatch(/succe|healthy|ok/i);
  expect(attemptWord('cancelled')).toBe('Cancelled');
 });
 test('the health line and the completeness are separate statements', () => {
  expect(healthLine('failed')).toBe('Current job health: Failed');
  expect(completenessWord(true)).toBe('Complete');
  expect(completenessWord(false)).toBe('Incomplete evidence');
 });
 test('every reason code the server can write has its own plain sentence, never the bare code', () => {
  const codes = [
   'no_evidence', 'attempt_succeeded', 'attempt_failed', 'attempt_cancelled', 'run_recovered_after_retry', 'retry_in_progress', 'attempt_running', 'running_beyond_max_runtime', 'attempt_result_corrected', 'expected_occurrence_not_started',
   'occurrence_window_closed_without_run', 'no_schedule_observer', 'schedule_observer_stale', 'schedule_observer_unhealthy', 'no_clock_evidence', 'evidence_gap_overlaps', 'evidence_of_absence_incomplete', 'nonexistent_local_time_skipped',
  ];
  const generic = healthReasonText('a_code_from_the_future');
  const sentences = codes.map(healthReasonText);
  for (const [i, s] of sentences.entries()) {
   expect(s).not.toBe(generic);
   expect(s).not.toContain(codes[i] ?? '');
   expect(s.endsWith('.')).toBe(true);
  }
  expect(new Set(sentences).size).toBe(codes.length);
 });
 test('a code this page does not know reads as a generic sentence that does not echo the code, including names of object prototype members', () => {
  const generic = healthReasonText('a_code_from_the_future');
  expect(generic).not.toContain('a_code_from_the_future');
  expect(generic).toContain('does not recognise');
  for (const odd of ['constructor', '__proto__', 'toString', '<img src=x>']) expect(healthReasonText(odd)).toBe(generic);
  expect(jobReasonText('toString')).toBe(jobReasonText('zzz'));
 });
 test('not_available reasons say that this is not an empty job list; erasure is not "never ran"', () => {
  for (const code of ['job_service_not_wired', 'job_store_not_readable']) expect(jobReasonText(code)).toContain('not an empty job list');
  expect(jobReasonText('job_service_not_wired')).toContain('no job service');
  expect(jobReasonText('job_store_not_readable')).toContain('cannot be read');
  expect(jobReasonText('job_history_erased')).toContain('not a job that never ran');
 });
});

describe('run recovery is worded apart from current job health', () => {
 const run = { status: 'recovered' as const, recovered: true, attempt_count: 2, failed_attempts: 1 };
 test('a recovered run says how it recovered', () => {
  expect(runRecoveryText(run)).toBe('Run recovery: Recovered after retry (attempt 2 succeeded after 1 failed)');
  expect(runRecoveryText({ ...run, attempt_count: 4, failed_attempts: 3 }, '4')).toBe('Run recovery: Recovered after retry (attempt 4 succeeded after 3 failed)');
 });
 test('a run that did not recover never reads as recovered, and every variant is a "Run recovery" sentence, never a health sentence', () => {
  const variants = [
   runRecoveryText({ status: 'failed', recovered: false, attempt_count: 2, failed_attempts: 2 }),
   runRecoveryText({ status: 'cancelled', recovered: false, attempt_count: 2, failed_attempts: 1 }),
   runRecoveryText({ status: 'running', recovered: false, attempt_count: 1, failed_attempts: 0 }),
   runRecoveryText({ status: 'succeeded', recovered: false, attempt_count: 1, failed_attempts: 0 }),
  ];
  for (const v of variants) {
   expect(v.startsWith('Run recovery: ')).toBe(true);
   expect(v).not.toContain('Recovered after retry');
   expect(v).not.toContain('Current job health');
  }
  expect(variants[0]).toContain('not recovered');
  expect(variants[1]).toContain('not recovered');
  expect(variants[1]).toContain('not a success');
  expect(variants[2]).toContain('n/a');
 });
 test('a run can have recovered while the job is currently failed: the two sentences differ and neither mentions the other', () => {
  const recovery = runRecoveryText(run);
  const basis = healthBasisText('failed', false);
  expect(basis).toBe('Current job health: Failed. This run is not the basis of that health.');
  expect(recovery).not.toContain('Failed');
  expect(basis).not.toContain('Recovered');
 });
 test('the basis sentence says whether this run is what the health rests on', () => {
  expect(healthBasisText('succeeded', true)).toBe('Current job health: Succeeded. This run is the basis of that health.');
  expect(healthBasisText('missed', false)).toContain('not the basis');
 });
 test('run statuses are words; recovered says it happened after a retry', () => {
  expect(runStatusWord('recovered')).toBe('Recovered after retry');
  expect(runStatusWord('cancelled')).toBe('Cancelled');
  expect(runStatusWord('running')).toBe('Running');
 });
 test('the final ordinal is the one of the attempt marked final', () => {
  const a = (ordinal: string, final: boolean) => ({ ordinal, final }) as Parameters<typeof finalOrdinal>[0][number];
  expect(finalOrdinal([a('1', false), a('3', true)])).toBe('3');
  expect(finalOrdinal([])).toBeUndefined();
 });
});

describe('supersession, lateness, overlap and daylight saving', () => {
 test('a superseded run says its result is history and did not change current health', () => {
  expect(supersededText('s.1.f0.abc')).toBe("Superseded by newer occurrence s.1.f0.abc: this run's result is history and did not change current job health");
 });
 test('overlap counts other runs in the singular and the plural, and says when the list is shorter than the count', () => {
  expect(overlapText({ overlap_count: 0, overlaps: [] })).toBe('No other run overlaps this run');
  expect(overlapText({ overlap_count: 1, overlaps: ['a'.repeat(32)] })).toBe('Overlaps with 1 other run');
  expect(overlapText({ overlap_count: 3, overlaps: ['a', 'b', 'c'] })).toBe('Overlaps with 3 other runs');
  expect(overlapText({ overlap_count: 12, overlaps: Array.from({ length: 8 }, () => 'a') })).toBe('Overlaps with 12 other runs (the first 8 are listed)');
 });
 test('only fold 1 is the repeated local time, and it is a separate expected run', () => {
  expect(foldText({ fold: 0 })).toBeNull();
  expect(foldText({ fold: 1 })).toBe('Second occurrence of a repeated local time (the clock moved back); it is a separate expected run');
 });
 test('a skipped local time names the zone and says no run was expected', () => {
  expect(skippedText('2026-03-08T02:30', 'America/New_York')).toBe('Skipped: local time 2026-03-08T02:30 does not exist in America/New_York (clock moved forward); no run was expected then');
 });
 test('a manual execution has no scheduled instant and says so; a scheduled one shows its instant', () => {
  expect(scheduledText({ key: 'manual.a', scheduled: false, fold: 0 }, at)).toContain('Not scheduled');
  expect(scheduledText({ key: 's.1', scheduled: true, at_ns: '1730000000000000000', fold: 0 }, at)).toBe('Scheduled for T(1730000000000000000)');
 });
});

describe('attempt wording keeps the original result', () => {
 test('the headline is the effective result; the original is a separate line that survives a correction', () => {
  const attempt = { ordinal: '2', effective: 'succeeded' as const, terminal: { state: 'failed' as const, at_ns: '5' } };
  expect(attemptHeadline(attempt)).toBe('Attempt 2: Succeeded');
  expect(originalResultText(attempt, at)).toBe('Original result: Failed at T(5)');
 });
 test('a started attempt has no result yet, and an attempt without a terminal result has no original result', () => {
  expect(attemptHeadline({ ordinal: '3', effective: 'started' })).toBe('Attempt 3: Started (no result yet)');
  expect(originalResultText({}, at)).toContain('none yet');
 });
 test('a correction names its version, actor, time and reason, and its state in words', () => {
  const actor = '7'.repeat(32);
  expect(correctionText({ state: 'succeeded', version: '2', actor, at_ns: '9', reason: 'verified by the data owner' }, at)).toBe(`Corrected to Succeeded (correction version 2 by ${actor} at T(9)): verified by the data owner`);
  expect(correctionText({ state: 'cancelled', version: '1', actor, at_ns: '9', reason: 'r' }, at)).toContain('Corrected to Cancelled');
 });
 test('cancelled is explained as not a success', () => { expect(CANCELLED_NOTE).toContain('not a success'); });
 test('the deduplication line states distinct attempts, accepted events and that redelivered events are neither counted nor retained', () => {
  expect(dedupText(3, 5)).toBe('3 distinct attempts counted; 5 events accepted. Redelivered events with the same producer epoch and sequence are not counted again and are not retained.');
 });
});

describe('observer and loss wording', () => {
 test('the observer line is exactly the state, and the explanation matches it', () => {
  for (const s of ['none', 'fresh', 'stale', 'unhealthy'] as const) expect(observerLine(s)).toBe(`Schedule observer: ${s}`);
  expect(observerExplanation('none', true)).toContain('missed run cannot be established');
  expect(observerExplanation('stale', true)).toContain('unknown rather than last observed');
  expect(observerExplanation('unhealthy', true)).toContain('not conclusive');
  expect(observerExplanation('none', false)).toContain('no calendar schedule');
  expect(observerExplanation('fresh', false)).toContain('never be missed');
 });
 test('missed is only ever from observer evidence and absence of records reads unknown', () => {
  expect(MISSED_RULE_TEXT).toContain('only from external schedule observer evidence');
  expect(MISSED_RULE_TEXT).toContain('Unknown');
  expect(MISSED_RULE_TEXT).toContain('never shown as recovered or missed by assumption');
 });
 test('loss reasons are in words; a reason this page does not know is stated as a code, not hidden', () => {
  expect(lossReasonText('source_loss')).toContain('source loss');
  expect(lossReasonText('exporter_connectivity')).toContain('connection');
  expect(lossReasonText('weird')).toBe('a recorded loss with the code weird');
  expect(lossIntervalText({ start_ns: '1', end_ns: '2', reason: 'observer_outage' }, at)).toBe('T(1) to T(2): an outage of the schedule observer');
 });
 test('whether loss overlaps current health is a sentence either way', () => {
  expect(lossOverlapText(true)).toContain('overlaps the evidence the current job health rests on');
  expect(lossOverlapText(false)).toContain('No loss interval overlaps');
 });
 test('expected occurrence text appears only for late and missed evidence', () => {
  const h = (evidence: Record<string, string>) => ({ evidence }) as Parameters<typeof expectedText>[0];
  expect(expectedText(h({}), at)).toBeNull();
  expect(expectedText(h({ expected_at_ns: '10', window_end_ns: '20' }), at)).toBe('Expected occurrence at T(10); its window closed at T(20)');
  expect(expectedText(h({ expected_at_ns: '10' }), at)).toBe('Expected occurrence at T(10)');
 });
});

describe('definition wording uses exact arithmetic', () => {
 test('durations are spelled out without rounding; zero is the server default or none', () => {
  expect(durationText('300000000000')).toBe('5 minutes');
  expect(durationText('3600000000000')).toBe('1 hour');
  expect(durationText('90000000000')).toBe('1 minute 30 seconds');
  expect(durationText('1500000')).toBe('1500000 ns');
  expect(durationText('2000000')).toBe('2 ms');
  expect(durationText('0')).toBe('0 seconds');
  expect(graceText('0')).toBe('5 minutes (default)');
  expect(graceText('600000000000')).toBe('10 minutes');
 });
 test('the largest int64 duration keeps every digit (it is not routed through a JavaScript number)', () => {
  expect(durationText('9223372036854775807')).toBe('106751 days 23 hours 47 minutes 16 seconds 854775807 ns');
 });
 test('a scheduled definition lists zone, cron, grace, runtime, observer stale-after, policy and revisions', () => {
  const d: JobDefinition = { revision: '3', effective_from_ns: '10', schedule: { cron: '0 * * * *', timezone: 'Europe/Berlin' }, grace_ns: '0', max_runtime_ns: '3600000000000', observer_stale_after_ns: '0', overlap: 'allow' };
  expect(definitionLines(d, 3, at)).toEqual([
   'Time zone: Europe/Berlin', 'Schedule: 0 * * * *', 'Grace: 5 minutes (default)', 'Maximum runtime: 1 hour', 'Observer stale after: 10 minutes (default)',
   'Overlap policy: allow: a run that starts while another runs is recorded, never dropped or merged', '3 definition revisions (current revision 3, effective from T(10))',
  ]);
 });
 test('a job without a schedule says it can never be missed; an unknown overlap policy is shown as is; a single revision is singular', () => {
  const d: JobDefinition = { revision: '1', effective_from_ns: '10', grace_ns: '300000000000', max_runtime_ns: '0', observer_stale_after_ns: '600000000000', overlap: 'skip' };
  const lines = definitionLines(d, 1, at);
  expect(lines).toContain('Schedule: No calendar schedule (this job can fail or succeed but can never be missed)');
  expect(lines).toContain('Maximum runtime: none set');
  expect(lines).toContain('Overlap policy: skip');
  expect(lines.at(-1)).toBe('1 definition revision (current revision 1, effective from T(10))');
  expect(overlapPolicyText('allow')).toContain('never dropped or merged');
 });
});

describe('source, runs and paging', () => {
 test('source version and origin cursor, or the absence of a cursor, are stated', () => {
  expect(sourceVersionText('7')).toBe('Committed source version 7');
  expect(cursorText({ group: 'g'.repeat(32), index: '12' })).toBe(`Origin cursor of the newest attempt evidence: ${'g'.repeat(32)}:12`);
  expect(cursorText(undefined)).toBe('Origin cursor: no attempt evidence cursor');
 });
 test('the runs limit steps 25, 50, 100 and then stops; without a truncation there is nothing more to ask for', () => {
  const t = { reason: 'runs_limit' as const, shown: 25, total: 90 };
  expect(nextRunsLimit(25, t)).toBe(50);
  expect(nextRunsLimit(50, t)).toBe(100);
  expect(nextRunsLimit(100, t)).toBeNull();
  expect(nextRunsLimit(25, undefined)).toBeNull();
  expect(runsShownText(25, 90)).toBe('Showing 25 of 90 runs');
 });
 test('compaction is stated only when runs were compacted, with exact counts even beyond 2^53', () => {
  expect(compactionText('0')).toBeNull();
  expect(compactionText('1')).toBe('1 older run was compacted out of this view; the journal keeps the full history');
  expect(compactionText('9007199254740993')).toBe('9007199254740993 older runs were compacted out of this view; the journal keeps the full history');
 });
 const job = (id: string, over: Partial<JobSummaryView> = {}): JobSummaryView => ({ job: id, version: '1', erased: false, runs: 1, attempts: 1, ...over }) as JobSummaryView;
 test('appending a page never lists a job twice and keeps the order', () => {
  const shown = [job('a'), job('b')];
  expect(appendJobs(shown, [job('b'), job('c'), job('a'), job('d')]).map((j) => j.job)).toEqual(['a', 'b', 'c', 'd']);
  expect(appendJobs(shown, []).map((j) => j.job)).toEqual(['a', 'b']);
  expect(shown).toHaveLength(2);
 });
 test('the project shown is the one chosen while the scope still holds it, else the first of the scope', () => {
  expect(chooseProject('p2', ['p1', 'p2'])).toBe('p2');
  expect(chooseProject('gone', ['p1', 'p2'])).toBe('p1');
  expect(chooseProject('', ['p1'])).toBe('p1');
  expect(chooseProject('x', [])).toBe('');
 });
 test('the job count says whether more follow', () => {
  expect(jobsShownText(25, true)).toContain('More jobs exist');
  expect(jobsShownText(3, false)).toBe('Showing 3 jobs. No more jobs follow.');
  expect(JOBS_PAGE_LIMIT).toBe(25);
 });
});

describe('what a change of context means for a held read', () => {
 const was = { key: 'org|p|job', generation: 4 };
 test('the ordinary Refresh (same target, new generation) re-reads in place; nothing changed means nothing to do', () => {
  expect(readChange(was, { key: 'org|p|job', generation: 5 })).toBe('refresh');
  expect(readChange(was, { key: 'org|p|job', generation: 4 })).toBe('none');
 });
 test('another scope, project, job or run is a new target and is never also a refresh, even when the generation moved too', () => {
  for (const key of ['org2|p|job', 'org|p2|job', 'org|p|job2', 'org|p|job|run']) {
   expect(readChange(was, { key, generation: 5 })).toBe('new-target');
   expect(readChange(was, { key, generation: 4 })).toBe('new-target');
  }
 });
});

describe('a job without a definition', () => {
 test('reads as exactly one sentence: attempt evidence only, never missed', () => {
  expect(definitionLines(undefined, 0, at)).toEqual(['No job definition has been reported: this job has only attempt evidence, so it has no calendar schedule (it can fail or succeed but can never be missed) and no grace, maximum runtime or overlap policy is configured.']);
 });
});
