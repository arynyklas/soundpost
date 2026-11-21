// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the job views. Job, run and attempt IDs, occurrence keys, reasons and correction text are untrusted:
// they must reach the page only as escaped text, and every state must be a sentence, not only a class.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { JobSummaryView, JobView } from '../api/types';
import type { ViewContext } from '../app/context';
import { JobDetail, JobTable, JobsPage } from './JobsPage';
import { ReasonNotes, RunDetailView, RunPage, timeIn } from './RunPage';

const ORG = 'a'.repeat(32), P1 = 'b'.repeat(32), P2 = 'c'.repeat(32), JOB = 'd'.repeat(32), RUN = '1'.repeat(32), RUN2 = '2'.repeat(32), RUN3 = '3'.repeat(32);
const A1 = '4'.repeat(32), A2 = '5'.repeat(32), A3 = '6'.repeat(32), OBS = '7'.repeat(32), ACTOR = '8'.repeat(32), GAP = '9'.repeat(32), G = 'e'.repeat(32), TRACE = 'f'.repeat(32), ERR = '0'.repeat(32);
const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const render = (el: React.ReactElement): string => renderToStaticMarkup(el);
const text = (html: string): string => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
const block = (html: string, testid: string): string => text(new RegExp(`<div data-testid="${testid}"[^>]*>(.*?)</div>`, 's').exec(html)?.[1] ?? '');
const noElementsFromText = (html: string): void => {
 expect(html).not.toMatch(/<img/i);
 expect(html).not.toMatch(/<script/i);
 expect(html).not.toMatch(/<[a-z][^>"']*\sonerror\s*=/i);
 expect(html).toContain('&lt;img src=x onerror=');
 expect(html).not.toMatch(/\sstyle=/i);
};
const ns = (s: number): string => String(BigInt(1_730_000_000 + s) * 1_000_000_000n);
const context: ViewContext = { org: ORG, projects: [P1, P2], environment: '', start: ns(0), end: ns(3600), timezone: 'UTC', generation: 0 };

const definition = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ revision: '3', effective_from_ns: ns(-86400), schedule: { cron: '0 * * * *', timezone: 'Europe/Berlin' }, grace_ns: '0', max_runtime_ns: '3600000000000', observer_stale_after_ns: '600000000000', overlap: 'allow', ...over });
const observerEvidence = { observer: OBS, observed_at_ns: ns(3600), complete_through_ns: ns(3500), healthy: true, stale: false };
const health = (over: Record<string, unknown> = {}, evidence: Record<string, unknown> = {}): Record<string, unknown> => ({
 status: 'failed', as_of_ns: ns(3600), complete: true, reasons: ['attempt_failed', 'attempt_result_corrected'], evidence: { occurrence: 's.new', run: RUN, observer: observerEvidence, ...evidence }, ...over,
});
const runView = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 id: RUN, occurrence: { key: 's.new', scheduled: true, at_ns: ns(0), fold: 0 }, status: 'failed', recovered: false, first_started_ns: ns(5), final_attempt: A2, attempt_count: 2, failed_attempts: 2, basis_of_health: true, overlaps: [], overlap_count: 0, ...over,
});
const jobView = (over: Record<string, unknown> = {}): JobView => ({
 org: ORG, project: P1, job: JOB, state: 'ready', permission: 'telemetry.read', source: { version: '7', cursor: { group: G, index: '4' } }, erased: false, definition: definition(), definition_revisions: 3, health: health(),
 observer: { state: 'fresh', expected_schedule: true, evidence: observerEvidence }, loss: { intervals: [], total: 0, affects_current_health: false }, total_runs: 1, total_attempts: 2, compaction: { runs: '0', through_ns: '0' },
 latest_occurrence: 's.new', runs: [runView()], sections: [{ name: 'job', state: 'ready' }], ...over,
}) as unknown as JobView;
const summary = (status: string, over: Record<string, unknown> = {}): JobSummaryView => ({ job: JOB, version: '1', erased: false, definition: definition(), health: health({ status }), runs: 3, attempts: 5, ...over }) as unknown as JobSummaryView;
const detailProps = { timezone: 'UTC', selectedRun: '' as const, runsLimit: 25, openRun: () => undefined, moreRuns: () => undefined };
const detail = (view: JobView, over: Partial<Parameters<typeof JobDetail>[0]> = {}): string => render(React.createElement(JobDetail, { ...detailProps, view, ...over }));

describe('the job list shows every health in words', () => {
 test('each status is a word in its row, next to the Open button for that job', () => {
  const statuses: [string, string][] = [['succeeded', 'Succeeded'], ['failed', 'Failed'], ['cancelled', 'Cancelled'], ['running', 'Running'], ['running_too_long', 'Running too long'], ['late', 'Late'], ['missed', 'Missed (external schedule observer evidence)'], ['unknown', 'Unknown']];
  for (const [status, word] of statuses) {
   const html = render(React.createElement(JobTable, { jobs: [summary(status)], selected: '', open: () => undefined }));
   expect(html).toContain(`<td>${word}</td>`);
   expect(html).toContain('data-testid="job-row"');
   expect(html).toContain(`data-job="${JOB}"`);
   expect(html).toContain(`Open job ${JOB}`);
   expect(html).toContain('<table class="data-table" aria-label="Jobs">');
  }
 });
 test('completeness, erasure, counts and the selected row are stated', () => {
  const html = render(React.createElement(JobTable, { jobs: [summary('unknown', { health: health({ status: 'unknown', complete: false }), erased: true }), summary('succeeded', { job: JOB.replace(/d/g, 'e') })], selected: JOB, open: () => undefined }));
  expect(html).toContain('Incomplete evidence. History erased');
  expect(html).toContain('<td>Complete</td>');
  expect(html).toContain('<td>3</td><td>5</td>');
  expect(html).toContain('data-selected="yes"');
  expect(html).toContain('data-selected="no"');
  expect(html).toContain('aria-pressed="true"');
  expect(html).toContain('scope="col"');
  expect(html).toContain('<caption>');
 });
});

describe('the job panel states health, definition, observer, loss, source and runs separately', () => {
 test('current health is a sentence with its reasons in plain words and the completeness of its evidence', () => {
  const html = detail(jobView());
  expect(block(html, 'job-health')).toContain('Current job health: Failed');
  expect(block(html, 'job-health')).toContain('Evidence: Complete');
  expect(block(html, 'job-health')).toContain('The newest attempt of the newest occurrence failed.');
  expect(block(html, 'job-health')).toContain('An authorized person corrected the result of the newest attempt');
  expect(block(html, 'job-health')).not.toContain('attempt_failed');
  expect(block(html, 'job-health')).toContain('Current health rests on run');
 });
 test('an unknown reason code is a generic sentence, never the bare code', () => {
  const html = detail(jobView({ health: health({ reasons: ['reason_from_the_future'] }) }));
  expect(block(html, 'job-health')).toContain('does not recognise');
  expect(html).not.toContain('reason_from_the_future</li>');
 });
 test('the definition lists zone, schedule, grace (zero = default), runtime, stale-after, overlap and revisions', () => {
  const lines = block(detail(jobView()), 'job-definition');
  for (const line of ['Time zone: Europe/Berlin', 'Schedule: 0 * * * *', 'Grace: 5 minutes (default)', 'Maximum runtime: 1 hour', 'Observer stale after: 10 minutes', 'allow: a run that starts while another runs is recorded, never dropped or merged', '3 definition revisions']) expect(lines).toContain(line);
 });
 test('a job without a calendar schedule says it can never be missed and shows any other overlap policy as is', () => {
  const lines = block(detail(jobView({ definition: definition({ schedule: undefined, max_runtime_ns: '0', overlap: 'queue' }), observer: { state: 'none', expected_schedule: false }, health: health({}, { observer: undefined }) })), 'job-definition');
  expect(lines).toContain('No calendar schedule (this job can fail or succeed but can never be missed)');
  expect(lines).toContain('Maximum runtime: none set');
  expect(lines).toContain('Overlap policy: queue');
 });
 test('the observer: state in words, its times, and the rule that missed needs external evidence', () => {
  const fresh = block(detail(jobView()), 'job-observer');
  expect(fresh).toContain('Schedule observer: fresh');
  expect(fresh).toMatch(/Observer observed at 27 Oct 2024/);
  expect(fresh).toMatch(/Observer complete through 27 Oct 2024/);
  expect(fresh).toContain('only from external schedule observer evidence');
  expect(fresh).toContain('never shown as recovered or missed by assumption');
  const none = block(detail(jobView({ observer: { state: 'none', expected_schedule: true }, health: health({ status: 'unknown', complete: false, reasons: ['no_schedule_observer'] }, { observer: undefined, run: undefined }), runs: [runView({ basis_of_health: false })] })), 'job-observer');
  expect(none).toContain('Schedule observer: none');
  expect(none).toContain('a missed run cannot be established');
  expect(none).not.toContain('Observer observed at');
  for (const state of ['stale', 'unhealthy']) expect(block(detail(jobView({ observer: { state, expected_schedule: true, evidence: { ...observerEvidence, stale: state === 'stale', healthy: state !== 'unhealthy' } } })), 'job-observer')).toContain(`Schedule observer: ${state}`);
 });
 test('loss is reported separately from the outcome, with its interval in words and whether it overlaps the health', () => {
  const html = detail(jobView({
   loss: { intervals: [{ id: GAP, start_ns: ns(10), end_ns: ns(20), reason: 'exporter_connectivity' }, { id: RUN3, start_ns: ns(30), end_ns: ns(40), reason: 'source_loss' }], total: 70, affects_current_health: true, truncation: { reason: 'loss_limit', shown: 2, total: 70 } },
   health: health({}, { gaps: [GAP] }),
  }));
  const loss = block(html, 'job-loss');
  expect(loss).toContain('Loss is reported separately from the job outcome.');
  expect(loss).toContain('the exporter lost its connection (overlaps the evidence current health rests on)');
  expect(loss).toContain('source loss (telemetry from the producer did not arrive)');
  expect(loss).toContain('Showing 2 of 70 loss intervals');
  expect(loss).toContain('A loss interval overlaps the evidence the current job health rests on');
  expect(block(detail(jobView()), 'job-loss')).toContain('No producer or evidence loss is recorded for this job.');
  expect(block(detail(jobView()), 'job-loss')).toContain('No loss interval overlaps');
 });
 test('the committed source version and origin cursor persist, or the absence of a cursor is said', () => {
  expect(block(detail(jobView()), 'job-source')).toBe(`Committed source version 7 Origin cursor of the newest attempt evidence: ${G}:4`);
  expect(block(detail(jobView({ source: { version: '9' } })), 'job-source')).toBe('Committed source version 9 Origin cursor: no attempt evidence cursor');
 });
 test('daylight saving: skipped local times are sentences that name the zone', () => {
  const html = detail(jobView({ health: health({}, { skipped_local_times: ['2026-03-08T02:30'] }) }));
  expect(html).toContain('Skipped: local time 2026-03-08T02:30 does not exist in Europe/Berlin (clock moved forward); no run was expected then');
  expect(detail(jobView())).not.toContain('Skipped:');
 });
 test('missed shows the expected occurrence and the window that closed', () => {
  const html = detail(jobView({ health: health({ status: 'missed', reasons: ['expected_occurrence_not_started', 'occurrence_window_closed_without_run'] }, { run: undefined, expected_at_ns: ns(0), window_end_ns: ns(3600) }), runs: [runView({ basis_of_health: false })] }));
  expect(block(html, 'job-health')).toContain('Current job health: Missed (external schedule observer evidence)');
  expect(block(html, 'job-health')).toMatch(/Expected occurrence at 27 Oct 2024.*its window closed at/);
 });
});

describe('runs: recovery, basis of health, supersession, overlap and daylight saving each have their own sentence', () => {
 const runs = [
  runView(),
  runView({ id: RUN2, occurrence: { key: 's.old', scheduled: true, at_ns: ns(-3600), fold: 1 }, status: 'recovered', recovered: true, attempt_count: 2, failed_attempts: 1, basis_of_health: false, superseded_by: 's.new', overlaps: [RUN3], overlap_count: 2 }),
  runView({ id: RUN3, occurrence: { key: 'manual.1', scheduled: false, fold: 0 }, status: 'cancelled', attempt_count: 1, failed_attempts: 0, basis_of_health: false }),
 ];
 const rowOf = (html: string, id: string): string => text(new RegExp(`<tr data-testid="run-row" data-run="${id}"[^>]*>(.*?)</tr>`, 's').exec(html)?.[1] ?? '');
 const html = detail(jobView({ runs, total_runs: 3, total_attempts: 5 }), { selectedRun: RUN2 });
 test('a recovered run is labelled as such while the job is currently failed, in two different sentences', () => {
  expect(block(html, 'job-health')).toContain('Current job health: Failed');
  const recovered = rowOf(html, RUN2);
  expect(recovered).toContain('Run status: Recovered after retry');
  expect(recovered).toContain('Run recovery: Recovered after retry (attempt 2 succeeded after 1 failed)');
  expect(recovered).not.toContain('Current job health');
  expect(rowOf(html, RUN)).toContain('Run recovery: not recovered');
  expect(rowOf(html, RUN)).not.toContain('Recovered after retry');
 });
 test('the run that current health rests on says so; a superseded run says its result is history', () => {
  expect(rowOf(html, RUN)).toContain('This run is the basis of current job health');
  expect(rowOf(html, RUN2)).not.toContain('This run is the basis');
  expect(rowOf(html, RUN2)).toContain("Superseded by newer occurrence s.new: this run's result is history and did not change current job health");
  expect(rowOf(html, RUN)).not.toContain('Superseded');
 });
 test('overlap, the repeated local time and a manual execution are words; the selected run is marked', () => {
  expect(rowOf(html, RUN2)).toContain('Overlaps with 2 other runs (the first 1 are listed)');
  expect(rowOf(html, RUN2)).toContain('Second occurrence of a repeated local time (the clock moved back); it is a separate expected run');
  expect(rowOf(html, RUN)).not.toContain('Second occurrence');
  expect(rowOf(html, RUN)).toContain('No other run overlaps this run');
  expect(rowOf(html, RUN3)).toContain('Not scheduled (a manual or unscheduled execution)');
  expect(rowOf(html, RUN3)).toContain('Run status: Cancelled');
  expect(rowOf(html, RUN3)).toContain('Run recovery: not recovered');
  expect(html).toContain(`data-run="${RUN2}" data-selected="yes"`);
  expect(html).toContain(`Open run ${RUN3}`);
  expect(html).toContain('2 failed of 2 attempts');
  expect(html).toContain('<table class="data-table" aria-label="Runs">');
 });
 test('the occurrence key and the scheduled instant are shown in the scope time zone', () => {
  const row = rowOf(html, RUN);
  expect(row).toContain('Occurrence s.new');
  expect(row).toMatch(/Scheduled for 27 Oct 2024/);
 });
 test('a truncated list says how many of how many, offers more runs up to 100 and then says it stops', () => {
  const truncated = { runs_truncation: { reason: 'runs_limit', shown: 25, total: 40 }, total_runs: 40 };
  const first = detail(jobView(truncated));
  expect(first).toContain('Showing 25 of 40 runs');
  expect(first).toContain('>Show more runs</button>');
  const top = detail(jobView({ runs_truncation: { reason: 'runs_limit', shown: 100, total: 130 }, total_runs: 130 }), { runsLimit: 100 });
  expect(top).toContain('Showing 100 of 130 runs');
  expect(top).not.toContain('Show more runs');
  expect(top).toContain('This view reads at most 100 runs; the journal keeps the full history.');
  const whole = detail(jobView());
  expect(whole).toContain('Showing all 1 runs');
  expect(whole).not.toContain('Show more runs');
 });
 test('compacted runs are stated with the journal keeping the history', () => {
  expect(detail(jobView({ compaction: { runs: '12', through_ns: ns(0) } }))).toContain('12 older runs were compacted out of this view; the journal keeps the full history');
  expect(detail(jobView())).not.toContain('compacted');
 });
 test('a job with no retained runs says so and renders no runs table', () => {
  const none = detail(jobView({ runs: [], total_runs: 0, total_attempts: 0, health: health({ status: 'unknown', complete: false, reasons: ['no_evidence'] }, { run: undefined }) }));
  expect(none).toContain('No run of this job is retained in this view.');
  expect(none).not.toContain('aria-label="Runs"');
 });
 test('a view without a health has nothing to show as a job', () => {
  expect(detail(jobView({ health: undefined, state: 'not_available', reason: 'job_service_not_wired' }))).toBe('');
 });
});

// ---- one run ----
const attempt = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: A1, ordinal: '1', started: true, observed_ns: ns(5), terminal: { state: 'failed', at_ns: ns(15) }, effective: 'failed', corrections: [], events_accepted: 2, final: false, after_newer_occurrence: false, ...over });
const runDetail = (attempts: Record<string, unknown>[], over: Record<string, unknown> = {}): JobView => jobView({ run: { ...runView({ attempt_count: attempts.length, final_attempt: attempts.at(-1)?.id, ...over }), attempts } });
const traceHref = (id: string): string => `#traces-${id}`;
const runHtml = (view: JobView): string => render(React.createElement(RunDetailView, { view, timezone: 'UTC', traceHref }));
const rowText = (html: string, id: string): string => text(new RegExp(`<tr data-testid="attempt-row" data-attempt="${id}"[^>]*>(.*?)</tr>`, 's').exec(html)?.[1] ?? '');

describe('a run lists every attempt with its original result', () => {
 const recovered = runDetail(
  [
   attempt({ cause_trace: TRACE, cause_error: ERR }),
   attempt({ id: A2, ordinal: '2', observed_ns: ns(60), terminal: { state: 'failed', at_ns: ns(70) }, corrections: [{ version: '1', state: 'succeeded', reason: 'the data owner confirmed the output', actor: ACTOR, at_ns: ns(500), command: OBS }], effective: 'succeeded', final: true }),
  ],
  { status: 'recovered', recovered: true, failed_attempts: 1, basis_of_health: false, superseded_by: 's.newest' },
 );
 const html = runHtml(recovered);
 test('the failed attempt stays failed and visible; the corrected one shows its original result and the correction', () => {
  const first = rowText(html, A1);
  expect(first).toContain('Attempt 1: Failed');
  expect(first).toMatch(/Original result: Failed at 27 Oct 2024/);
  const second = rowText(html, A2);
  expect(second).toContain('Attempt 2: Succeeded');
  expect(second).toMatch(/Original result: Failed at 27 Oct 2024/);
  expect(second).toContain(`Corrected to Succeeded (correction version 1 by ${ACTOR} at `);
  expect(second).toContain('): the data owner confirmed the output');
  expect(second).toContain('never rewritten or hidden');
  expect(html).toContain('data-testid="correction"');
  expect(html.indexOf(`data-attempt="${A1}"`)).toBeLessThan(html.indexOf(`data-attempt="${A2}"`));
  expect(html).toContain(`data-attempt="${A1}" data-state="failed"`);
  expect(html).toContain(`data-attempt="${A2}" data-state="succeeded"`);
 });
 test('the final attempt is marked and the others are not', () => {
  expect(rowText(html, A2)).toContain('Final attempt of this run');
  expect(rowText(html, A1)).not.toContain('Final attempt');
 });
 test('recovery is its own sentence and the health basis is another; superseded is explained', () => {
  expect(text(/<p data-testid="run-recovery">(.*?)<\/p>/s.exec(html)?.[1] ?? '')).toBe('Run recovery: Recovered after retry (attempt 2 succeeded after 1 failed)');
  const basis = block(html, 'run-health-basis');
  expect(basis).toContain('Current job health: Failed. This run is not the basis of that health.');
  expect(basis).toContain("Superseded by newer occurrence s.newest: this run's result is history and did not change current job health");
  expect(basis).not.toContain('Recovered');
 });
 test('deduplication: distinct attempts counted, events accepted, and what redelivery does', () => {
  expect(text(/<p data-testid="run-dedup">(.*?)<\/p>/s.exec(html)?.[1] ?? '')).toBe('2 distinct attempts counted; 4 events accepted. Redelivered events with the same producer epoch and sequence are not counted again and are not retained.');
 });
 test('cause links: the trace ID with a normal link to the Traces view and the access note; the error ID with the Issues sentence', () => {
  const causes = text(/<div data-testid="cause-links">(.*?)<\/div>/s.exec(html)?.[1] ?? '');
  expect(causes).toContain(`Cause trace ${TRACE}`);
  expect(causes).toContain('Opening it checks your access to the trace separately; a missing or denied trace reads Not found.');
  expect(causes).toContain(`Cause error ${ERR}`);
  expect(causes).toContain('opened from the Issues view');
  expect(html).toContain(`<a href="#traces-${TRACE}">`);
  expect(html).toContain(`<code>${TRACE}</code>`);
  expect(html).not.toContain(`href="#traces-${ERR}"`);
  expect(rowText(html, A2)).not.toContain('Cause trace');
 });
 test('a failed run is not recovered and is not worded as recovered', () => {
  const failed = runHtml(runDetail([attempt(), attempt({ id: A2, ordinal: '2', observed_ns: ns(60), final: true })], { basis_of_health: true }));
  expect(failed).toContain('Run recovery: not recovered');
  expect(text(/<p data-testid="run-recovery">(.*?)<\/p>/s.exec(failed)?.[1] ?? '')).not.toContain('Recovered after retry');
  expect(block(failed, 'run-health-basis')).toContain('This run is the basis of that health.');
  expect(failed).not.toContain('Superseded');
 });
 test('a cancelled attempt is Cancelled, explained as not a success, and never the word Succeeded', () => {
  const html = runHtml(runDetail([attempt({ terminal: { state: 'cancelled', at_ns: ns(15) }, effective: 'cancelled', final: true })], { status: 'cancelled', failed_attempts: 0, basis_of_health: false }));
  const row = rowText(html, A1);
  expect(row).toContain('Attempt 1: Cancelled');
  expect(row).toContain('Original result: Cancelled at');
  expect(row).toContain('Cancelled is not a success');
  expect(row).not.toContain('Succeeded');
  expect(html).toContain('data-state="cancelled"');
 });
 test('a started attempt has no result yet and no original result', () => {
  const html = runHtml(runDetail([attempt({ terminal: undefined, effective: 'started', final: true })], { status: 'running', failed_attempts: 0 }));
  expect(rowText(html, A1)).toContain('Attempt 1: Started (no result yet)');
  expect(rowText(html, A1)).toContain('Original result: none yet');
  expect(html).toContain('Run recovery: n/a');
 });
 test('a late result of an older occurrence says it is history and does not overwrite current health', () => {
  const html = runHtml(runDetail([attempt({ after_newer_occurrence: true, final: true, terminal: { state: 'succeeded', at_ns: ns(15) }, effective: 'succeeded' })], { status: 'succeeded', failed_attempts: 0, basis_of_health: false, superseded_by: 's.newest' }));
  const row = rowText(html, A1);
  expect(row).toContain('Completed after a newer occurrence started');
  expect(row).toContain('This is a late result for an older occurrence: it is recorded in history and does not overwrite current job health');
  expect(rowText(runHtml(recovered), A1)).not.toContain('Completed after a newer occurrence');
 });
 test('an attempt table has a caption, labelled columns and a row header per attempt', () => {
  expect(html).toContain('<table class="data-table" aria-label="Attempts of this run">');
  expect(html).toContain('<caption>Attempts of this run in ordinal order.');
  expect(html).toContain('<th scope="col">Attempt</th>');
  expect(html).toContain('<th scope="row">');
  expect(html).toContain(`Occurrence <code>s.new</code>`);
 });
 test('a view without a run renders nothing', () => { expect(runHtml(jobView())).toBe(''); });
});

describe('text from the server is only ever text', () => {
 test('the job list escapes an ID, a health word and a counter that carry a canary', () => {
  const html = render(React.createElement(JobTable, { jobs: [summary('failed', { job: CANARY })], selected: CANARY, open: () => undefined }));
  noElementsFromText(html);
 });
 test('the job panel escapes cron, time zone, overlap policy, loss reasons, occurrence keys, superseded keys, skipped times and unknown reasons', () => {
  const html = detail(jobView({
   definition: definition({ schedule: { cron: CANARY, timezone: CANARY }, overlap: CANARY }),
   health: health({ reasons: [CANARY] }, { skipped_local_times: [CANARY], gaps: [GAP] }),
   loss: { intervals: [{ id: GAP, start_ns: ns(1), end_ns: ns(2), reason: CANARY }], total: 1, affects_current_health: true },
   runs: [runView({ occurrence: { key: CANARY, scheduled: true, at_ns: ns(0), fold: 1 }, superseded_by: CANARY, id: RUN })],
  }));
  noElementsFromText(html);
  expect((html.match(/&lt;img src=x onerror=/g) ?? []).length).toBeGreaterThanOrEqual(6);
 });
 test('the run panel escapes the occurrence key, correction reason, actor and cause IDs, including inside an attribute', () => {
  const html = runHtml(runDetail(
   [attempt({ cause_trace: CANARY, cause_error: CANARY, corrections: [{ version: '1', state: 'succeeded', reason: CANARY, actor: CANARY, at_ns: ns(500), command: CANARY }], effective: 'succeeded', final: true })],
   { occurrence: { key: CANARY, scheduled: true, at_ns: ns(0), fold: 0 }, superseded_by: CANARY, overlaps: [CANARY], overlap_count: 1, id: CANARY },
  ));
  noElementsFromText(html);
  expect((html.match(/&lt;img src=x onerror=/g) ?? []).length).toBeGreaterThanOrEqual(6);
 });
});

describe('the pages as the user first meets them', () => {
 test('the jobs page has a Jobs heading, a labelled project selector over the scope and a state in words while it loads', () => {
  const html = render(React.createElement(JobsPage, { context }));
  expect(html).toContain('<h2 id="jobs-heading">Jobs</h2>');
  expect(html).toMatch(/<select aria-label="Project"[^>]*>/);
  expect(html).toContain(`<option value="${P1}" selected="">${P1}</option>`);
  expect(html).toContain(`<option value="${P2}">${P2}</option>`);
  expect(html).toContain('data-state="loading"');
  expect(html).toContain('Loading this view for the selected scope.');
  expect(html).not.toContain('data-testid="job-row"');
  expect(html).not.toContain('Load more');
 });
 test('the run page has a heading with the run ID and says it is loading', () => {
  const html = render(React.createElement(RunPage, { jobId: JOB, runId: RUN, context }));
  expect(html).toContain(`Run <code>${RUN}</code>`);
  expect(html).toContain('<h3 id="run-heading">');
  expect(html).toContain('data-state="loading"');
  expect(html).not.toContain('data-testid="attempt-row"');
 });
 test('a time that cannot be formatted reads as the nanosecond count instead of breaking the page', () => {
  expect(timeIn('Not/A_Zone')('1730000000000000000')).toBe('1730000000000000000 ns since the Unix epoch');
  expect(timeIn('UTC')('1730000000000000000')).toMatch(/^27 Oct 2024/);
 });
});

describe('the reasons of a view and of its parts are sentences', () => {
 const notes = (reason: string | undefined, sections: { name: string; state: string; reason?: string }[]): string => render(React.createElement(ReasonNotes, { testid: 'x-reason', reason, sections: sections as never }));
 test('a store that cannot be read is not an empty job list, and the sentence appears once', () => {
  const html = notes('job_store_not_readable', [{ name: 'jobs', state: 'not_available', reason: 'job_store_not_readable' }]);
  expect(text(html)).toContain('The job store of this installation cannot be read');
  expect(text(html)).toContain('not an empty job list');
  expect((text(html).match(/not an empty job list/g) ?? []).length).toBe(1);
 });
 test('a part with a reason of its own is named with the meaning of that reason', () => {
  const html = notes('job_evidence_incomplete', [{ name: 'health', state: 'incomplete', reason: 'job_evidence_incomplete' }, { name: 'observer', state: 'stale', reason: 'schedule_observer_stale' }, { name: 'loss', state: 'incomplete', reason: 'evidence_loss_recorded' }, { name: 'attempts', state: 'ready' }]);
  expect(html).toContain('data-section="observer"');
  expect(html).toContain('observer: The external schedule observer has not reported recently enough');
  expect(html).toContain('loss: Producer or evidence loss is recorded for this job. It is reported separately from the job outcome.');
  expect(html).not.toContain('data-section="attempts"');
  expect(html).not.toContain('data-section="health"');
 });
 test('a code this page does not know is a generic sentence; with nothing to report nothing is rendered', () => {
  expect(text(notes('from_the_future', []))).toContain('does not recognise');
  expect(notes('from_the_future', [])).not.toContain('from_the_future');
  expect(notes(undefined, [{ name: 'job', state: 'ready' }])).toBe('');
 });
 test('the name of a part and the text around an unknown reason are escaped', () => {
  noElementsFromText(notes(undefined, [{ name: CANARY, state: 'stale', reason: 'schedule_observer_stale' }]));
  expect(notes(CANARY, [])).not.toContain('onerror');
 });
});

describe('a job without a definition renders', () => {
 test('the panel says so, and the list row still shows its health', () => {
  const view = jobView({ definition: undefined, definition_revisions: 0, observer: { state: 'none', expected_schedule: false }, health: health({ status: 'unknown', complete: false, reasons: ['no_evidence'] }, { observer: undefined, run: undefined }), runs: [runView({ basis_of_health: false })] });
  const html = detail(view);
  expect(block(html, 'job-definition')).toBe('No job definition has been reported: this job has only attempt evidence, so it has no calendar schedule (it can fail or succeed but can never be missed) and no grace, maximum runtime or overlap policy is configured.');
  expect(block(html, 'job-health')).toContain('Current job health: Unknown');
  expect(render(React.createElement(JobTable, { jobs: [summary('unknown', { definition: undefined })], selected: '', open: () => undefined }))).toContain('<td>Unknown</td>');
 });
});
