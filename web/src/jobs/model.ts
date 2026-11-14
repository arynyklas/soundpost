// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Wording and derivation for the job views (POST /api/v1/jobs/list and /api/v1/jobs/view). Everything here is pure text and arithmetic: no
// React, no fetch. Three facts are kept apart on purpose and never derived from each other: the job's CURRENT HEALTH, one RUN's recovery and
// PRODUCER LOSS. Times are formatted by the caller (a nanosecond string never passes through a JavaScript number here).
import type { Id, JobAttemptState, JobAttemptView, JobCorrection, JobDefinition, JobHealth, JobHealthStatus, JobInterval, JobObserverState, JobOccurrenceView, JobRunStatus, JobRunView, JobSummaryView, JobTruncation } from '../api/types';

/** How many jobs one page of the listing asks for. */
export const JOBS_PAGE_LIMIT = 25;
/** The run list limits the view can ask for, in order; the server never answers more than the last. */
export const RUNS_STEPS: readonly number[] = [25, 50, 100];
export type TimeText = (ns: string) => string;

/** The run list limit a job opens with. */
export const DEFAULT_RUNS_LIMIT = 25;
const words = (table: readonly (readonly [string, string])[], code: string, fallback: string): string => new Map(table).get(code) ?? fallback;

const HEALTH_WORDS = [
 ['succeeded', 'Succeeded'], ['failed', 'Failed'], ['cancelled', 'Cancelled'], ['running', 'Running'], ['running_too_long', 'Running too long'], ['late', 'Late'],
 ['missed', 'Missed (external schedule observer evidence)'], ['unknown', 'Unknown'],
] as const;
/** The current health of a job in words. Missed always names its only possible source. */
export function healthWord(status: JobHealthStatus): string { return words(HEALTH_WORDS, status, 'Unknown'); }
export function healthLine(status: JobHealthStatus): string { return `Current job health: ${healthWord(status)}`; }
export function completenessWord(complete: boolean): string { return complete ? 'Complete' : 'Incomplete evidence'; }

const HEALTH_REASONS = [
 ['no_evidence', 'No run or attempt has been reported for this job, so nothing supports any other verdict.'],
 ['attempt_succeeded', 'The newest attempt of the newest occurrence succeeded.'],
 ['attempt_failed', 'The newest attempt of the newest occurrence failed.'],
 ['attempt_cancelled', 'The newest attempt of the newest occurrence was cancelled. Cancelled is not a success.'],
 ['run_recovered_after_retry', 'The newest run succeeded on a retry after an earlier attempt failed; the failed attempt stays in its history.'],
 ['retry_in_progress', 'The newest run has started another attempt after an earlier one.'],
 ['attempt_running', 'The newest attempt has started and has not reported a result yet.'],
 ['running_beyond_max_runtime', 'The newest attempt has been running longer than the maximum runtime set for this job.'],
 ['attempt_result_corrected', 'An authorized person corrected the result of the newest attempt; its original result is kept in the attempt history.'],
 ['expected_occurrence_not_started', 'A scheduled occurrence was expected and no run started for it.'],
 ['occurrence_window_closed_without_run', 'The window of the expected occurrence has closed and no run started in it.'],
 ['no_schedule_observer', 'No external schedule observer has reported for this scheduled job, so a missed run cannot be established and a success cannot be confirmed.'],
 ['schedule_observer_stale', 'The external schedule observer has not reported recently enough, so schedule health is unknown rather than last observed.'],
 ['schedule_observer_unhealthy', 'The external schedule observer reported that it is unhealthy, so its evidence is not conclusive.'],
 ['no_clock_evidence', 'No external clock has reported, so the maximum runtime cannot be checked.'],
 ['evidence_gap_overlaps', 'A period of lost evidence overlaps what this verdict rests on, so the verdict is not conclusive.'],
 ['evidence_of_absence_incomplete', 'It cannot be shown that nothing ran in the expected window, because the evidence of absence is incomplete.'],
 ['nonexistent_local_time_skipped', 'A scheduled local time does not exist on a day the clock moved forward, so no run was expected then.'],
] as const;
/** One plain sentence for a reason code of the health verdict; a code this page does not know is never shown as a bare code. */
export function healthReasonText(code: string): string { return words(HEALTH_REASONS, code, 'This verdict carries a reason this page does not recognise; the evidence shown is still the evidence the server used.'); }

const JOB_REASONS = [
 ['job_service_not_wired', 'This installation has no job service wired, so no job can be shown. That is not an empty job list: it says nothing about whether jobs exist.'],
 ['job_store_not_readable', 'The job store of this installation cannot be read, so no job can be shown. That is not an empty job list: it says nothing about whether jobs exist.'],
 ['no_jobs', 'This project has no jobs. Nothing is missing.'],
 ['job_history_erased', 'The history of this job was erased. Its definition and health are shown, but its runs and attempts are gone; this is not a job that never ran.'],
 ['job_evidence_incomplete', 'Evidence the health of this job needs is missing, so the verdict is not conclusive.'],
 ['schedule_observer_stale', 'The external schedule observer has not reported recently enough, so schedule health is unknown rather than last observed.'],
 ['no_schedule_observer', 'No external schedule observer has reported for this scheduled job, so a missed run cannot be established.'],
 ['evidence_loss_recorded', 'Producer or evidence loss is recorded for this job. It is reported separately from the job outcome.'],
] as const;
/** The sentence for a reason of a job view or one of its parts (the section list). */
export function jobReasonText(code: string): string { return words(JOB_REASONS, code, 'This part of the view reports a reason this page does not recognise.'); }

const ATTEMPT_WORDS = [['succeeded', 'Succeeded'], ['failed', 'Failed'], ['cancelled', 'Cancelled'], ['started', 'Started (no result yet)']] as const;
/** An attempt state in words: cancelled is Cancelled, never a success. */
export function attemptWord(state: JobAttemptState): string { return words(ATTEMPT_WORDS, state, 'Unknown'); }
const RUN_WORDS = [['running', 'Running'], ['succeeded', 'Succeeded'], ['recovered', 'Recovered after retry'], ['failed', 'Failed'], ['cancelled', 'Cancelled']] as const;
export function runStatusWord(status: JobRunStatus): string { return words(RUN_WORDS, status, 'Unknown'); }

/** Recovery describes one run's own attempts. It is always worded apart from the job's current health. `finalOrdinal` is the ordinal of the final attempt when the attempts are known. */
export function runRecoveryText(run: Pick<JobRunView, 'status' | 'recovered' | 'attempt_count' | 'failed_attempts'>, finalOrdinal?: string): string {
 if (run.recovered) return `Run recovery: Recovered after retry (attempt ${finalOrdinal ?? String(run.attempt_count)} succeeded after ${run.failed_attempts} failed)`;
 switch (run.status) {
  case 'failed': return 'Run recovery: not recovered (the final attempt of this run failed)';
  case 'cancelled': return 'Run recovery: not recovered (the final attempt of this run was cancelled, which is not a success)';
  case 'running': return 'Run recovery: n/a (this run has not finished)';
  default: return 'Run recovery: n/a (no attempt of this run failed before its final success)';
 }
}
/** Whether this run is what the job's current health rests on: a statement about the verdict, not about recovery. */
export function healthBasisText(status: JobHealthStatus, basis: boolean): string { return `${healthLine(status)}. This run is ${basis ? '' : 'not '}the basis of that health.`; }
export const BASIS_TEXT = 'This run is the basis of current job health';
export function supersededText(key: string): string { return `Superseded by newer occurrence ${key}: this run's result is history and did not change current job health`; }
export const LATE_STARTED_TEXT = 'Completed after a newer occurrence started';
export const LATE_RESULT_TEXT = 'This is a late result for an older occurrence: it is recorded in history and does not overwrite current job health';
export const FINAL_ATTEMPT_TEXT = 'Final attempt of this run';
export const FOLD_TEXT = 'Second occurrence of a repeated local time (the clock moved back); it is a separate expected run';
export function foldText(o: Pick<JobOccurrenceView, 'fold'>): string | null { return o.fold === 1 ? FOLD_TEXT : null; }
export function skippedText(local: string, timezone: string): string { return `Skipped: local time ${local} does not exist in ${timezone} (clock moved forward); no run was expected then`; }
export function scheduledText(o: JobOccurrenceView, format: TimeText): string { return o.scheduled && o.at_ns !== undefined ? `Scheduled for ${format(o.at_ns)}` : 'Not scheduled (a manual or unscheduled execution)'; }
export function overlapText(run: Pick<JobRunView, 'overlap_count' | 'overlaps'>): string {
 const n = run.overlap_count;
 if (n === 0) return 'No other run overlaps this run';
 return `Overlaps with ${n} other run${n === 1 ? '' : 's'}${n > run.overlaps.length ? ` (the first ${run.overlaps.length} are listed)` : ''}`;
}

/** Attempt lines. The original result is always shown; a correction is a later, audited statement that never rewrites it. */
export function attemptHeadline(a: Pick<JobAttemptView, 'ordinal' | 'effective'>): string { return `Attempt ${a.ordinal}: ${attemptWord(a.effective)}`; }
export function originalResultText(a: Pick<JobAttemptView, 'terminal'>, format: TimeText): string {
 return a.terminal === undefined ? 'Original result: none yet (no result has been reported for this attempt)' : `Original result: ${attemptWord(a.terminal.state)} at ${format(a.terminal.at_ns)}`;
}
export function correctionText(c: Pick<JobCorrection, 'state' | 'version' | 'actor' | 'at_ns' | 'reason'>, format: TimeText): string {
 return `Corrected to ${attemptWord(c.state)} (correction version ${c.version} by ${c.actor} at ${format(c.at_ns)}): ${c.reason}`;
}
export const CORRECTION_NOTE = 'A correction is a later, audited statement. The original result above stays in this history and is never rewritten or hidden.';
export const CANCELLED_NOTE = 'Cancelled is not a success: the attempt was stopped without finishing its work.';
/** Events accepted for the attempts of a run, and how duplicates were treated. */
export function dedupText(distinctAttempts: number, eventsAccepted: number): string {
 return `${distinctAttempts} distinct attempts counted; ${eventsAccepted} events accepted. Redelivered events with the same producer epoch and sequence are not counted again and are not retained.`;
}
export const TRACE_LINK_NOTE = "The job view embeds none of the trace's content. Opening it checks your access to the trace separately; a missing or denied trace reads Not found.";
export const ERROR_LINK_NOTE = 'Only the error ID is shown here. The error is opened from the Issues view, which checks your access to it separately.';

const OBSERVER_EXPLANATION = [
 ['none', 'No external schedule observer has reported for this job, so a missed run cannot be established and a success cannot be confirmed.'],
 ['fresh', 'The external schedule observer reported recently and says it is healthy.'],
 ['stale', 'The newest report of the external schedule observer is older than its stale-after limit, so schedule health is unknown rather than last observed.'],
 ['unhealthy', 'The external schedule observer reported that it is unhealthy, so its evidence is not conclusive.'],
] as const;
export function observerLine(state: JobObserverState): string { return `Schedule observer: ${state}`; }
export function observerExplanation(state: JobObserverState, expectedSchedule: boolean): string {
 return expectedSchedule ? words(OBSERVER_EXPLANATION, state, 'The state of the schedule observer is not recognised.') : 'This job has no calendar schedule, so it needs no schedule observer and can never be missed.';
}
export const MISSED_RULE_TEXT = 'Missed is shown only from external schedule observer evidence. When no records exist, or the SDK or exporter is down, the job reads Unknown; it is never shown as recovered or missed by assumption.';

const LOSS_REASONS = [
 ['source_loss', 'source loss (telemetry from the producer did not arrive)'], ['observer_outage', 'an outage of the schedule observer'],
 ['evidence_expired', 'evidence expired before it could be read'], ['expired', 'evidence expired before it could be read'],
 ['exporter_connectivity', 'the exporter lost its connection'],
] as const;
export function lossReasonText(code: string): string { return words(LOSS_REASONS, code, `a recorded loss with the code ${code}`); }
export function lossIntervalText(i: Pick<JobInterval, 'start_ns' | 'end_ns' | 'reason'>, format: TimeText): string { return `${format(i.start_ns)} to ${format(i.end_ns)}: ${lossReasonText(i.reason)}`; }
export const LOSS_SEPARATE_TEXT = 'Loss is reported separately from the job outcome.';
export function lossOverlapText(affects: boolean): string {
 return affects ? 'A loss interval overlaps the evidence the current job health rests on, so that health is not conclusive.' : 'No loss interval overlaps the evidence the current job health rests on.';
}

/** Zero is the server's "not set" value for these three durations. */
export function durationText(ns: string): string {
 const total = BigInt(ns);
 if (total < 0n) return `${ns} nanoseconds`;
 if (total === 0n) return '0 seconds';
 const parts: string[] = [];
 let rest = total;
 for (const [size, unit] of [[86_400_000_000_000n, 'day'], [3_600_000_000_000n, 'hour'], [60_000_000_000n, 'minute'], [1_000_000_000n, 'second']] as const) {
  const n = rest / size;
  rest %= size;
  if (n > 0n) parts.push(`${n} ${unit}${n === 1n ? '' : 's'}`);
 }
 if (rest > 0n) parts.push(rest % 1_000_000n === 0n ? `${rest / 1_000_000n} ms` : `${rest} ns`);
 return parts.join(' ');
}
export function graceText(ns: string): string { return BigInt(ns) === 0n ? '5 minutes (default)' : durationText(ns); }
export function maxRuntimeText(ns: string): string { return BigInt(ns) === 0n ? 'none set' : durationText(ns); }
export function staleAfterText(ns: string): string { return BigInt(ns) === 0n ? '10 minutes (default)' : durationText(ns); }
export function overlapPolicyText(policy: string): string { return policy === 'allow' ? 'allow: a run that starts while another runs is recorded, never dropped or merged' : policy; }

/** The job definition as labelled lines: time zone, schedule, grace, maximum runtime, observer stale-after, overlap policy and revisions. */
export const NO_DEFINITION_TEXT = 'No job definition has been reported: this job has only attempt evidence, so it has no calendar schedule (it can fail or succeed but can never be missed) and no grace, maximum runtime or overlap policy is configured.';
export function definitionLines(d: JobDefinition | undefined, revisions: number, format: TimeText): string[] {
 if (d === undefined) return [NO_DEFINITION_TEXT];
 return [
  d.schedule === undefined ? 'Time zone: not set (no calendar schedule)' : `Time zone: ${d.schedule.timezone}`,
  d.schedule === undefined ? 'Schedule: No calendar schedule (this job can fail or succeed but can never be missed)' : `Schedule: ${d.schedule.cron}`,
  `Grace: ${graceText(d.grace_ns)}`,
  `Maximum runtime: ${maxRuntimeText(d.max_runtime_ns)}`,
  `Observer stale after: ${staleAfterText(d.observer_stale_after_ns)}`,
  `Overlap policy: ${overlapPolicyText(d.overlap)}`,
  `${revisions} definition revision${revisions === 1 ? '' : 's'} (current revision ${d.revision}, effective from ${format(d.effective_from_ns)})`,
 ];
}

/** The committed source of a view: the version of the job state and the origin cursor of the newest attempt evidence applied. */
export function sourceVersionText(version: string): string { return `Committed source version ${version}`; }
export function cursorText(cursor: { group: Id; index: string } | undefined): string { return cursor === undefined ? 'Origin cursor: no attempt evidence cursor' : `Origin cursor of the newest attempt evidence: ${cursor.group}:${cursor.index}`; }

export function runsShownText(shown: number, total: number): string { return `Showing ${shown} of ${total} runs`; }
/** The next run limit (25 → 50 → 100), or null when the view is already at the most it reads or shows every run. */
export function nextRunsLimit(current: number, truncation: JobTruncation | undefined): number | null {
 if (truncation === undefined) return null;
 return RUNS_STEPS.find((step) => step > current) ?? null;
}
export function compactionText(runs: string): string | null {
 const n = BigInt(runs);
 return n > 0n ? `${runs} older run${n === 1n ? ' was' : 's were'} compacted out of this view; the journal keeps the full history` : null;
}
export function expectedText(h: JobHealth, format: TimeText): string | null {
 const e = h.evidence;
 if (e.expected_at_ns === undefined) return null;
 return `Expected occurrence at ${format(e.expected_at_ns)}${e.window_end_ns === undefined ? '' : `; its window closed at ${format(e.window_end_ns)}`}`;
}

/** The project the page shows: the one chosen if the scope still holds it, else the first of the scope. */
export function chooseProject(choice: string, projects: readonly Id[]): Id { return projects.includes(choice) ? choice : (projects[0] ?? ''); }
/** Appends a page after the jobs already shown; a job already listed is never listed twice. */
export function appendJobs(shown: readonly JobSummaryView[], page: readonly JobSummaryView[]): JobSummaryView[] {
 const have = new Set(shown.map((j) => j.job));
 return [...shown, ...page.filter((j) => !have.has(j.job))];
}
/** The ordinal of the final attempt of a run's attempts, for the recovery sentence. */
export function finalOrdinal(attempts: readonly JobAttemptView[]): string | undefined { return attempts.find((a) => a.final)?.ordinal; }
/** How many listed jobs are on screen and whether the server says more follow. */
export function jobsShownText(shown: number, more: boolean): string { return more ? `Showing ${shown} jobs. More jobs exist; Load more reads the next page.` : `Showing ${shown} jobs. No more jobs follow.`; }
export function lossShownText(shown: number, total: number): string { return `Showing ${shown} of ${total} loss intervals`; }
/** What a change of the shell's context means for a page that holds a read. The same target with a new generation is the ordinary Refresh: read again and keep the answer on screen until the new one arrives. A different target is a new read that shows loading at once, so it is never also a refresh. */
export function readChange(before: { key: string; generation: number }, after: { key: string; generation: number }): 'none' | 'refresh' | 'new-target' {
 if (before.key !== after.key) return 'new-target';
 return before.generation === after.generation ? 'none' : 'refresh';
}
