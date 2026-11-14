// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getJob } from '../api/client';
import type { Id, JobAttemptView, JobView, ViewSection } from '../api/types';
import { encodeHash, formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { dataOf, useEvidence } from '../evidence/useEvidence';
import {
 CANCELLED_NOTE, CORRECTION_NOTE, ERROR_LINK_NOTE, FINAL_ATTEMPT_TEXT, LATE_RESULT_TEXT, LATE_STARTED_TEXT, TRACE_LINK_NOTE, attemptHeadline, correctionText, dedupText, finalOrdinal, foldText, healthBasisText, jobReasonText,
 originalResultText, overlapText, readChange, runRecoveryText, runStatusWord, scheduledText, supersededText,
} from './model';

/** The wording of a time that cannot be shown must not stop the page: a value outside the range of a date reads as the raw nanosecond count. */
export function timeIn(timezone: string): (ns: string) => string {
 return (ns) => {
  try { return formatNs(ns, timezone); } catch { return `${ns} ns since the Unix epoch`; }
 };
}

/** The ordinary Refresh of the shell bumps the generation without remounting a page: a read of the same target is repeated, and the answer on screen stays (labelled as refreshing) until the new one arrives. */
export function useRefreshOnGeneration(key: string, generation: number, reload: () => void): void {
 const seen = React.useRef({ key, generation });
 React.useEffect(() => {
  const before = seen.current;
  seen.current = { key, generation };
  if (readChange(before, seen.current) === 'refresh') reload();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, generation]);
}

/** The reason of a view and of each of its parts in the words of the job views. The generic section list prints a code it does not know as "Not available"; this says what the code means. */
export function ReasonNotes(props: { testid: string; reason: string | undefined; sections: readonly ViewSection[] }): React.JSX.Element | null {
 const parts = props.sections.flatMap((s) => s.reason !== undefined && s.reason !== props.reason ? [{ name: s.name, reason: s.reason }] : []);
 if (props.reason === undefined && parts.length === 0) return null;
 return (
  <div data-testid={props.testid}>
   {props.reason !== undefined && <p>{jobReasonText(props.reason)}</p>}
   {parts.length > 0 && <ul aria-label="What the parts of this view report">{parts.map((p) => <li key={p.name} data-section={p.name}>{`${p.name}: ${jobReasonText(p.reason)}`}</li>)}</ul>}
  </div>
 );
}

export function Refreshing(props: { active: boolean }): React.JSX.Element | null {
 return props.active ? <p role="status" data-testid="refreshing">Refreshing: the answer shown is the previous one until the new answer arrives.</p> : null;
}

function AttemptRow(props: { attempt: JobAttemptView; format: (ns: string) => string; traceHref: (trace: Id) => string }): React.JSX.Element {
 const { attempt: a, format, traceHref } = props;
 return (
  <tr data-testid="attempt-row" data-attempt={a.id} data-state={a.effective}>
   <th scope="row">
    <p><strong>{attemptHeadline(a)}</strong></p>
    <p>Attempt ID <code>{a.id}</code></p>
    {a.final && <p>{FINAL_ATTEMPT_TEXT}</p>}
    {a.effective === 'cancelled' && <p>{CANCELLED_NOTE}</p>}
   </th>
   <td>
    <p>{originalResultText(a, format)}</p>
    {a.corrections.length > 0 && (
     <>
      <ul aria-label="Corrections of this attempt">
       {a.corrections.map((c) => <li key={c.version} data-testid="correction">{correctionText(c, format)}</li>)}
      </ul>
      <p>{CORRECTION_NOTE}</p>
     </>
    )}
   </td>
   <td>
    <p>{`Observed at ${format(a.observed_ns)}`}</p>
    <p>{`${a.events_accepted} events accepted for this attempt`}</p>
    {a.after_newer_occurrence && <><p>{LATE_STARTED_TEXT}</p><p>{LATE_RESULT_TEXT}</p></>}
    {(a.cause_trace !== undefined || a.cause_error !== undefined) && (
     <div data-testid="cause-links">
      {a.cause_trace !== undefined && <p>Cause trace <code>{a.cause_trace}</code> <a href={traceHref(a.cause_trace)}>Open this trace in the Traces view</a></p>}
      {a.cause_trace !== undefined && <p>{TRACE_LINK_NOTE}</p>}
      {a.cause_error !== undefined && <p>Cause error <code>{a.cause_error}</code></p>}
      {a.cause_error !== undefined && <p>{ERROR_LINK_NOTE}</p>}
     </div>
    )}
   </td>
  </tr>
 );
}

/** One run of a job view with every attempt, in ordinal order. Recovery is this run's own; whether the run is the basis of the job's current health is a separate statement; a failed attempt stays visible with its original result whatever came after it. */
export function RunDetailView(props: { view: JobView; timezone: string; traceHref: (trace: Id) => string }): React.JSX.Element | null {
 const { view, timezone, traceHref } = props;
 const run = view.run;
 const health = view.health;
 if (run === undefined || health === undefined) return null;
 const format = timeIn(timezone);
 const fold = foldText(run.occurrence);
 const accepted = run.attempts.reduce((sum, a) => sum + a.events_accepted, 0);
 return (
  <div data-testid="run-detail" data-run={run.id}>
   <p data-testid="run-recovery">{runRecoveryText(run, finalOrdinal(run.attempts))}</p>
   <div data-testid="run-health-basis">
    <p>{healthBasisText(health.status, run.basis_of_health)}</p>
    {run.superseded_by !== undefined && <p>{supersededText(run.superseded_by)}</p>}
   </div>
   <p data-testid="run-status">{`Run status: ${runStatusWord(run.status)}. ${run.failed_attempts} failed attempts of ${run.attempt_count}.`}</p>
   <ul aria-label="Occurrence of this run">
    <li>Occurrence <code>{run.occurrence.key}</code></li>
    <li>{scheduledText(run.occurrence, format)}</li>
    <li>{`First started at ${format(run.first_started_ns)}`}</li>
    {fold !== null && <li>{fold}</li>}
    <li>{overlapText(run)}</li>
    {run.overlaps.length > 0 && <li>Overlapping run IDs: {run.overlaps.map((id, i) => <React.Fragment key={id}>{i > 0 ? ', ' : ''}<code>{id}</code></React.Fragment>)}</li>}
   </ul>
   <p data-testid="run-dedup">{dedupText(run.attempts.length, accepted)}</p>
   <table className="data-table" aria-label="Attempts of this run">
    <caption>Attempts of this run in ordinal order. A failed attempt stays visible with its original result whatever came after it.</caption>
    <thead><tr><th scope="col">Attempt</th><th scope="col">Result</th><th scope="col">Evidence</th></tr></thead>
    <tbody>{run.attempts.map((a) => <AttemptRow key={a.id} attempt={a} format={format} traceHref={traceHref} />)}</tbody>
   </table>
  </div>
 );
}

/** One run of one job under the caller's own scope. The server reads only what this account may read; a missing run, a missing job and a denied one are the same Not found. */
export function RunPage(props: { jobId: Id; runId: Id; context: ViewContext; project?: Id }): React.JSX.Element {
 const { context, jobId, runId } = props;
 const project = props.project ?? context.projects[0] ?? '';
 const key = `${scopeKey(context)}|${project}|${jobId}|${runId}`;
 const evidence = useEvidence<JobView>(key, (signal) => getJob(context.org, project, jobId, { run: runId }, signal));
 useRefreshOnGeneration(key, context.generation, evidence.reload);
 const view = dataOf(evidence.state);
 const traceHref = (trace: Id): string => encodeHash(context, 'traces', '', null, { project, id: trace });
 return (
  <section className="panel" aria-labelledby="run-heading" data-testid="run-page">
   <h3 id="run-heading">Run <code>{runId}</code></h3>
   <p>Job <code>{jobId}</code>. Times are shown in {context.timezone}.</p>
   <Refreshing active={evidence.reloading} />
   <StatusPanel state={evidence.state} />
   {view && <EvidenceSections sections={view.sections} />}
   {view && <ReasonNotes testid="run-reason" reason={view.reason} sections={view.sections} />}
   {view && <RunDetailView view={view} timezone={context.timezone} traceHref={traceHref} />}
  </section>
 );
}
