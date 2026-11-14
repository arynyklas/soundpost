// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getJob, isAbort, listJobs, stateOfFault } from '../api/client';
import type { Id, JobRunView, JobsListView, JobSummaryView, JobView, LoadState } from '../api/types';
import { latestOnly, scopeKey, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { dataOf, stateOfEvidence, useEvidence } from '../evidence/useEvidence';
import {
 BASIS_TEXT, DEFAULT_RUNS_LIMIT, JOBS_PAGE_LIMIT, LOSS_SEPARATE_TEXT, MISSED_RULE_TEXT, appendJobs, chooseProject, compactionText, completenessWord, cursorText, definitionLines, expectedText, foldText, healthLine, healthReasonText, healthWord,
 jobsShownText, lossIntervalText, lossOverlapText, lossShownText, nextRunsLimit, observerExplanation, observerLine, overlapText, runRecoveryText, runStatusWord, runsShownText, scheduledText, skippedText,
 sourceVersionText, supersededText,
} from './model';
import { ReasonNotes, Refreshing, RunPage, timeIn, useRefreshOnGeneration } from './RunPage';

/** The listed jobs: one row each with the current health in words, whether its evidence is complete, and the counts of runs and attempts. Health and completeness are separate columns. */
export function JobTable(props: { jobs: readonly JobSummaryView[]; selected: Id | ''; open: (job: Id) => void }): React.JSX.Element {
 return (
  <table className="data-table" aria-label="Jobs">
   <caption>Jobs of this project in job ID order. Current health and completeness of its evidence are separate columns.</caption>
   <thead><tr><th scope="col">Job ID</th><th scope="col">Current health</th><th scope="col">Evidence</th><th scope="col">Runs</th><th scope="col">Attempts</th><th scope="col">Action</th></tr></thead>
   <tbody>
    {props.jobs.map((j) => (
     <tr key={j.job} data-testid="job-row" data-job={j.job} data-health={j.health.status} data-selected={j.job === props.selected ? 'yes' : 'no'}>
      <th scope="row"><code>{j.job}</code></th>
      <td>{healthWord(j.health.status)}</td>
      <td>{j.erased ? `${completenessWord(j.health.complete)}. History erased` : completenessWord(j.health.complete)}</td>
      <td>{j.runs}</td>
      <td>{j.attempts}</td>
      <td><button type="button" aria-pressed={j.job === props.selected} onClick={() => props.open(j.job)}>{`Open job ${j.job}`}</button></td>
     </tr>
    ))}
   </tbody>
  </table>
 );
}

function RunRow(props: { run: JobRunView; selected: boolean; format: (ns: string) => string; open: (run: Id) => void }): React.JSX.Element {
 const { run, format } = props;
 const fold = foldText(run.occurrence);
 return (
  <tr data-testid="run-row" data-run={run.id} data-selected={props.selected ? 'yes' : 'no'}>
   <th scope="row"><code>{run.id}</code></th>
   <td>
    <p>Occurrence <code>{run.occurrence.key}</code></p>
    <p>{scheduledText(run.occurrence, format)}</p>
    {fold !== null && <p>{fold}</p>}
   </td>
   <td>{`Run status: ${runStatusWord(run.status)}`}</td>
   <td>{runRecoveryText(run)}</td>
   <td>{`${run.failed_attempts} failed of ${run.attempt_count} attempts`}</td>
   <td>
    <ul aria-label="About this run">
     {run.basis_of_health && <li>{BASIS_TEXT}</li>}
     {run.superseded_by !== undefined && <li>{supersededText(run.superseded_by)}</li>}
     <li>{overlapText(run)}</li>
    </ul>
   </td>
   <td><button type="button" aria-pressed={props.selected} onClick={() => props.open(run.id)}>{`Open run ${run.id}`}</button></td>
  </tr>
 );
}

/** One job: its current health, definition, schedule observer, loss, committed source and runs. The current health, a run's recovery and loss are three separate statements; none is derived from another. */
export function JobDetail(props: { view: JobView; timezone: string; selectedRun: Id | ''; runsLimit: number; openRun: (run: Id) => void; moreRuns: (limit: number) => void }): React.JSX.Element | null {
 const { view, timezone } = props;
 const { health, definition, observer, loss, source, compaction } = view;
 if (health === undefined || observer === undefined || loss === undefined || source === undefined || compaction === undefined) return null;
 const format = timeIn(timezone);
 const expected = expectedText(health, format);
 const compacted = compactionText(compaction.runs);
 const next = nextRunsLimit(props.runsLimit, view.runs_truncation);
 const gaps = health.evidence.gaps ?? [];
 const zone = definition?.schedule?.timezone ?? 'the job time zone';
 return (
  <div data-testid="job-detail" data-job={view.job}>
   <h4>Current health</h4>
   <div data-testid="job-health">
    <p>{healthLine(health.status)}</p>
    <p>{`Evidence: ${completenessWord(health.complete)}`}</p>
    <ul aria-label="Why the job has this health">
     {health.reasons.map((r) => <li key={r} data-reason={r}>{healthReasonText(r)}</li>)}
    </ul>
    {health.evidence.run !== undefined && <p>Current health rests on run <code>{health.evidence.run}</code>.</p>}
    {expected !== null && <p>{expected}</p>}
   </div>
   {(health.evidence.skipped_local_times ?? []).length > 0 && (
    <ul data-testid="job-skipped" aria-label="Skipped local times">
     {(health.evidence.skipped_local_times ?? []).map((t) => <li key={t}>{skippedText(t, zone)}</li>)}
    </ul>
   )}
   <h4>Definition</h4>
   <div data-testid="job-definition">
    <ul aria-label="Job definition">{definitionLines(definition, view.definition_revisions, format).map((line) => <li key={line}>{line}</li>)}</ul>
   </div>
   <h4>Schedule observer</h4>
   <div data-testid="job-observer">
    <p>{observerLine(observer.state)}</p>
    <p>{observerExplanation(observer.state, observer.expected_schedule)}</p>
    {observer.evidence !== undefined && (
     <ul aria-label="Observer evidence">
      <li>{`Observer observed at ${format(observer.evidence.observed_at_ns)}`}</li>
      <li>{`Observer complete through ${format(observer.evidence.complete_through_ns)}`}</li>
      <li>{`Observer reports itself ${observer.evidence.healthy ? 'healthy' : 'unhealthy'}`}</li>
     </ul>
    )}
    <p>{MISSED_RULE_TEXT}</p>
   </div>
   <h4>Producer and evidence loss</h4>
   <div data-testid="job-loss">
    <p>{LOSS_SEPARATE_TEXT}</p>
    {loss.intervals.length === 0
     ? <p>No producer or evidence loss is recorded for this job.</p>
     : <ul aria-label="Loss intervals">{loss.intervals.map((i) => <li key={i.id} data-overlaps={gaps.includes(i.id) ? 'yes' : 'no'}>{`${lossIntervalText(i, format)}${gaps.includes(i.id) ? ' (overlaps the evidence current health rests on)' : ''}`}</li>)}</ul>}
    {loss.truncation !== undefined && <p>{lossShownText(loss.truncation.shown, loss.truncation.total ?? loss.total)}</p>}
    <p>{lossOverlapText(loss.affects_current_health)}</p>
   </div>
   <h4>Committed source</h4>
   <div data-testid="job-source">
    <p>{sourceVersionText(source.version)}</p>
    <p>{cursorText(source.cursor)}</p>
   </div>
   <h4>Runs</h4>
   <p data-testid="runs-summary">{view.runs_truncation === undefined ? `Showing all ${view.runs.length} runs` : runsShownText(view.runs_truncation.shown, view.runs_truncation.total ?? view.total_runs)}</p>
   {compacted !== null && <p data-testid="runs-compacted">{compacted}</p>}
   {view.runs_truncation !== undefined && next !== null && <button type="button" onClick={() => props.moreRuns(next)}>Show more runs</button>}
   {view.runs_truncation !== undefined && next === null && <p>This view reads at most {props.runsLimit} runs; the journal keeps the full history.</p>}
   {view.runs.length === 0
    ? <p>No run of this job is retained in this view.</p>
    : (
     <table className="data-table" aria-label="Runs">
      <caption>Runs of this job, newest first. Run recovery describes one run; it is not the current health of the job.</caption>
      <thead><tr><th scope="col">Run</th><th scope="col">Occurrence</th><th scope="col">Status</th><th scope="col">Recovery</th><th scope="col">Failed attempts</th><th scope="col">About this run</th><th scope="col">Action</th></tr></thead>
      <tbody>{view.runs.map((r) => <RunRow key={r.id} run={r} selected={r.id === props.selectedRun} format={format} open={props.openRun} />)}</tbody>
     </table>
    )}
  </div>
 );
}

function JobPanel(props: { context: ViewContext; project: Id; job: Id; run: Id | ''; runsLimit: number; setRunsLimit: (limit: number) => void; openRun: (run: Id) => void; closeRun: () => void }): React.JSX.Element {
 const { context, project, job, run, runsLimit } = props;
 const key = `${scopeKey(context)}|${project}|${job}`;
 const evidence = useEvidence<JobView>(key, (signal) => getJob(context.org, project, job, { runsLimit }, signal));
 useRefreshOnGeneration(key, context.generation, evidence.reload);
 // A larger run limit re-reads the same job; the answer on screen stays until the new one arrives.
 const limit = React.useRef(runsLimit);
 React.useEffect(() => {
  if (limit.current === runsLimit) return;
  limit.current = runsLimit;
  evidence.reload();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [runsLimit]);
 const view = dataOf(evidence.state);
 return (
  <section className="panel" aria-labelledby="job-heading" data-testid="job-panel" data-job={job}>
   <h3 id="job-heading">Job <code>{job}</code></h3>
   <Refreshing active={evidence.reloading} />
   <StatusPanel state={evidence.state} />
   {view && <EvidenceSections sections={view.sections} />}
   {view && <ReasonNotes testid="job-reason" reason={view.reason} sections={view.sections} />}
   {view && <JobDetail view={view} timezone={context.timezone} selectedRun={run} runsLimit={runsLimit} openRun={props.openRun} moreRuns={props.setRunsLimit} />}
   {view && run !== '' && (
    <>
     <button type="button" onClick={props.closeRun}>Back to job</button>
     <RunPage key={run} jobId={job} runId={run} context={context} project={project} />
    </>
   )}
  </section>
 );
}

interface Selection { scope: string; job: Id | ''; run: Id | ''; runsLimit: number }
interface More { base: JobsListView; jobs: JobSummaryView[]; next: Id | null; status: LoadState<unknown> | null; busy: boolean }

/** The jobs of one project under the caller's own scope, and one job with its runs and attempts. The project, job and run the user selected are kept here, so the shell's Refresh re-reads them in place instead of jumping to another run. */
export function JobsPage(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const [projectChoice, setProjectChoice] = React.useState('');
 const project = chooseProject(projectChoice, context.projects);
 const scope = `${scopeKey(context)}|${project}`;
 const [selection, setSelection] = React.useState<Selection>({ scope: '', job: '', run: '', runsLimit: DEFAULT_RUNS_LIMIT });
 const current: Selection = selection.scope === scope ? selection : { scope, job: '', run: '', runsLimit: DEFAULT_RUNS_LIMIT };
 const list = useEvidence<JobsListView>(scope, (signal) => listJobs(context.org, project, '', JOBS_PAGE_LIMIT, signal));
 useRefreshOnGeneration(scope, context.generation, list.reload);

 // Pages after the first belong to the first page they follow: when a new first page arrives they are dropped and Load more starts again from it.
 const [more, setMore] = React.useState<More | null>(null);
 const moreRead = React.useRef<Latest>(latestOnly());
 React.useEffect(() => () => moreRead.current.stop(), [scope]);
 const view = dataOf(list.state);
 const extra = view !== undefined && more !== null && more.base === view ? more : null;
 const shown = view === undefined ? [] : extra === null ? view.jobs : appendJobs(view.jobs, extra.jobs);
 const next: Id | null = extra !== null ? extra.next : (view?.truncation?.next ?? null);
 const loadMore = (): void => {
  if (view === undefined || next === null || extra?.busy === true) return;
  const base = view;
  const prior = extra?.jobs ?? [];
  const after = next;
  const read = moreRead.current.begin();
  setMore({ base, jobs: prior, next: after, status: null, busy: true });
  listJobs(context.org, project, after, JOBS_PAGE_LIMIT, read.signal).then(
   (page) => {
    if (!read.current()) return;
    const fresh = appendJobs([...base.jobs, ...prior], page.jobs).slice(base.jobs.length + prior.length);
    setMore({ base, jobs: [...prior, ...fresh], next: page.state === 'not_available' ? after : (page.truncation?.next ?? null), status: page.state === 'ready' ? null : stateOfEvidence(page), busy: false });
   },
   (error: unknown) => { if (read.current() && !isAbort(error)) setMore({ base, jobs: prior, next: after, status: stateOfFault(error), busy: false }); },
  );
 };

 return (
  <section className="panel" aria-labelledby="jobs-heading" data-testid="jobs-page">
   <h2 id="jobs-heading">Jobs</h2>
   <p>The current health of a job, the recovery of one run and producer loss are reported separately. Times are shown in {context.timezone}.</p>
   <label>Project <select aria-label="Project" value={project} onChange={(e) => setProjectChoice(e.target.value)}>{context.projects.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
   <Refreshing active={list.reloading} />
   <StatusPanel state={list.state} />
   {view && <EvidenceSections sections={view.sections} />}
   {view && <ReasonNotes testid="jobs-reason" reason={view.reason} sections={view.sections} />}
   {shown.length > 0 && <JobTable jobs={shown} selected={current.job} open={(job) => { if (job !== current.job) setSelection({ scope, job, run: '', runsLimit: DEFAULT_RUNS_LIMIT }); }} />}
   {shown.length > 0 && <p data-testid="jobs-count">{jobsShownText(shown.length, next !== null)}</p>}
   {extra !== null && extra.status !== null && <StatusPanel state={extra.status} />}
   {next !== null && <button type="button" onClick={loadMore} disabled={extra?.busy === true}>Load more</button>}
   {current.job !== '' && (
    <JobPanel
     key={`${scope}|${current.job}`} context={context} project={project} job={current.job} run={current.run} runsLimit={current.runsLimit}
     setRunsLimit={(runsLimit) => setSelection({ ...current, runsLimit })}
     openRun={(run) => setSelection({ ...current, run })}
     closeRun={() => setSelection({ ...current, run: '' })}
    />
   )}
  </section>
 );
}
