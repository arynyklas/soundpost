// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getJob, isAbort, listJobs, stateOfFault } from '../api/client';
import type { Id, JobRunView, JobsListView, JobSummaryView, JobView, LoadState } from '../api/types';
import { latestOnly, scopeKey, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { EvidenceSections } from '../evidence/Sections';
import { dataOf, stateOfEvidence, useEvidence } from '../evidence/useEvidence';
import { Content, Hero, PageHead } from '../shell/Frames';
import { type ShellApi } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Card, DataTable, EmptyState, FilterChips, IdCode, Pill, shortId, type Column } from '../ui/primitives';
import {
 BASIS_TEXT, DEFAULT_RUNS_LIMIT, JOBS_PAGE_LIMIT, LOSS_SEPARATE_TEXT, MISSED_RULE_TEXT, appendJobs, chooseProject, compactionText, completenessWord, cursorText, definitionLines, expectedText, foldText, healthLine, healthReasonText, healthTone, healthWord,
 jobsShownText, lossIntervalText, lossOverlapText, lossShownText, nextRunsLimit, observerExplanation, observerLine, overlapText, runRecoveryText, runStatusWord, runsShownText, scheduledText, skippedText,
 sourceVersionText, supersededText,
} from './model';
import { ReasonNotes, Refreshing, RunPage, timeIn, useRefreshOnGeneration } from './RunPage';
import { RunStrip, StripLegend } from './RunStrip';
import { buildStrip, type StripState } from './strip';

type Href = ShellApi['href'];

/** The listed jobs: one row each with the current health in words, whether its evidence is complete, the counts of runs and attempts, and the runs drawn at the instants they started. Health and completeness are separate columns. */
export function JobTable(props: { jobs: readonly JobSummaryView[]; project: Id; href: Href; strips: ReadonlyMap<Id, StripState> }): React.JSX.Element {
 const columns: Column<JobSummaryView>[] = [
  {
   key: 'job', header: 'Job', cell: (j) => (
    <div className="cell-title">
     <a className="a mono" href={props.href('jobs', { target: { project: props.project, id: j.job } })} aria-label={`Open job ${j.job}`}>{j.job}</a>
     <span className="s">{j.definition?.schedule ? `${j.definition.schedule.cron} (${j.definition.schedule.timezone})` : 'no calendar schedule'}</span>
    </div>
   ),
  },
  { key: 'health', header: 'Current health', cell: (j) => <Pill tone={healthTone(j.health.status)} state={j.health.status}>{healthWord(j.health.status)}</Pill> },
  { key: 'evidence', header: 'Evidence', cell: (j) => <span className="small">{j.erased ? `${completenessWord(j.health.complete)}. History erased` : completenessWord(j.health.complete)}</span> },
  { key: 'strip', header: 'Runs in the window', cell: (j) => <RunStrip state={props.strips.get(j.job) ?? { kind: 'loading' }} job={j.job} /> },
  { key: 'runs', header: 'Runs', align: 'right', cell: (j) => <span className="num">{j.runs}</span> },
  { key: 'attempts', header: 'Attempts', align: 'right', cell: (j) => <span className="num">{j.attempts}</span> },
 ];
 return (
  <DataTable
   label="Jobs" caption="Jobs of this project in job ID order. Current health and completeness of its evidence are separate columns." rows={props.jobs} rowKey={(j) => j.job} columns={columns}
   rowAttrs={(j) => ({ 'data-testid': 'job-row', 'data-job': j.job, 'data-health': j.health.status })}
  />
 );
}

function RunStatusPill(props: { run: JobRunView }): React.JSX.Element {
 const { status } = props.run;
 return <Pill tone={status === 'succeeded' ? 'ok' : status === 'recovered' ? 'high' : status === 'failed' ? 'crit' : status === 'running' ? 'info' : 'unk'}>{runStatusWord(status)}</Pill>;
}

function runColumns(format: (ns: string) => string, selected: Id | '', open: (run: Id) => void): Column<JobRunView>[] {
 return [
  { key: 'run', header: 'Run', cell: (run) => <IdCode value={run.id} /> },
  {
   key: 'occurrence', header: 'Occurrence', cell: (run) => {
    const fold = foldText(run.occurrence);
    return (
     <>
      <p>Occurrence <code>{run.occurrence.key}</code></p>
      <p>{scheduledText(run.occurrence, format)}</p>
      {fold !== null && <p>{fold}</p>}
     </>
    );
   },
  },
  { key: 'status', header: 'Status', cell: (run) => <><span className="sr-only">Run status: </span><RunStatusPill run={run} /></> },
  { key: 'recovery', header: 'Recovery', cell: (run) => runRecoveryText(run) },
  { key: 'failed', header: 'Failed attempts', cell: (run) => `${run.failed_attempts} failed of ${run.attempt_count} attempts` },
  {
   key: 'about', header: 'About this run', cell: (run) => (
    <ul aria-label="About this run">
     {run.basis_of_health && <li>{BASIS_TEXT}</li>}
     {run.superseded_by !== undefined && <li>{supersededText(run.superseded_by)}</li>}
     <li>{overlapText(run)}</li>
    </ul>
   ),
  },
  { key: 'action', header: 'Action', cell: (run) => <button type="button" className="btn btn-sm" aria-pressed={run.id === selected} aria-label={`Open run ${run.id}`} onClick={() => open(run.id)}>Open run</button> },
 ];
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
  <div className="col g16" data-testid="job-detail" data-job={view.job}>
   <Card title="Current health" titleId="job-health-h">
    <div data-testid="job-health" className="job-block">
     <p>{healthLine(health.status)}</p>
     <p>{`Evidence: ${completenessWord(health.complete)}`}</p>
     <ul aria-label="Why the job has this health">
      {health.reasons.map((r) => <li key={r} data-reason={r}>{healthReasonText(r)}</li>)}
     </ul>
     {health.evidence.run !== undefined && <p>Current health rests on run <IdCode value={health.evidence.run} />.</p>}
     {expected !== null && <p>{expected}</p>}
    </div>
    {(health.evidence.skipped_local_times ?? []).length > 0 && (
     <ul data-testid="job-skipped" aria-label="Skipped local times">
      {(health.evidence.skipped_local_times ?? []).map((t) => <li key={t}>{skippedText(t, zone)}</li>)}
     </ul>
    )}
   </Card>
   <div className="grid-2">
    <Card title="Definition" titleId="job-definition-h">
     <div data-testid="job-definition" className="job-block">
      <ul aria-label="Job definition">{definitionLines(definition, view.definition_revisions, format).map((line) => <li key={line}>{line}</li>)}</ul>
     </div>
    </Card>
    <Card title="Schedule observer" titleId="job-observer-h">
     <div data-testid="job-observer" className="job-block">
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
    </Card>
    <Card title="Producer and evidence loss" titleId="job-loss-h">
     <div data-testid="job-loss" className="job-block">
      <p>{LOSS_SEPARATE_TEXT}</p>
      {loss.intervals.length === 0
       ? <p>No producer or evidence loss is recorded for this job.</p>
       : <ul aria-label="Loss intervals">{loss.intervals.map((i) => <li key={i.id} data-overlaps={gaps.includes(i.id) ? 'yes' : 'no'}>{`${lossIntervalText(i, format)}${gaps.includes(i.id) ? ' (overlaps the evidence current health rests on)' : ''}`}</li>)}</ul>}
      {loss.truncation !== undefined && <p>{lossShownText(loss.truncation.shown, loss.truncation.total ?? loss.total)}</p>}
      <p>{lossOverlapText(loss.affects_current_health)}</p>
     </div>
    </Card>
    <Card title="Committed source" titleId="job-source-h">
     <div data-testid="job-source" className="job-block">
      <p>{sourceVersionText(source.version)}</p>
      <p>{cursorText(source.cursor)}</p>
     </div>
    </Card>
   </div>
   <Card title="Runs" titleId="job-runs-h" bodyClass={false}>
    <div className="card-body">
     <p data-testid="runs-summary">{view.runs_truncation === undefined ? `Showing all ${view.runs.length} runs` : runsShownText(view.runs_truncation.shown, view.runs_truncation.total ?? view.total_runs)}</p>
     {compacted !== null && <p data-testid="runs-compacted">{compacted}</p>}
     {view.runs_truncation !== undefined && next !== null && <button type="button" className="btn" onClick={() => props.moreRuns(next)}>Show more runs</button>}
     {view.runs_truncation !== undefined && next === null && <p>This view reads at most {props.runsLimit} runs; the journal keeps the full history.</p>}
     {view.runs.length === 0 && <p>No run of this job is retained in this view.</p>}
    </div>
    {view.runs.length > 0 && (
     <DataTable
      label="Runs" caption="Runs of this job, newest first. Run recovery describes one run; it is not the current health of the job." rows={view.runs} rowKey={(r) => r.id} columns={runColumns(format, props.selectedRun, props.openRun)}
      rowAttrs={(r) => ({ 'data-testid': 'run-row', 'data-run': r.id, 'data-selected': r.id === props.selectedRun ? 'yes' : 'no' })}
     />
    )}
   </Card>
  </div>
 );
}

/** The strips of the listed jobs, read a few at a time from each job's own view: a strip is the job's own runs, never an inference from the counts. A job whose view cannot be read is drawn as such, not as having no runs. */
function useStrips(context: ViewContext, project: Id, jobs: readonly JobSummaryView[]): ReadonlyMap<Id, StripState> {
 const ids = jobs.map((j) => `${j.job}${j.erased ? 'e' : ''}`).join(',');
 const key = `${scopeKey(context)}|${context.generation}|${project}|${ids}`;
 const [held, setHeld] = React.useState<{ key: string; strips: ReadonlyMap<Id, StripState> }>({ key: '', strips: new Map() });
 const latest = React.useRef<Latest>(latestOnly());
 React.useEffect(() => {
  if (jobs.length === 0) { latest.current.stop(); return; }
  const read = latest.current.begin();
  const window = { start: context.start, end: context.end };
  const queue = [...jobs];
  const settled = new Map<Id, StripState>();
  const publish = (): void => { if (read.current()) setHeld({ key, strips: new Map(settled) }); };
  const worker = async (): Promise<void> => {
   for (let job = queue.shift(); job !== undefined; job = queue.shift()) {
    if (job.erased) { settled.set(job.job, { kind: 'ready', strip: buildStrip({ runs: [], runs_truncation: undefined, health: job.health, erased: true }, window) }); publish(); continue; }
    try {
     const view = await getJob(context.org, project, job.job, { runsLimit: DEFAULT_RUNS_LIMIT }, read.signal);
     settled.set(job.job, view.state === 'not_available' ? { kind: 'failed' } : { kind: 'ready', strip: buildStrip(view, window) });
    } catch (error) {
     if (isAbort(error)) return;
     settled.set(job.job, { kind: 'failed' });
    }
    publish();
   }
  };
  void Promise.all([worker(), worker(), worker(), worker()]);
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return held.key === key ? held.strips : new Map();
}

const HEALTH_FILTERS: readonly { value: 'all' | 'failing' | 'unknown'; label: string }[] = [{ value: 'all', label: 'All' }, { value: 'failing', label: 'Failing' }, { value: 'unknown', label: 'Unknown' }];
const failing = (j: JobSummaryView): boolean => j.health.status === 'failed' || j.health.status === 'missed' || j.health.status === 'running_too_long';

interface More { base: JobsListView; jobs: JobSummaryView[]; next: Id | null; status: LoadState<unknown> | null; busy: boolean }

/** The jobs of one project under the caller's own scope. The project the user selected is kept here, so the shell's Refresh re-reads the list in place. */
export function JobsList(props: { context: ViewContext; href: Href; project?: Id }): React.JSX.Element {
 const { context } = props;
 const [projectChoice, setProjectChoice] = React.useState(props.project ?? '');
 const project = chooseProject(projectChoice, context.projects);
 const scope = `${scopeKey(context)}|${project}`;
 const list = useEvidence<JobsListView>(scope, (signal) => listJobs(context.org, project, '', JOBS_PAGE_LIMIT, signal));
 useRefreshOnGeneration(scope, context.generation, list.reload);
 const [filter, setFilter] = React.useState<'all' | 'failing' | 'unknown'>('all');
 const [text, setText] = React.useState('');

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
 const strips = useStrips(context, project, shown);
 const counts = { all: shown.length, failing: shown.filter(failing).length, unknown: shown.filter((j) => j.health.status === 'unknown').length };
 const q = text.trim().toLowerCase();
 const visible = shown.filter((j) => (filter === 'all' || (filter === 'failing' ? failing(j) : j.health.status === 'unknown')) && (q === '' || j.job.includes(q)));
 return (
  <section className="col g12" aria-label="Jobs of the selected project" data-testid="jobs-page">
   <p>The current health of a job, the recovery of one run and producer loss are reported separately. Times are shown in {context.timezone}.</p>
   <div className="row wrap">
    <label className="iss-select"><span className="t3 small">Project</span><select aria-label="Project" value={project} onChange={(e) => setProjectChoice(e.target.value)}>{context.projects.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
    <div className="searchbar grow">
     <Icon name="search" size="s" />
     <input name="filter" aria-label="Filter jobs by ID" placeholder="Filter jobs by ID" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off" spellCheck={false} maxLength={64} />
    </div>
    <FilterChips<'all' | 'failing' | 'unknown'> label="Health" value={filter} options={HEALTH_FILTERS.map((o) => ({ ...o, count: counts[o.value] }))} onChange={setFilter} />
   </div>
   <Refreshing active={list.reloading} />
   {list.state.kind === 'empty' && view?.reason === 'no_jobs'
    // A complete answer with no jobs: one card says it, and the state stays in words for assistive technology.
    ? <Card bodyClass={false} ariaLabel="Job list"><div className="sr-only"><StatusPanel state={list.state} /></div><EmptyState icon="job" title="No jobs in this project" testId="jobs-empty">This project reports no scheduled or background jobs in this window. Nothing is missing.</EmptyState></Card>
    : <>
     <StatusPanel state={list.state} />
     {view && <ReasonNotes testid="jobs-reason" reason={view.reason} sections={view.sections} />}
    </>}
   {view && <EvidenceSections sections={view.sections} />}
   {shown.length > 0 && (
    <Card bodyClass={false} ariaLabel="Job list" footer={<StripLegend />}>
     {visible.length === 0
      ? <EmptyState icon="job" title="No listed job matches" testId="jobs-filter-empty">No job on screen matches this filter.</EmptyState>
      : <JobTable jobs={visible} project={project} href={props.href} strips={strips} />}
    </Card>
   )}
   {shown.length > 0 && <p data-testid="jobs-count">{jobsShownText(shown.length, next !== null)}</p>}
   {extra !== null && extra.status !== null && <StatusPanel state={extra.status} />}
   {next !== null && <button type="button" className="btn" onClick={loadMore} disabled={extra?.busy === true}>Load more</button>}
  </section>
 );
}

/** One job: its identity as the one h1, its health in words, the runs drawn in the window, and every statement of the job view. The run the user selected is kept here, so the shell's Refresh re-reads it in place instead of jumping to another run. */
export function JobPage(props: { context: ViewContext; project: Id; job: Id; href: Href; footer?: React.ReactNode }): React.JSX.Element {
 const { context, project, job, href } = props;
 const key = `${scopeKey(context)}|${project}|${job}`;
 const [run, setRun] = React.useState<Id | ''>('');
 const [runsLimit, setRunsLimit] = React.useState(DEFAULT_RUNS_LIMIT);
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
 const health = view?.health;
 const strip: StripState | undefined = view?.health ? { kind: 'ready', strip: buildStrip(view, { start: context.start, end: context.end }) } : undefined;
 return (
  <>
   <PageHead crumb={<><a href={href('jobs')}>Jobs</a><Icon name="right" size="xs" /><span className="mono">{shortId(project)}</span><Icon name="right" size="xs" /><span className="mono">{shortId(job)}</span></>} />
   <Hero>
    <div className="row wrap g12">
     <h1 tabIndex={-1} data-testid="job-heading" data-job={job}>Job</h1>
     <span className="mono small t2" title={job}>job {job.slice(0, 4)}…{job.slice(-4)}</span>
     {health && <Pill tone={healthTone(health.status)} state={health.status}>{healthWord(health.status)}</Pill>}
    </div>
    {health && (
     <div className="row wrap small t2 g12">
      <span>{completenessWord(health.complete)} evidence</span>
      {view?.definition?.schedule ? <span>{view.definition.schedule.cron} ({view.definition.schedule.timezone})</span> : <span>no calendar schedule</span>}
      <span>{view?.total_runs ?? 0} runs, {view?.total_attempts ?? 0} attempts</span>
     </div>
    )}
    {strip && <div className="job-hero-strip"><RunStrip state={strip} job={job} /><StripLegend /></div>}
   </Hero>
   <Content>
    <Refreshing active={evidence.reloading} />
    <StatusPanel state={evidence.state} />
    {view && <EvidenceSections sections={view.sections} />}
    {view && <ReasonNotes testid="job-reason" reason={view.reason} sections={view.sections} />}
    {view && <JobDetail view={view} timezone={context.timezone} selectedRun={run} runsLimit={runsLimit} openRun={setRun} moreRuns={setRunsLimit} />}
    {view && run !== '' && (
     <>
      <div><button type="button" className="btn" onClick={() => setRun('')}><Icon name="right" size="s" />Back to job</button></div>
      <RunPage key={run} jobId={job} runId={run} context={context} project={project} />
     </>
    )}
    {props.footer}
   </Content>
  </>
 );
}
