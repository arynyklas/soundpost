// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getQueue, investigate, listJobs, stateOfFault, stateOfView } from '../api/client';
import { listIssues } from '../api/console';
import type { IncidentView, JobSummaryView, LoadState, QueueView, VisibleService } from '../api/types';
import { StatusPanel } from '../app/StatusPanel';
import { PAGE_LIMIT, formatNs, requestFor, type ViewContext } from '../app/context';
import { useScoped } from '../app/loadState';
import { Content, PageHead } from '../shell/Frames';
import { clockText } from '../shell/ScopeControls';
import { projectLabel, useShell, type Names } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Card, EmptyState, Person, Pill, SeverityIcon, shortId, type Tone } from '../ui/primitives';
import { byUrgency, dataHealth, errorChanges, incidentTitle, jobNeedsAttention, jobWords, leadIncident, needsAction, nextStep, serviceRow, unhealthyServices, type DataHealth, type ErrorChange, type ServiceRow } from './model';

const SERVICE_PROBE_LIMIT = 10;

function stateOfQueue(view: QueueView): LoadState<QueueView> {
 switch (view.state) {
  case 'ready': return { kind: 'ready', data: view };
  case 'empty': return { kind: 'empty', data: view };
  case 'incomplete': return { kind: 'incomplete', data: view, reason: view.reason ?? 'incomplete' };
  case 'stale': return { kind: 'stale', data: view, reason: view.reason ?? 'stale' };
  case 'not_available': return { kind: 'unsupported', reason: view.reason ?? 'not_available', data: view };
 }
}

const SOURCE_TONE: Record<string, Tone> = { firing: 'crit', recovered: 'ok', unknown: 'unk' };
function SourcePill(props: { incident: IncidentView }): React.JSX.Element {
 const c = props.incident.condition;
 const tone = SOURCE_TONE[c.state] ?? 'unk';
 return <Pill tone={tone} icon={c.state === 'firing' ? 'fire' : c.state === 'recovered' ? 'check' : 'question'}>{c.state === 'firing' ? 'Firing' : c.state === 'recovered' ? 'Recovered' : 'Unknown'}{c.freshness !== 'fresh' ? ` · ${c.freshness} data` : ''}</Pill>;
}

function Lead(props: { incident: IncidentView; context: ViewContext }): React.JSX.Element {
 const { incident: e, context } = props;
 const shell = useShell();
 const ref = { project: e.project_id, id: e.incident_id };
 const tz = context.timezone;
 const delivery = e.notification.delivery;
 const failing = delivery.attention === 'failed' || delivery.attention === 'uncertain';
 const links = e.links.filter((l) => l.kind === 'issue' || l.kind === 'release' || l.kind === 'service');
 return (
  <Card urgent bodyClass={false} testId="home-lead">
   <div className="card-head">
    <SeverityIcon severity={e.severity} />
    <h2 id="home-lead-h">Most urgent: {incidentTitle(e)}</h2>
    <span className="small t3">{e.severity} · last activity {clockText(e.last_activity, tz, false)}</span>
    <a className="btn btn-primary btn-sm ml-auto" href={shell.href('incidents', { incident: ref })}>Open incident<Icon name="arrow" size="xs" /></a>
   </div>
   <div className="card-body grid-3 card-lead">
    <div className="col g4"><span className="eyebrow">Impact now</span><span className="bold"><SourcePill incident={e} /></span><span className="small t2">{e.observed_impacts} impact observation{e.observed_impacts === 1 ? '' : 's'} · last observed {clockText(e.condition.observed_at, tz, false)} · {e.condition.freshness} data</span></div>
    <div className="col g4"><span className="eyebrow">Response</span><Person id={e.owner} name={e.owner ? shell.names.members.get(e.owner) : undefined} /><span className="small t2">{e.ack ? `acknowledged ${clockText(e.ack.at, tz, false)}${e.ack.current ? '' : ' (an earlier impact only)'}` : 'not acknowledged'}</span>{failing && <span className="small tone-crit">{delivery.attention === 'failed' ? 'a notification failed' : 'a notification may not have arrived'}</span>}</div>
    <div className="col g4"><span className="eyebrow">Related records</span>{links.length === 0 ? <span className="small t2">No issue, release or service is linked yet.</span> : links.map((l) => <span key={`${l.kind}:${l.id}`} className="small"><a href={shell.href(l.kind === 'issue' ? 'issues' : l.kind === 'release' ? 'releases' : 'services', l.kind === 'service' ? { service: l.id } : { target: { project: e.project_id, id: l.id } })}>{l.kind[0]!.toUpperCase()}{l.kind.slice(1)} {shortId(l.id)}</a></span>)}</div>
   </div>
  </Card>
 );
}

function NeedsAction(props: { entries: readonly IncidentView[]; context: ViewContext }): React.JSX.Element {
 const shell = useShell();
 const need = byUrgency(props.entries.filter(needsAction));
 const shown = need.slice(0, 5);
 const open = props.entries.filter((e) => e.status === 'open').length;
 return (
  <Card title="Incidents that need team action" titleId="home-need-h" bodyClass={false} actions={<a className="small" href={shell.href('incidents')}>All {open} open</a>} footer={need.length > shown.length ? `+${need.length - shown.length} more need action; the rest are in Incidents` : undefined} testId="home-need">
   {shown.length === 0
    ? <div className="card-body"><span className="small t2">{open === 0 ? 'No incident is open in the selected projects.' : 'Every open incident is acknowledged, snoozed or in maintenance, and none has a failing notification.'}</span></div>
    : <ul className="feed">{shown.map((e) => {
     const delivery = e.notification.delivery.attention;
     return (
      <li key={`${e.project_id}:${e.incident_id}`}>
       <SeverityIcon severity={e.severity} />
       <div className="cell-title grow"><a className="a" href={shell.href('incidents', { incident: { project: e.project_id, id: e.incident_id } })}>{incidentTitle(e)}</a>
        <span className="s"><b>{projectLabel(shell.names, e.project_id)}</b> · <SourcePill incident={e} /> · last activity {clockText(e.last_activity, shell.context?.timezone ?? 'UTC', false)}{delivery === 'failed' || delivery === 'uncertain' ? <> · <span className="tone-crit">{delivery === 'failed' ? 'notification failed' : 'notification uncertain'}</span></> : null}</span></div>
       <a className="need" href={shell.href('incidents', { incident: { project: e.project_id, id: e.incident_id } })}>{nextStep(e)}</a>
      </li>
     );
    })}</ul>}
  </Card>
 );
}

interface JobsData { rows: { project: string; job: JobSummaryView }[]; projectsFailed: number; total: number }
function JobsPanel(props: { context: ViewContext }): React.JSX.Element {
 const shell = useShell();
 const { context } = props;
 const state = useScoped<JobsData>(context, 'home-jobs', async (signal) => {
  const settled = await Promise.allSettled(context.projects.map((p) => listJobs(context.org, p, '', 50, signal)));
  if (signal.aborted) throw new DOMException('aborted', 'AbortError');
  const rows: JobsData['rows'] = [];
  let failed = 0, total = 0;
  settled.forEach((r, i) => { if (r.status === 'fulfilled') { total += r.value.jobs.length; for (const job of r.value.jobs) if (jobNeedsAttention(job)) rows.push({ project: context.projects[i]!, job }); } else failed++; });
  const data: JobsData = { rows, projectsFailed: failed, total };
  if (failed === context.projects.length) return { kind: 'error', fault: (settled[0] as PromiseRejectedResult).reason as never };
  return failed > 0 ? { kind: 'incomplete', data, reason: 'project_failed' } : total === 0 ? { kind: 'empty', data } : { kind: 'ready', data };
 });
 const data = 'data' in state ? state.data : undefined;
 return (
  <Card title="Jobs" titleId="home-jobs-h" bodyClass={false} actions={<a className="small" href={shell.href('jobs')}>All jobs</a>} testId="home-jobs">
   {state.kind !== 'ready' && state.kind !== 'empty' && <div className="card-body"><StatusPanel state={state} /></div>}
   {data && data.rows.length > 0 && <ul className="feed">{data.rows.slice(0, 5).map(({ project, job }) => {
    const w = jobWords(job.health.status);
    return <li key={`${project}:${job.job}`}><Pill tone={w.tone} icon={w.tone === 'crit' ? 'x' : w.tone === 'high' ? 'warn' : 'question'}>{w.word}</Pill><a className="grow bold" href={shell.href('jobs', { target: { project, id: job.job } })} title={job.job}>Job {shortId(job.job)}</a><span className="small t2">{projectLabel(shell.names, project)} · {job.runs} run{job.runs === 1 ? '' : 's'}</span></li>;
   })}</ul>}
   {data && data.rows.length === 0 && state.kind !== 'loading' && <div className="card-body"><span className="small t2">{data.total === 0 ? 'No job reported in the selected projects.' : `${data.total} job${data.total === 1 ? '' : 's'} reported; none needs attention.`}</span></div>}
  </Card>
 );
}

interface ServicesData { rows: ServiceRow[]; projects: { project_id: string; sources: number; word: DataHealth }[]; probed: number; total: number }
function useServices(context: ViewContext): LoadState<ServicesData> {
 return useScoped<ServicesData>(context, 'home-services', async (signal) => {
  const list = await investigate(requestFor(context, 'service'), signal);
  const services: VisibleService[] = list.services ?? [];
  const probe = services.slice(0, SERVICE_PROBE_LIMIT);
  const health = await Promise.allSettled(probe.map((s) => investigate({ ...requestFor(context, 'service', s.id), projects: [s.project_id] }, signal)));
  if (signal.aborted) throw new DOMException('aborted', 'AbortError');
  const rows = probe.map((s, i) => { const r = health[i]; return serviceRow(s, r?.status === 'fulfilled' ? r.value.health : undefined); });
  const data: ServicesData = { rows, probed: probe.length, total: services.length, projects: list.projects.map((p) => ({ project_id: p.project_id, sources: p.sources.length, word: dataHealth(p.sources.length, list) })) };
  return stateOfView(list).kind === 'ready' || stateOfView(list).kind === 'empty' ? { kind: 'ready', data } : { ...stateOfView(list), data } as LoadState<ServicesData>;
 });
}

function ServicesPanel(props: { state: LoadState<ServicesData> }): React.JSX.Element {
 const shell = useShell();
 const { state } = props;
 const data = 'data' in state ? state.data : undefined;
 const u = data ? unhealthyServices(data.rows) : undefined;
 return (
  <Card title="Services not healthy" titleId="home-svc-h" bodyClass={false} actions={<a className="small" href={shell.href('services')}>{data ? `All ${data.total}` : 'All'}</a>} footer={data && data.total > data.probed ? `Health was read for the first ${data.probed} of ${data.total} services; the others are not assessed here.` : u && u.healthy > 0 ? `${u.healthy} healthy` : undefined} testId="home-services">
   {state.kind !== 'ready' && <div className="card-body"><StatusPanel state={state} /></div>}
   {u && u.listed.length > 0 && <ul className="feed">{u.listed.map((r) => (
    <li key={`${r.project_id}:${r.id}`}>
     {r.status === 'failing' ? <Pill tone="crit" icon="x">Failing</Pill> : r.status === 'degraded' ? <Pill tone="high" icon="warn">Degraded</Pill> : <Pill tone="unk" icon="question">Not assessed</Pill>}
     <a className="grow bold" href={shell.href('services', { service: r.id })} title={r.id}>Service {shortId(r.id)}</a>
     <span className="small t2">{r.status === 'not_assessed' ? 'no incident or condition reader states its health' : `${r.openIncidents} open incident${r.openIncidents === 1 ? '' : 's'}${r.conditions > 0 ? ` · ${r.conditions} active condition${r.conditions === 1 ? '' : 's'}` : ''}`}</span>
    </li>
   ))}</ul>}
   {u && u.listed.length === 0 && state.kind === 'ready' && <div className="card-body"><span className="small t2">{data!.total === 0 ? 'No source policy of the selected projects admits a service.' : 'Every assessed service is healthy.'}</span></div>}
  </Card>
 );
}

function DataHealthPanel(props: { state: LoadState<ServicesData>; names: Names }): React.JSX.Element {
 const { state } = props;
 const data = 'data' in state ? state.data : undefined;
 return (
  <Card title="Data health" titleId="home-data-h" bodyClass={false} testId="home-data">
   {!data && <div className="card-body"><StatusPanel state={state} /></div>}
   {data && <ul className="feed">{data.projects.map((p) => (
    <li key={p.project_id} data-project={p.project_id}>
     <span className={`dot dot-${p.word.tone === 'ok' ? 'ok' : p.word.tone === 'unk' ? 'unk' : 'high'}`} aria-hidden="true" />
     <span className="grow">{projectLabel(props.names, p.project_id)}<span className="t3"> · {p.sources} readable source{p.sources === 1 ? '' : 's'}</span></span>
     <span className="small t2">{p.word.word}</span>
    </li>
   ))}</ul>}
  </Card>
 );
}

function ErrorChanges(props: { context: ViewContext }): React.JSX.Element {
 const shell = useShell();
 const { context } = props;
 const state = useScoped(context, 'home-errors', async (signal) => {
  const base = { org: context.org, projects: context.projects, window: { start: context.start, end: context.end }, limit: 20 };
  const [regressed, recent] = await Promise.all([listIssues(base, { regressed: true, workflow: ['open'] }, signal), listIssues({ ...base, sort: 'first_seen' }, { workflow: ['open'] }, signal)]);
  if (regressed.kind === 'not_built' || recent.kind === 'not_built') return { kind: 'unsupported', reason: 'not_built' } as LoadState<ErrorChange[]>;
  if (regressed.kind === 'fault') return stateOfFault(regressed.fault);
  if (recent.kind === 'fault') return stateOfFault(recent.fault);
  const rows = errorChanges(regressed.data.items, recent.data.items, context.start, 5);
  const partial = regressed.data.state === 'incomplete' || recent.data.state === 'incomplete';
  return partial ? { kind: 'incomplete', data: rows, reason: regressed.data.reason ?? recent.data.reason ?? 'incomplete' } : rows.length === 0 ? { kind: 'empty', data: rows } : { kind: 'ready', data: rows };
 });
 const rows = 'data' in state ? state.data : undefined;
 return (
  <Card title="Error changes in this window" titleId="home-err-h" bodyClass={false} actions={<a className="small" href={shell.href('issues')}>All issues</a>} testId="home-errors">
   {state.kind !== 'ready' && state.kind !== 'empty' && <div className="card-body"><StatusPanel state={state} /></div>}
   {rows && rows.length > 0 && <ul className="feed">{rows.map(({ change, issue }) => (
    <li key={`${issue.project_id}:${issue.issue_id}`}>
     <Pill tone={change === 'Regressed' ? 'crit' : 'acc'}>{change}</Pill>
     <div className="cell-title grow"><a className="a" href={shell.href('issues', { target: { project: issue.project_id, id: issue.issue_id } })}>{issue.title ?? `Issue ${shortId(issue.issue_id)}`}</a><span className="s">{projectLabel(shell.names, issue.project_id)}{issue.titleState === 'not_available' ? ' · title not available' : ''}</span></div>
     <span className="small t2 num">{issue.occurrences === null ? 'count not available' : `${Number(issue.occurrences).toLocaleString('en-US')} events`}</span>
    </li>
   ))}</ul>}
   {rows && rows.length === 0 && state.kind === 'empty' && <div className="card-body"><span className="small t2">No issue regressed or appeared in this window.</span></div>}
  </Card>
 );
}

/** Home: what is burning now. Every panel reads its own answer for the scope and says its own state in words; a part the installation does not serve is
 * "not available yet", never an empty list. */
export function HomeRoute(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const shell = useShell();
 const queue = useScoped(context, 'home-queue', async (signal) => stateOfQueue(await getQueue(context.org, context.projects, PAGE_LIMIT, signal)));
 const view = 'data' in queue ? queue.data : undefined;
 const services = useServices(context);
 const open = view ? view.entries.filter((e) => e.status === 'open').length : undefined;
 const { setCounts } = shell;
 React.useEffect(() => { if (view && !view.truncated) setCounts({ incidents: open }); }, [view, open, setCounts]);
 const lead = view ? leadIncident(view.entries) : undefined;
 const names = shell.names;
 return (
  <>
   <PageHead title="Home" sub={`What needs attention in ${context.projects.length === 1 ? projectLabel(names, context.projects[0]!) : `${context.projects.length} projects`} right now`} />
   <Content>
    {!view && <StatusPanel state={queue} />}
    {view && view.state !== 'ready' && view.state !== 'empty' && <StatusPanel state={queue} />}
    {view && lead && <Lead incident={lead} context={context} />}
    {view && !lead && (
     <Card bodyClass={false} ariaLabel="No open incident"><EmptyState icon="check" title="No incident is open" testId="home-calm">Nothing in the selected projects is waiting for the team. Window {formatNs(context.start, context.timezone)} to {formatNs(context.end, context.timezone)}.</EmptyState></Card>
    )}
    <div className="grid-2">
     <div className="col g12">
      {view && <NeedsAction entries={view.entries} context={context} />}
      <JobsPanel context={context} />
      <DataHealthPanel state={services} names={names} />
     </div>
     <div className="col g12">
      <ServicesPanel state={services} />
      <ErrorChanges context={context} />
     </div>
    </div>
   </Content>
  </>
 );
}
