// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getRed, type RedView } from '../api/console';
import type { HealthStatus, Id, ServiceHealth, VisibleService } from '../api/types';
import { useConsoleRead } from '../api/useConsoleRead';
import { formatNs, useInvestigation, type ViewContext } from '../app/context';
import { SectionList, StatusPanel } from '../app/StatusPanel';
import { countText } from '../issues/listModel';
import { Section } from '../issues/Section';
import { Content, Hero, PageHead, Tools } from '../shell/Frames';
import { projectLabel, type Names, type ShellApi } from '../shell/ShellContext';
import { LineChart } from '../ui/chart/Chart';
import { Icon } from '../ui/Icon';
import { Callout, Card, NotAvailable, Pill, SeverityIcon, shortId, type Severity } from '../ui/primitives';
import { dependencyNames, durationMs, gapsOf, healthPill, partWord, percent, perSecond, redReasonText, samplesOf, windowMs } from './model';

type Href = ShellApi['href'];

const HEALTH_WORDS: Record<HealthStatus, string> = {
 healthy: 'Healthy: no open incident is linked to this service and no active condition names it.',
 degraded: 'Degraded: no open incident is linked to this service, but at least one active condition names it.',
 failing: 'Failing: at least one open incident is linked to this service.',
};

/** The investigation reads one page of metric names; when the server says more exist, the page says its list is only the first page. */
export function MoreNote(props: { view: { more: boolean; metric_names: string[] } }): React.JSX.Element | null {
 if (!props.view.more) return null;
 return <p role="status" data-testid="investigate-more">This answer covers only the first {props.view.metric_names.length} metric names of this window; more exist and are not counted or listed here. Open Explore to browse all of them.</p>;
}

const SEVERITIES: readonly Severity[] = ['critical', 'major', 'minor'];
function SeverityMark(props: { severity: string }): React.JSX.Element {
 const known = SEVERITIES.find((s) => s === props.severity);
 return known ? <SeverityIcon severity={known} /> : <Pill tone="unk">{props.severity}</Pill>;
}

function Health(props: { health: ServiceHealth; href: Href }): React.JSX.Element {
 const { health } = props;
 const p = healthPill(health.status);
 return (
  <div data-testid="service-health" data-status={health.status} className="col g12">
   <p className="row"><Pill tone={p.tone} icon={p.icon}>{p.text}</Pill><span>{HEALTH_WORDS[health.status]}</span></p>
   {health.incidents.length > 0 && (
    <div>
     <h3 className="iss-sub">Open incidents</h3>
     <ul className="feed" aria-label="Open incidents linked to this service">
      {health.incidents.map((i) => (
       <li key={`${i.project_id}:${i.incident_id}`} data-testid="health-incident">
        <SeverityMark severity={i.severity} />
        <span className="grow"><a href={props.href('incidents', { incident: { project: i.project_id, id: i.incident_id } })}>Incident {i.incident_id}</a> in project <code>{i.project_id}</code>, severity {i.severity}.</span>
       </li>
      ))}
     </ul>
    </div>
   )}
   {health.conditions.length > 0 && (
    <div>
     <h3 className="iss-sub">Active conditions that name this service</h3>
     <ul className="feed" aria-label="Active conditions that name this service">
      {health.conditions.map((c) => (
       <li key={`${c.project_id}:${c.condition_id}`} data-testid="health-condition">
        <SeverityMark severity={c.severity} />
        <span className="grow">Condition <code>{c.condition_id}</code> in project <code>{c.project_id}</code>: {c.phase}, severity {c.severity}, evidence {c.freshness}.</span>
       </li>
      ))}
     </ul>
    </div>
   )}
   {health.truncated && <p>More evidence exists than is listed here.</p>}
  </div>
 );
}

function Figure(props: { label: string; value: string; unknown?: boolean }): React.JSX.Element {
 return <div className="kpi"><span className="label">{props.label}</span><span className={props.unknown ? 'small t3' : 'value num'}>{props.value}</span></div>;
}

/** The RED figures of one service over the scope's window, from the metrics route when this installation serves it. A bucket or window with no samples is drawn as `no samples`, never as zero; a part that is partial, empty or not available says so in words. */
export function RedBody(props: { red: RedView; timezone: string }): React.JSX.Element {
 const { red } = props;
 const win = windowMs(red.window);
 const gaps = gapsOf(red.gaps);
 const reason = redReasonText(red.reason);
 const drawn = (state: RedView['rate']['state'], count: number): boolean => (state === 'ready' || state === 'incomplete' || state === 'stale') && count > 0;
 const stateText = (state: RedView['rate']['state']): string => (state === 'empty' ? 'No span of this service was read in this window, so there are no samples. That is not zero.' : state === 'not_available' ? 'The server does not state this part.' : reason === '' ? 'This part may be incomplete.' : reason);
 const note = (state: RedView['rate']['state'], what: string): React.JSX.Element => <p className="small t2" data-testid={`red-${what}-state`} data-state={state}><strong>{partWord(state)}.</strong> {stateText(state)}</p>;
 return (
  <div className="col g16" data-testid="red" data-state={red.state}>
   {red.state !== 'ready' && <Callout tone={red.state === 'not_available' ? 'unk' : 'warn'} role="status" testId="red-state"><strong>{partWord(red.state)}.</strong> {reason === '' ? 'These figures may be incomplete.' : reason}</Callout>}
   <div className="kpis" role="group" aria-label="Service figures for the window">
    <Figure label="Requests" value={countText(red.requests)} unknown={red.requests === null} />
    <Figure label="Rate" value={perSecond(red.rate.perSecond)} unknown={red.rate.perSecond === null} />
    <Figure label="Errors" value={percent(red.errors.ratio)} unknown={red.errors.ratio === null} />
    <Figure label="Duration p50" value={durationMs(red.duration.p50Ms)} unknown={red.duration.p50Ms === null} />
    <Figure label="Duration p95" value={durationMs(red.duration.p95Ms)} unknown={red.duration.p95Ms === null} />
    <Figure label="Duration p99" value={durationMs(red.duration.p99Ms)} unknown={red.duration.p99Ms === null} />
   </div>
   <div className="grid-3">
    <Card title="Throughput" titleId="red-rate-h" headingLevel={3} actions={<span className="small t3">requests / s</span>}>
     {drawn(red.rate.state, red.rate.points.length)
      ? <LineChart label="Service throughput in requests per second over the window; buckets with no samples are shown as no samples" series={[{ id: 'rate', name: 'Requests per second', tone: 'c5', samples: samplesOf(red.rate.points) }]} start={win.start} end={win.end} timeZone={props.timezone} format={perSecond} gaps={gaps} height={170} testId="red-rate" />
      : note(red.rate.state, 'rate')}
    </Card>
    <Card title="Error rate" titleId="red-errors-h" headingLevel={3} actions={<span className="small t3">% of requests</span>}>
     {drawn(red.errors.state, red.errors.points.length)
      ? <LineChart label="Share of requests that failed over the window; buckets with no samples are shown as no samples" series={[{ id: 'errors', name: 'Error rate', tone: 'crit', samples: samplesOf(red.errors.points) }]} start={win.start} end={win.end} timeZone={props.timezone} format={(v) => percent(v)} gaps={gaps} height={170} testId="red-errors" />
      : note(red.errors.state, 'errors')}
    </Card>
    <Card title="Duration" titleId="red-duration-h" headingLevel={3} actions={<span className="small t3">per bucket</span>}>
     {drawn(red.duration.state, red.duration.points.length)
      ? <LineChart label="Request duration p50, p95 and p99 per bucket over the window; buckets with no samples are shown as no samples" series={[{ id: 'p50', name: 'p50', tone: 'c1', samples: samplesOf(red.duration.p50Points) }, { id: 'p95', name: 'p95', tone: 'c2', samples: samplesOf(red.duration.p95Points) }, { id: 'p99', name: 'p99', tone: 'crit', samples: samplesOf(red.duration.points) }]} start={win.start} end={win.end} timeZone={props.timezone} format={durationMs} gaps={gaps} height={170} testId="red-duration" />
      : note(red.duration.state, 'duration')}
    </Card>
   </div>
  </div>
 );
}

function RedSection(props: { context: ViewContext; id: Id }): React.JSX.Element {
 const { context } = props;
 const red = useConsoleRead<RedView>(`${context.org}|${context.projects.join(',')}|${context.environment}|${context.start}|${context.end}|${props.id}|${context.generation}|red`, (signal) => getRed({ org: context.org, projects: context.projects, service: props.id, ...(context.environment !== '' ? { environment: context.environment } : {}), window: { start: context.start, end: context.end } }, signal));
 return (
  <section aria-labelledby="red-h" className="col g12">
   <h2 id="red-h">Service metrics: rate, errors, duration</h2>
   {red.state.kind === 'loading' && <StatusPanel state={{ kind: 'loading' }} />}
   {red.state.kind === 'not_built' && <NotAvailable title="Service metrics are not available yet" testId="red-unavailable">This installation does not serve service metrics yet, so no rate, error or duration figure is shown. Nothing is drawn in their place.</NotAvailable>}
   {red.state.kind === 'fault' && <StatusPanel state={red.state.state} />}
   {red.state.kind === 'ok' && <RedBody red={red.state.data} timezone={context.timezone} />}
  </section>
 );
}

function Entry(props: { e: VisibleService; names: Names }): React.JSX.Element {
 const { e } = props;
 return (
  <div data-project={e.project_id}>
   <p>Project <code>{e.project_id}</code> ({projectLabel(props.names, e.project_id)})</p>
   <p>Environments: {e.environments.length === 0 ? 'none declared' : e.environments.map((x) => <code key={x}>{x} </code>)}</p>
   <p>Builds: {e.builds.length === 0 ? 'none declared' : e.builds.map((x) => <code key={x}>{x} </code>)}. Release records for these builds open from Releases with an organization administrator account.</p>
  </div>
 );
}

/** One service as the scoped server answers it. Health comes only from stored incidents and conditions that name the service; dependencies are the names the source policies declare; builds are the builds the policies admit. A part the server cannot state is shown as not available, never as healthy, zero or empty. All values are bounded plain text. */
export function ServicePage(props: { id: Id; context: ViewContext; names: Names; href: Href; footer?: React.ReactNode }): React.JSX.Element {
 const { context, id, names, href } = props;
 const state = useInvestigation(context, 'service', id);
 const view = 'data' in state ? state.data : undefined;
 const entries: VisibleService[] = view?.services ?? [];
 const status = view?.health?.status;
 const pill = status ? healthPill(status) : view ? healthPill('not_assessed') : undefined;
 const incidents = view?.health?.incidents.length ?? 0;
 return (
  <>
   <PageHead crumb={<><a href={href('services')}>Services</a><Icon name="right" size="xs" /><span className="mono">{shortId(id)}</span></>} />
   <Hero>
    <div className="row wrap g12">
     <h1 tabIndex={-1} data-service={id}>Service</h1>
     <span className="mono small t2" title={id}>service {id.slice(0, 4)}…{id.slice(-4)}</span>
     {pill && <Pill tone={pill.tone} icon={pill.icon}>{pill.text}</Pill>}
    </div>
    {view && (
     <div className="row wrap small t2 g12">
      <span>{[...new Set(entries.map((e) => projectLabel(names, e.project_id)))].join(', ') || 'no project admits it'}</span>
      {view.health && <a href={href('incidents')}>{incidents} open incident{incidents === 1 ? '' : 's'}</a>}
     </div>
    )}
   </Hero>
   <Content>
    <StatusPanel state={state} />
    {view && (
     <>
      <Section id="svc-health-h" section="svc-current-health" title="Current health">
       {view.health ? <Health health={view.health} href={href} /> : <p data-testid="service-health-unavailable">The health of this service is not stated (see the health part below).</p>}
      </Section>
      <RedSection context={context} id={id} />
      <div className="grid-2">
       <Section id="svc-deps-h" section="svc-dependencies" title="Dependencies declared by the source policies">
        {entries.every((e) => e.dependencies.length === 0)
         ? <p>No dependency is declared. This says nothing about the dependencies the service calls.</p>
         : <ul className="feed">{dependencyNames(entries).map((d) => <li key={d}><Icon name="box" size="s" /><span className="grow">{d}</span><Pill tone="unk" icon="question">declared · health not stated</Pill></li>)}</ul>}
       </Section>
       <Section id="svc-env-h" section="svc-environments-builds" title="Environments and builds the policies admit">
        {entries.map((e) => <Entry key={e.project_id} e={e} names={names} />)}
       </Section>
      </div>
      <Section id="svc-src-h" section="svc-evidence-sources" title="Evidence sources">
       {view.projects.map((p) => (
        <div key={p.project_id} data-project={p.project_id}>
         <p>Project <code>{p.project_id}</code></p>
         {p.sources.length === 0
          ? <p>No readable source of this service in this project.</p>
          : <ul>{p.sources.map((s) => <li key={s.id}><code>{s.id}</code> — class {s.class}, kinds {s.kinds.join(', ')}{s.replay ? ', replay' : ''}</li>)}</ul>}
        </div>
       ))}
      </Section>
      <Section id="svc-parts-h" section="svc-parts" title="Parts of this view">
       <SectionList sections={view.sections} />
       <MoreNote view={view} />
       {view.freshness && <p>Freshness: {view.freshness.completeness}. Window {formatNs(view.window.start, context.timezone)} to {formatNs(view.window.end, context.timezone)} ({context.timezone}).</p>}
      </Section>
     </>
    )}
    {props.footer !== undefined && <Tools label="Tools: open another service">{props.footer}</Tools>}
   </Content>
  </>
 );
}
