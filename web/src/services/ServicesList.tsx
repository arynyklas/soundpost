// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { investigate } from '../api/client';
import { getRed } from '../api/console';
import type { VisibleService } from '../api/types';
import { latestOnly, requestFor, scopeKey, useInvestigation, type Latest, type ViewContext } from '../app/context';
import { SectionList, StatusPanel } from '../app/StatusPanel';
import { projectLabel, type Names, type ShellApi } from '../shell/ShellContext';
import { Sparkline } from '../ui/chart/Chart';
import { Callout, Card, DataTable, EmptyState, FilterChips, Pill, type Column } from '../ui/primitives';
import { Icon } from '../ui/Icon';
import { MoreNote } from './ServicePage';
import { HEALTH_FILTERS, SERVICE_PROBE_LIMIT, countsByHealth, filterServices, healthPill, healthReason, orderServices, redCell, samplesOf, windowMs, wordOfProbe, type ServiceHealthWord, type ServiceRowModel } from './model';

interface Probe { word: ServiceHealthWord; health: ServiceRowModel['health']; red: ServiceRowModel['red'] }

/** Reads the health and the RED figures of the first services of the list, one service at a time of the server's answer; the answer of an older scope never paints a newer one. A service whose health read failed is `Unknown`, one whose health is not stated is `Not assessed`. */
function useProbes(context: ViewContext, services: readonly VisibleService[]): ReadonlyMap<string, Probe> {
 const ids = services.slice(0, SERVICE_PROBE_LIMIT).map((s) => `${s.project_id}:${s.id}`).join(',');
 const key = `${scopeKey(context)}|${context.generation}|${ids}`;
 const [held, setHeld] = React.useState<{ key: string; probes: ReadonlyMap<string, Probe> }>({ key: '', probes: new Map() });
 const latest = React.useRef<Latest>(latestOnly());
 React.useEffect(() => {
  const probe = services.slice(0, SERVICE_PROBE_LIMIT);
  if (probe.length === 0) { latest.current.stop(); return; }
  const read = latest.current.begin();
  const win = { start: context.start, end: context.end };
  Promise.all(probe.map(async (s): Promise<[string, Probe]> => {
   const [view, red] = await Promise.allSettled([
    investigate({ ...requestFor(context, 'service', s.id), projects: [s.project_id] }, read.signal),
    getRed({ org: context.org, projects: [s.project_id], service: s.id, ...(context.environment !== '' ? { environment: context.environment } : {}), window: win }, read.signal),
   ]);
   const word = wordOfProbe(view.status === 'fulfilled' ? { kind: 'view', view: view.value } : { kind: 'failed' });
   const redState: ServiceRowModel['red'] = red.status !== 'fulfilled' ? 'failed' : red.value.kind === 'ok' ? red.value.data : red.value.kind === 'not_built' ? 'not_built' : 'failed';
   return [`${s.project_id}:${s.id}`, { word, health: view.status === 'fulfilled' ? view.value.health : undefined, red: redState }];
  })).then((entries) => { if (read.current()) setHeld({ key, probes: new Map(entries) }); });
  return () => latest.current.stop();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return held.key === key ? held.probes : new Map();
}

/** The services as a table: health in words and why, open incidents, and the RED figures when this installation serves them. */
export function ServiceTable(props: { rows: readonly ServiceRowModel[]; context: ViewContext; names: Names; href: ShellApi['href']; open: (id: string) => void }): React.JSX.Element {
 const { context, names, href } = props;
 const win = windowMs({ start: context.start, end: context.end });
 const columns: Column<ServiceRowModel>[] = [
  {
   key: 'service', header: 'Service', cell: ({ service: s }) => (
    <div className="cell-title">
     <a className="a mono" href={href('services', { service: s.id })} aria-label={`Open service ${s.id}`} onClick={(e) => { if (!e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) { e.preventDefault(); props.open(s.id); } }}>{s.id}</a>
     <span className="s row wrap g4"><span>{projectLabel(names, s.project_id)}</span><span aria-hidden="true">·</span>{s.environments.length === 0 ? <span>no environment declared</span> : s.environments.map((e) => <code key={e}>{e}</code>)}</span>
    </div>
   ),
  },
  {
   key: 'health', header: 'Health', cell: (r) => {
    const p = healthPill(r.word);
    return <div className="col g4"><Pill tone={p.tone} icon={p.icon} state={r.word}>{p.text}</Pill><span className="xsmall t3">{healthReason(r.word, r.health)}</span></div>;
   },
  },
  { key: 'incidents', header: 'Open incidents', align: 'right', cell: (r) => (r.health ? (r.health.incidents.length > 0 ? <a href={href('incidents')} className="num">{r.health.incidents.length}</a> : <span className="num">0</span>) : <span className="xsmall t3">not available</span>) },
  { key: 'p99', header: 'P99', align: 'right', cell: (r) => { const c = redCell(r.red, 'p99'); return <span className={c.figure ? 'num' : 'xsmall t3'}>{c.text}</span>; } },
  { key: 'errors', header: 'Errors', align: 'right', cell: (r) => { const c = redCell(r.red, 'errors'); return <span className={c.figure ? 'num' : 'xsmall t3'}>{c.text}</span>; } },
  { key: 'rate', header: 'Throughput', align: 'right', cell: (r) => { const c = redCell(r.red, 'rate'); return <span className={c.figure ? 'num' : 'xsmall t3'}>{c.text}</span>; } },
  {
   key: 'trend', header: 'Errors over the window', xlOnly: true, cell: (r) => (typeof r.red === 'object' && r.red.errors.state === 'ready' && r.red.errors.points.length > 0
    ? <Sparkline label={`Error ratio of service ${r.service.id} over the window`} samples={samplesOf(r.red.errors.points)} start={win.start} end={win.end} tone="crit" />
    : <span className="xsmall t3">no samples</span>),
  },
 ];
 return (
  <DataTable
   label="Services admitted by the active source policies" caption="Services admitted by the active source policies, by health, open incidents and RED figures." rows={props.rows} rowKey={(r) => `${r.service.project_id}:${r.service.id}`} columns={columns}
   rowAttrs={(r) => ({ 'data-testid': 'service-row', 'data-service': r.service.id, 'data-project': r.service.project_id, 'data-health': r.word })}
  />
 );
}

/** The services the active source policies admit (D9: there is no separate registry). Health comes only from stored incidents and conditions; RED figures only when this installation serves them. */
export function ServiceList(props: { context: ViewContext; names: Names; href: ShellApi['href']; open: (id: string) => void }): React.JSX.Element {
 const { context } = props;
 const state = useInvestigation(context, 'service');
 const view = 'data' in state ? state.data : undefined;
 const services = view?.services ?? [];
 const probes = useProbes(context, services);
 const [filter, setFilter] = React.useState<ServiceHealthWord | 'all'>('all');
 const [text, setText] = React.useState('');
 const rows: ServiceRowModel[] = orderServices(services.map((s, i) => {
  const p = probes.get(`${s.project_id}:${s.id}`);
  if (p) return { service: s, word: p.word, health: p.health, red: p.red };
  return i < SERVICE_PROBE_LIMIT ? { service: s, word: 'reading', health: undefined, red: 'reading' } : { service: s, word: 'not_assessed', health: undefined, red: 'not_read' };
 }));
 const shown = filterServices(rows, filter, text);
 const counts = countsByHealth(rows);
 return (
  <>
   <StatusPanel state={state} />
   {view && (
    <>
     {services.length === 0
      ? <Card bodyClass={false} ariaLabel="Services"><EmptyState icon="box" title="No service" testId="service-list-empty">No active source policy of the selected projects admits a service{context.environment ? ' in the selected environment' : ''}.</EmptyState></Card>
      : (
       <>
        <div className="row wrap">
         <div className="searchbar grow">
          <Icon name="search" size="s" />
          <input name="filter" aria-label="Filter services by ID or environment" placeholder="Filter services" value={text} onChange={(e) => setText(e.target.value)} autoComplete="off" spellCheck={false} maxLength={80} />
         </div>
         <FilterChips<ServiceHealthWord | 'all'> label="Health" value={filter} options={HEALTH_FILTERS.map((o) => ({ ...o, count: counts[o.value] }))} onChange={setFilter} />
        </div>
        <Card bodyClass={false} ariaLabel="Services">
         {shown.length === 0
          ? <EmptyState icon="box" title="No service matches" testId="service-filter-empty">No listed service matches this filter.</EmptyState>
          : <ServiceTable rows={shown} context={context} names={props.names} href={props.href} open={props.open} />}
         <div className="card-foot">
          <span>A service exists here while an active source policy of a selected project lists it among the services it admits.{services.length > SERVICE_PROBE_LIMIT ? ` Health and RED figures were read for the first ${SERVICE_PROBE_LIMIT} of ${services.length} services; the others are not assessed here.` : ''}</span>
         </div>
        </Card>
       </>
      )}
     <Card title="Evidence by project" titleId="svc-projects-h">
      <div className="col g4">
       {view.projects.map((p) => (
        <p key={p.project_id} data-project={p.project_id}>Project <code>{p.project_id}</code>: {p.sources.length === 0 ? 'no readable source' : `${p.sources.length} readable source${p.sources.length === 1 ? '' : 's'}`}.</p>
       ))}
      </div>
     </Card>
     <MoreNote view={view} />
     {counts.unknown > 0 && <Callout tone="unk" role="status">The health of {counts.unknown} service{counts.unknown === 1 ? '' : 's'} could not be read. {counts.unknown === 1 ? 'It is' : 'They are'} not shown as healthy.</Callout>}
     <Card title="Parts of this view" titleId="svc-parts-h"><SectionList sections={view.sections} /></Card>
    </>
   )}
  </>
 );
}
