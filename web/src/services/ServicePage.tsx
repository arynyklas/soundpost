// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { HealthStatus, Id, ServiceHealth, VisibleService } from '../api/types';
import { encodeHash, formatNs, useInvestigation, type ViewContext } from '../app/context';
import { SectionList, StatusPanel } from '../app/StatusPanel';

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

/** The services the active source policies admit (D9: there is no separate registry). Each entry opens its own page; nothing here states health. */
export function ServiceList(props: { context: ViewContext; open: (id: Id) => void }): React.JSX.Element {
 const state = useInvestigation(props.context, 'service');
 const view = 'data' in state ? state.data : undefined;
 const services = view?.services ?? [];
 return (
  <section className="panel" aria-labelledby="view-heading">
   <h2 id="view-heading">Services</h2>
   <StatusPanel state={state} />
   {view && (
    <>
     <p>A service exists here while an active source policy of a selected project lists it among the services it admits. Open a service to see its health.</p>
     {services.length === 0
      ? <p data-testid="service-list-empty">No active source policy of the selected projects admits a service{props.context.environment ? ' in the selected environment' : ''}.</p>
      : (
       <table className="data-table" aria-label="Services">
        <caption>Services admitted by the active source policies, by project and service ID.</caption>
        <thead><tr><th scope="col">Service ID</th><th scope="col">Project</th><th scope="col">Environments</th><th scope="col">Action</th></tr></thead>
        <tbody>
         {services.map((s) => (
          <tr key={`${s.project_id}:${s.id}`} data-testid="service-row" data-service={s.id} data-project={s.project_id}>
           <th scope="row"><code>{s.id}</code></th>
           <td><code>{s.project_id}</code></td>
           <td>{s.environments.length === 0 ? 'none declared' : s.environments.map((e) => <code key={e}>{e} </code>)}</td>
           <td><button type="button" onClick={() => props.open(s.id)}>{`Open service ${s.id}`}</button></td>
          </tr>
         ))}
        </tbody>
       </table>
      )}
     {view.projects.map((p) => (
      <p key={p.project_id} data-project={p.project_id}>Project <code>{p.project_id}</code>: {p.sources.length === 0 ? 'no readable source' : `${p.sources.length} readable source${p.sources.length === 1 ? '' : 's'}`}.</p>
     ))}
     <MoreNote view={view} />
     <SectionList sections={view.sections} />
    </>
   )}
  </section>
 );
}

function Health(props: { context: ViewContext; health: ServiceHealth }): React.JSX.Element {
 const { context, health } = props;
 return (
  <div data-testid="service-health" data-status={health.status}>
   <p><strong>{health.status}</strong>. {HEALTH_WORDS[health.status]}</p>
   {health.incidents.length > 0 && (
    <>
     <h4>Open incidents</h4>
     <ul aria-label="Open incidents linked to this service">
      {health.incidents.map((i) => (
       <li key={`${i.project_id}:${i.incident_id}`} data-testid="health-incident">
        <a href={encodeHash(context, 'incidents', '', { project: i.project_id, id: i.incident_id })}>Incident {i.incident_id}</a> in project <code>{i.project_id}</code>, severity {i.severity}.
       </li>
      ))}
     </ul>
    </>
   )}
   {health.conditions.length > 0 && (
    <>
     <h4>Active conditions that name this service</h4>
     <ul aria-label="Active conditions that name this service">
      {health.conditions.map((c) => (
       <li key={`${c.project_id}:${c.condition_id}`} data-testid="health-condition">
        Condition <code>{c.condition_id}</code> in project <code>{c.project_id}</code>: {c.phase}, severity {c.severity}, evidence {c.freshness}.
       </li>
      ))}
     </ul>
    </>
   )}
   {health.truncated && <p>More evidence exists than is listed here.</p>}
  </div>
 );
}

/** One service as the scoped server answers it. Health comes only from stored incidents and conditions that name the service; dependencies
 * are the names the source policies declare; builds are the builds the policies admit. A part the server cannot state is shown as
 * not available, never as healthy, zero or empty. All values are bounded plain text. */
export function ServicePage(props: { id: Id; context: ViewContext }): React.JSX.Element {
 const state = useInvestigation(props.context, 'service', props.id);
 const view = 'data' in state ? state.data : undefined;
 const entries: VisibleService[] = view?.services ?? [];
 return (
  <section className="panel" aria-labelledby="service-heading">
   <h2 id="service-heading">Service <code>{props.id}</code></h2>
   <StatusPanel state={state} />
   {view && (
    <>
     <SectionList sections={view.sections} />
     <h3>Current health</h3>
     {view.health ? <Health context={props.context} health={view.health} /> : <p data-testid="service-health-unavailable">The health of this service is not stated (see the health part above).</p>}
     <h3>Dependencies declared by the source policies</h3>
     {entries.every((e) => e.dependencies.length === 0)
      ? <p>No dependency is declared. This says nothing about the dependencies the service calls.</p>
      : <ul>{[...new Set(entries.flatMap((e) => e.dependencies))].sort().map((d) => <li key={d}><code>{d}</code></li>)}</ul>}
     <h3>Environments and builds the policies admit</h3>
     {entries.map((e) => (
      <div key={e.project_id} data-project={e.project_id}>
       <p>Project <code>{e.project_id}</code></p>
       <p>Environments: {e.environments.length === 0 ? 'none declared' : e.environments.map((x) => <code key={x}>{x} </code>)}</p>
       <p>Builds: {e.builds.length === 0 ? 'none declared' : e.builds.map((x) => <code key={x}>{x} </code>)}. Release records for these builds open from Releases with an organization administrator account.</p>
      </div>
     ))}
     <h3>Evidence sources</h3>
     {view.projects.map((p) => (
      <div key={p.project_id} data-project={p.project_id}>
       <p>Project <code>{p.project_id}</code></p>
       {p.sources.length === 0
        ? <p>No readable source of this service in this project.</p>
        : <ul>{p.sources.map((s) => <li key={s.id}><code>{s.id}</code> — class {s.class}, kinds {s.kinds.join(', ')}{s.replay ? ', replay' : ''}</li>)}</ul>}
      </div>
     ))}
     <MoreNote view={view} />
     {view.freshness && <p>Freshness: {view.freshness.completeness}. Window {formatNs(view.window.start, props.context.timezone)} to {formatNs(view.window.end, props.context.timezone)} ({props.context.timezone}).</p>}
    </>
   )}
  </section>
 );
}
