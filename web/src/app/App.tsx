// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { bindSession } from '../api/client';
import type { Id, InvestigationKind } from '../api/types';
import { ExplorePage } from '../explore/ExplorePage';
import { IncidentPage } from '../incidents/IncidentPage';
import { IssuePage } from '../issues/IssuePage';
import { ReleasePage } from '../releases/ReleasePage';
import { TracePage } from '../traces/TracePage';
import { QueuePage } from '../queue/QueuePage';
import { ProjectSettings } from '../settings/ProjectSettings';
import { SessionContext } from '../auth/ElevationDialog';
import { ServicePage } from '../services/ServicePage';
import { MAX_PROJECTS, SECTIONS, decodeHash, encodeHash, formatNs, isId, scopeKey, useInvestigation, validTimezone, windowEndingAt, type IncidentRef, type SectionId, type ViewContext } from './context';
import { SectionList, StatusPanel } from './StatusPanel';

const WINDOWS: readonly { minutes: number; label: string }[] = [{ minutes: 15, label: 'Last 15 minutes' }, { minutes: 60, label: 'Last hour' }, { minutes: 360, label: 'Last 6 hours' }, { minutes: 1440, label: 'Last 24 hours' }];

function ScopeForm(props: { current: ViewContext | null; apply: (next: Omit<ViewContext, 'generation'>) => void }): React.JSX.Element {
 const [org, setOrg] = React.useState(props.current?.org ?? '');
 const [projects, setProjects] = React.useState(props.current?.projects.join(', ') ?? '');
 const [timezone, setTimezone] = React.useState(props.current?.timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone);
 const [minutes, setMinutes] = React.useState(60);
 const [error, setError] = React.useState('');
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  const list = projects.split(/[\s,]+/).filter((p) => p !== '');
  if (!isId(org.trim())) return setError('Organization ID must be 32 lowercase hexadecimal characters.');
  if (list.length === 0 || list.length > MAX_PROJECTS || !list.every(isId) || new Set(list).size !== list.length) return setError(`Enter 1 to ${MAX_PROJECTS} distinct project IDs, each 32 lowercase hexadecimal characters.`);
  if (!validTimezone(timezone.trim())) return setError('Time zone must be a valid IANA name such as UTC or Europe/Berlin.');
  setError('');
  props.apply({ org: org.trim(), projects: list, environment: '', timezone: timezone.trim(), ...windowEndingAt(Date.now(), minutes) });
 };
 return (
  <form onSubmit={submit} aria-label="Select scope" className="scope-form">
   <label>Organization ID <input value={org} onChange={(e) => setOrg(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <label>Project IDs (comma separated) <input value={projects} onChange={(e) => setProjects(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <label>Time zone <input value={timezone} onChange={(e) => setTimezone(e.target.value)} autoComplete="off" spellCheck={false} /></label>
   <label>Window <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>{WINDOWS.map((w) => <option key={w.minutes} value={w.minutes}>{w.label}</option>)}</select></label>
   <button type="submit" className="primary">Apply scope</button>
   {error && <p role="alert" className="error">{error}</p>}
   <p>Selecting a scope is navigation, not access. Every read is authorized by the server for your own account; anything you may not read is shown as not found.</p>
  </form>
 );
}

function ScopeBar(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 return (
  <dl className="scope-bar" aria-label="Current scope">
   <dt>Organization</dt><dd data-testid="visible-org"><code>{c.org}</code></dd>
   <dt>Projects</dt><dd data-testid="visible-projects"><code>{c.projects.join(', ')}</code></dd>
   <dt>Environment</dt><dd>All environments (no environment filter is available yet)</dd>
   <dt>Time zone</dt><dd>{c.timezone}</dd>
   <dt>Window</dt><dd>{formatNs(c.start, c.timezone)} to {formatNs(c.end, c.timezone)} (end excluded)</dd>
  </dl>
 );
}

function KindView(props: { context: ViewContext; kind: InvestigationKind; label: string }): React.JSX.Element {
 const state = useInvestigation(props.context, props.kind);
 const view = 'data' in state ? state.data : undefined;
 return (
  <section className="panel" aria-labelledby="view-heading">
   <h2 id="view-heading">{props.label}</h2>
   <StatusPanel state={state} />
   {view && <SectionList sections={view.sections} />}
  </section>
 );
}

function IncidentEntry(props: { context: ViewContext; incident: IncidentRef | null; open: (ref: IncidentRef) => void }): React.JSX.Element {
 const [project, setProject] = React.useState(props.incident?.project ?? props.context.projects[0] ?? '');
 const [value, setValue] = React.useState(props.incident?.id ?? '');
 const [error, setError] = React.useState('');
 return (
  <div>
   <form aria-label="Open an incident" onSubmit={(e) => { e.preventDefault(); if (!isId(value.trim())) return setError('Incident ID must be 32 lowercase hexadecimal characters.'); setError(''); props.open({ project, id: value.trim() }); }}>
    <label>Project <select value={project} onChange={(e) => setProject(e.target.value)}>{props.context.projects.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
    <label>Incident ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <button type="submit">Open incident</button>
    {error && <p role="alert" className="error">{error}</p>}
   </form>
   {props.incident ? <IncidentPage key={`${props.incident.project}:${props.incident.id}`} id={props.incident.id} project={props.incident.project} context={props.context} /> : <p role="status">Open an incident by its ID, or pick one from the queue.</p>}
  </div>
 );
}

function ServiceEntry(props: { context: ViewContext; service: Id; open: (id: Id) => void }): React.JSX.Element {
 const [value, setValue] = React.useState(props.service);
 const [error, setError] = React.useState('');
 return (
  <div>
   <form aria-label="Open a service" onSubmit={(e) => { e.preventDefault(); if (!isId(value.trim())) return setError('Service ID must be 32 lowercase hexadecimal characters.'); setError(''); props.open(value.trim()); }}>
    <label>Service ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <button type="submit">Open service</button>
    {error && <p role="alert" className="error">{error}</p>}
   </form>
   {props.service ? <ServicePage id={props.service} context={props.context} /> : <KindView context={props.context} kind="service" label="Services" />}
  </div>
 );
}

function TargetEntry(props: { context: ViewContext; noun: 'issue' | 'release' | 'trace'; target: IncidentRef | null; open: (ref: IncidentRef) => void; children: (ref: IncidentRef) => React.JSX.Element }): React.JSX.Element {
 const [project, setProject] = React.useState(props.target?.project ?? props.context.projects[0] ?? '');
 const [value, setValue] = React.useState(props.target?.id ?? '');
 const [error, setError] = React.useState('');
 const Noun = props.noun === 'issue' ? 'Issue' : props.noun === 'release' ? 'Release' : 'Trace';
 const article = props.noun === 'issue' ? 'an issue' : props.noun === 'release' ? 'a release' : 'a trace';
 return (
  <div>
   <form aria-label={`Open ${article}`} onSubmit={(e) => { e.preventDefault(); if (!isId(value.trim())) return setError(`${Noun} ID must be 32 lowercase hexadecimal characters.`); setError(''); props.open({ project, id: value.trim() }); }}>
    <label>Project <select value={project} onChange={(e) => setProject(e.target.value)}>{props.context.projects.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
    <label>{Noun} ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <button type="submit">Open {props.noun}</button>
    {error && <p role="alert" className="error">{error}</p>}
   </form>
   {props.target ? props.children(props.target) : <p role="status">Open {article} by its ID.</p>}
  </div>
 );
}

/** The investigation shell: persistent scope bar, native navigation and one view
 * per section. Scope lives in the URL hash (IDs, nanosecond strings, time zone,
 * section) so back and forward restore it; held data never outlives its scope. */
export function App(): React.JSX.Element {
 const session = React.useContext(SessionContext);
 const generation = React.useRef(0);
 const [nav, setNav] = React.useState(() => decodeHash(window.location.hash, 0));
 const csrf = session?.session.csrf ?? '';
 // Bound during render (an idempotent in-memory assignment) so reads issued by child effects already carry the token.
 bindSession(csrf);
 React.useEffect(() => () => bindSession(''), []);
 React.useEffect(() => {
  const onHash = (): void => { generation.current += 1; setNav(decodeHash(window.location.hash, generation.current)); };
  window.addEventListener('hashchange', onHash);
  return () => window.removeEventListener('hashchange', onHash);
 }, []);
 const go = (context: ViewContext, section: SectionId, service = '', incident: IncidentRef | null = null, target: IncidentRef | null = null): void => {
  const hash = encodeHash(context, section, service, incident, target);
  if (hash === window.location.hash) { generation.current += 1; setNav(decodeHash(hash, generation.current)); } else window.location.hash = hash;
 };
 const context = nav.context;
 const heading = React.useRef<HTMLHeadingElement>(null);
 React.useEffect(() => { heading.current?.focus(); }, [nav.section, context ? scopeKey(context) : '']);
 const section = SECTIONS.find((s) => s.id === nav.section) ?? SECTIONS[0]!;
 return (
  <div className="investigation">
   <h2 tabIndex={-1} ref={heading}>Investigation</h2>
   <ScopeForm current={context} apply={(next) => { generation.current += 1; go({ ...next, generation: generation.current }, nav.section); }} />
   {!context && <p role="status">Select an organization and projects to begin. Nothing is shown until a scope is chosen.</p>}
   {context && (
    <>
     <ScopeBar context={context} />
     <nav aria-label="Investigation sections">
      <ul className="nav-list">
       {SECTIONS.map((s) => <li key={s.id}><a href={encodeHash(context, s.id)} aria-current={s.id === nav.section ? 'page' : undefined}>{s.label}</a></li>)}
      </ul>
     </nav>
     <button onClick={() => go(context, nav.section, nav.service, nav.incident, nav.target)}>Refresh</button>
     {section.id === 'explore' && <ExplorePage context={context} />}
     {section.id === 'settings' && <ProjectSettings context={context} />}
     {section.id === 'queue' && <QueuePage context={context} />}
     {section.id === 'incidents' && <IncidentEntry context={context} incident={nav.incident} open={(ref) => go(context, 'incidents', '', ref)} />}
     {section.id === 'issues' && <TargetEntry context={context} noun="issue" target={nav.target} open={(ref) => go(context, 'issues', '', null, ref)}>{(ref) => <IssuePage key={`${ref.project}:${ref.id}`} id={ref.id} project={ref.project} context={context} />}</TargetEntry>}
     {section.id === 'releases' && <TargetEntry context={context} noun="release" target={nav.target} open={(ref) => go(context, 'releases', '', null, ref)}>{(ref) => <ReleasePage key={`${ref.project}:${ref.id}`} id={ref.id} project={ref.project} context={context} />}</TargetEntry>}
     {section.id === 'traces' && <TargetEntry context={context} noun="trace" target={nav.target} open={(ref) => go(context, 'traces', '', null, ref)}>{(ref) => <TracePage key={`${ref.project}:${ref.id}`} id={ref.id} project={ref.project} context={context} />}</TargetEntry>}
     {section.id === 'services' && <ServiceEntry key={nav.service} context={context} service={nav.service} open={(id) => go(context, 'services', id)} />}
     {section.kind !== null && section.id !== 'services' && section.id !== 'queue' && section.id !== 'incidents' && section.id !== 'issues' && section.id !== 'releases' && section.id !== 'traces' && <KindView context={context} kind={section.kind} label={section.label} />}
    </>
   )}
  </div>
 );
}
