// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { bindSession, capabilities, isAbort, stateOfFault } from '../api/client';
import type { Id, InvestigationKind, LoadState, VisibleSource } from '../api/types';
import { SessionContext } from '../auth/ElevationDialog';
import { ServicePage } from '../services/ServicePage';
import { MAX_PROJECTS, SECTIONS, decodeHash, encodeHash, formatNs, isId, scopeKey, useInvestigation, validTimezone, windowEndingAt, type SectionId, type ViewContext } from './context';
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

function Explore(): React.JSX.Element {
 const state: LoadState<never> = { kind: 'unsupported', reason: 'view_not_built' };
 return <section className="panel" aria-labelledby="view-heading"><h2 id="view-heading">Explore</h2><StatusPanel state={state} /></section>;
}

function Settings(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const [held, setHeld] = React.useState<{ key: string; byProject: Record<string, LoadState<VisibleSource[]>> }>({ key: '', byProject: {} });
 const key = `${scopeKey(c)}|${c.generation}`;
 React.useEffect(() => {
  const ctl = new AbortController();
  setHeld({ key, byProject: {} });
  for (const project of c.projects) {
   capabilities(c.org, project, ctl.signal).then(
    (r) => { if (!ctl.signal.aborted) setHeld((h) => h.key === key ? { key, byProject: { ...h.byProject, [project]: r.sources.length ? { kind: 'ready', data: r.sources } : { kind: 'empty', data: [] } } } : h); },
    (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld((h) => h.key === key ? { key, byProject: { ...h.byProject, [project]: stateOfFault(e) } } : h); },
   );
  }
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return (
  <section className="panel" aria-labelledby="view-heading">
   <h2 id="view-heading">Project settings</h2>
   <p>Source capabilities this account may read. A project with no readable source is empty, not unhealthy.</p>
   {c.projects.map((project) => {
    const state: LoadState<VisibleSource[]> = held.key === key ? held.byProject[project] ?? { kind: 'loading' } : { kind: 'loading' };
    return (
     <div key={project} data-project={project}>
      <h3>Project <code>{project}</code></h3>
      <StatusPanel state={state} />
      {'data' in state && state.data.length > 0 && <ul>{state.data.map((s) => <li key={s.id}><code>{s.id}</code> — class {s.class}, kinds {s.kinds.join(', ')}{s.replay ? ', replay' : ''}</li>)}</ul>}
     </div>
    );
   })}
  </section>
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
 const go = (context: ViewContext, section: SectionId, service = ''): void => {
  const hash = encodeHash(context, section, service);
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
     <button onClick={() => go(context, nav.section, nav.service)}>Refresh</button>
     {section.id === 'explore' && <Explore />}
     {section.id === 'settings' && <Settings context={context} />}
     {section.id === 'services' && <ServiceEntry key={nav.service} context={context} service={nav.service} open={(id) => go(context, 'services', id)} />}
     {section.kind !== null && section.id !== 'services' && <KindView context={context} kind={section.kind} label={section.label} />}
    </>
   )}
  </div>
 );
}
