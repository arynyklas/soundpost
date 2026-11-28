// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { formatExpression, isAbort, profileRegistry, query, stateOfFault, stateOfQueryFault } from '../api/client';
import { ApiFault, type FormatResult, type LiveTicketRequest, type LoadState, type QueryLanguage, type QueryRequest, type QueryResult } from '../api/types';
import { latestOnly, scopeKey, type ViewContext } from '../app/context';
import { ElevationControls, SessionContext } from '../auth/ElevationDialog';
import { StatusPanel } from '../app/StatusPanel';
import { elevationFor } from '../api/elevation';
import { useShell } from '../shell/ShellContext';
import { Callout, Card, Pill, shortId } from '../ui/primitives';
import { Discovery } from './Discovery';
import { Exemplars } from './Exemplars';
import { ExportPanel } from './ExportPanel';
import { MAX_BODY_BYTES, buildLiveRequest, buildQueryRequest, defaultForm, type QueryForm } from './form';
import { LiveLogView } from './LiveLogView';
import { TimeText } from './MetricResult';
import { nsToIso, resultState } from './model';
import { featureSetId, profileById, profilesFor, type ProfileInfo } from './profiles';
import { FaultView, ProjectPanel } from './Results';
import { runLatest, type RunState } from './runner';
import { SavedViews } from './SavedViews';

const featuresLabel = (features: string[]): string => (features.length === 0 ? 'no optional features' : features.join(', '));
export const LANGUAGE_WORD: Record<QueryLanguage, string> = { promql: 'PromQL', logql: 'LogQL' };

/** What was actually asked, kept with the result it produced, so changing the form never relabels an answer. */
interface RunView { key: string; request: QueryRequest; features: string[]; state: LoadState<QueryResult>; id: number; elevated: boolean }

function WorkbenchBody(props: { context: ViewContext; registry: readonly ProfileInfo[]; language: QueryLanguage }): React.JSX.Element {
 const { context, registry, language } = props;
 const session = React.useContext(SessionContext);
 const shell = useShell();
 const scope = `${scopeKey(context)}|${context.generation}`;
 const [form, setForm] = React.useState<QueryForm>(() => defaultForm(context, language, registry));
 const [problems, setProblems] = React.useState<string[]>([]);
 const [run, setRun] = React.useState<RunView | null>(null);
 const [formatted, setFormatted] = React.useState<{ key: string; state: LoadState<FormatResult> } | null>(null);
 const [liveRequest, setLiveRequest] = React.useState<LiveTicketRequest | null>(null);
 const latest = React.useRef(latestOnly());
 const formatLatest = React.useRef(latestOnly());
 const scopeRef = React.useRef(scope);
 scopeRef.current = scope;
 const runCounter = React.useRef(0);
 const heading = React.useRef<HTMLHeadingElement>(null);
 const view = run !== null && run.key === scope ? run : null;
 React.useEffect(() => () => { latest.current.stop(); formatLatest.current.stop(); }, [scope]);
 React.useEffect(() => { if (view !== null && view.state.kind !== 'loading') heading.current?.focus(); }, [view?.id, view?.state.kind]);

 const profile = profileById(registry, form.profileId);
 const featureSet = profile === undefined ? null : featureSetId(profile, form.features);
 const set = (over: Partial<QueryForm>): void => setForm((f) => ({ ...f, ...over }));
 const bodyBytes = new TextEncoder().encode(form.expression).length;
 const toggleFeature = (name: string): void => set({ features: form.features.includes(name) ? form.features.filter((f) => f !== name) : [...form.features, name] });
 const toggleProject = (id: string): void => set({ projects: form.projects.includes(id) ? form.projects.filter((p) => p !== id) : context.projects.filter((p) => p === id || form.projects.includes(p)) });

 const execute = (): void => {
  const built = buildQueryRequest(context, form, registry);
  if (!built.ok) { setProblems(built.problems); return; }
  setProblems([]);
  const request = built.request;
  const features = form.features;
  const id = ++runCounter.current;
  // Whether this read goes out under the elevation is decided where the request is sent (api/elevation.ts withElevation); the same predicate says so here.
  const elevated = elevationFor(session?.elevation ?? null, context.org, Date.now()) !== undefined;
  void runLatest(latest.current, () => scopeRef.current, scope, (signal) => query(request, signal), (s: RunState<QueryResult>) => {
   if (s.kind === 'loading') setRun({ key: scope, request, features, state: { kind: 'loading' }, id, elevated });
   else if (s.kind === 'done') setRun({ key: scope, request, features, state: resultState(s.value), id, elevated });
   else setRun({ key: scope, request, features, state: stateOfQueryFault(s.error), id, elevated });
  });
 };
 const cancel = (): void => {
  latest.current.stop();
  setRun((r) => (r !== null && r.state.kind === 'loading' ? { ...r, state: { kind: 'error', fault: new ApiFault(499, 'cancelled', '', '') } } : r));
 };
 const format = (): void => {
  if (featureSet === null) { setProblems(['Choose a pinned profile and a registered feature set before formatting.']); return; }
  if (form.expression.trim() === '' || form.projects.length === 0) { setProblems(['Enter a query expression and select a project before formatting.']); return; }
  setProblems([]);
  void runLatest(formatLatest.current, () => scopeRef.current, scope, (signal) => formatExpression({ org: context.org, projects: form.projects, language: form.language, profile: form.profileId, feature_set: featureSet, expression: form.expression }, signal), (s) => {
   if (s.kind === 'loading') setFormatted({ key: scope, state: { kind: 'loading' } });
   else if (s.kind === 'done') setFormatted({ key: scope, state: { kind: 'ready', data: s.value } });
   else setFormatted({ key: scope, state: stateOfQueryFault(s.error) });
  });
 };
 const live = buildLiveRequest(context, form, registry);
 const fmt = formatted !== null && formatted.key === scope ? formatted.state : null;
 const running = view?.state.kind === 'loading';
 const data = view !== null && 'data' in view.state ? view.state.data : undefined;
 const nameOf = (id: string): string | undefined => shell.names.projects.get(id);
 // The advanced options open by themselves when they hold a value (a restored saved view), and are never closed under the user.
 const advanced = React.useRef<HTMLDetailsElement>(null);
 const advancedSet = form.features.length > 0 || form.minCursors.trim() !== '' || form.source.trim() !== '';
 React.useEffect(() => { if (advancedSet && advanced.current) advanced.current.open = true; }, [advancedSet]);
 return (
  <div className="exp-bench col g16" data-section="explore" data-language={language}>
   <Card bodyClass="exp-query-card col g12">
    <form className="exp-form col g12" aria-label="Query" onSubmit={(e) => { e.preventDefault(); execute(); }}>
     <div className="exp-bar">
      <label className="exp-expr-label">Query expression
       <textarea value={form.expression} onChange={(e) => set({ expression: e.target.value })} rows={3} spellCheck={false} autoComplete="off" autoCapitalize="off" className="exp-expr-input" aria-describedby="expr-help"
        onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); execute(); } }} />
      </label>
      <div className="exp-bar-actions">
       <button type="submit" className="btn btn-primary" disabled={running} aria-label="Run query">Run query <span className="kbd" aria-hidden="true">Ctrl ↵</span></button>
       <button type="button" className="btn" onClick={format}>Format expression</button>
       {running && <button type="button" className="btn" onClick={cancel}>Cancel the running query</button>}
      </div>
     </div>
     <p id="expr-help" className="small t3">Ctrl+Enter runs the query. {bodyBytes} of {MAX_BODY_BYTES} bytes. The text is sent in the request body only, never in a URL, history, storage or a log.</p>
     <div className="exp-toolbar">
      <span className="row g4"><Pill tone="acc">{LANGUAGE_WORD[language]}</Pill></span>
      <label>Pinned profile <select value={form.profileId} onChange={(e) => set({ profileId: e.target.value, features: [] })}>{profilesFor(registry, form.language).map((p) => <option key={p.id} value={p.id}>{p.id}</option>)}</select></label>
      <fieldset className="exp-seg">
       <legend className="sr-only">Evaluation</legend>
       <label className="check"><input type="radio" name="mode" checked={form.mode === 'instant'} onChange={() => set({ mode: 'instant' })} />Instant</label>
       <label className="check"><input type="radio" name="mode" checked={form.mode === 'range'} onChange={() => set({ mode: 'range' })} />Range over the selected window</label>
      </fieldset>
      {form.mode === 'instant'
       ? <label>Evaluation time <input value={form.instantTime} onChange={(e) => set({ instantTime: e.target.value })} inputMode="numeric" autoComplete="off" aria-describedby="eval-time-help" /><span id="eval-time-help">{/^(0|[1-9][0-9]{0,18})$/.test(form.instantTime) ? nsToIso(form.instantTime) : 'not a whole number of nanoseconds'} · nanoseconds since the epoch</span></label>
       : <label>Step (seconds) <input className="exp-num" value={form.stepSeconds} onChange={(e) => set({ stepSeconds: e.target.value })} inputMode="numeric" autoComplete="off" /></label>}
      <label>Result budget <input className="exp-num" value={form.maxReturned} onChange={(e) => set({ maxReturned: e.target.value })} inputMode="numeric" autoComplete="off" aria-describedby="budget-help" /><span id="budget-help">most samples or log entries</span></label>
      {form.language === 'logql' && <label>Log order <select value={form.logOrder} onChange={(e) => set({ logOrder: e.target.value === 'forward' ? 'forward' : 'backward' })}><option value="backward">Newest first</option><option value="forward">Oldest first</option></select></label>}
      {form.language === 'logql' && <label>Log page size <input className="exp-num" value={form.logLimit} onChange={(e) => set({ logLimit: e.target.value })} inputMode="numeric" autoComplete="off" aria-describedby="page-help" /><span id="page-help">empty: none; a larger result is refused</span></label>}
      <label className="check"><input type="checkbox" checked={form.allowPartial} onChange={(e) => set({ allowPartial: e.target.checked })} aria-describedby="partial-help" />Allow partial results</label>
     </div>
     <p id="partial-help" className="small t3">Without partial results, any missing data or failed project refuses the whole query instead of showing a part.</p>
     <fieldset className="exp-fs exp-projects">
      <legend>Projects <span className="t3">· each is evaluated and shown on its own; nothing is merged</span></legend>
      <div className="exp-fields">
       {context.projects.map((p) => <label className="check" key={p}><input type="checkbox" checked={form.projects.includes(p)} onChange={() => toggleProject(p)} />{nameOf(p) ?? <code aria-hidden="true">{shortId(p)}</code>}<span className="sr-only">{p}</span></label>)}
      </div>
     </fieldset>
     <details className="exp-advanced" ref={advanced}>
      <summary>Advanced query options</summary>
      <div className="col g12">
       {profile !== undefined && profile.features.length > 0 && (
        <fieldset className="exp-fs exp-features">
         <legend>Registered features ({profile.features.length}); the profile registers a feature set for every combination</legend>
         {profile.features.map((name) => <label className="check" key={name}><input type="checkbox" checked={form.features.includes(name)} onChange={() => toggleFeature(name)} />{name}</label>)}
        </fieldset>
       )}
       {form.language === 'logql' && <label>Restricted source ID (raw.read, one project; empty for ordinary telemetry) <input value={form.source} onChange={(e) => set({ source: e.target.value })} autoComplete="off" spellCheck={false} /></label>}
       <label>Minimum data position (optional, one <code>group:index</code> per line, as returned by an ingest receipt); a read that has not reached it is answered stale <textarea value={form.minCursors} onChange={(e) => set({ minCursors: e.target.value })} rows={2} autoComplete="off" spellCheck={false} /></label>
      </div>
     </details>
     <p className="small t2" data-testid="feature-set">Feature set sent: {featureSet === null ? <strong>none registered for this combination</strong> : <code>{featureSet}</code>} ({featuresLabel(form.features)}). The profile is never switched for you.</p>
     {problems.length > 0 && <ul role="alert" className="error" data-testid="form-problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
    </form>
    {fmt !== null && (
     <div data-testid="format-result" className="col g4">
      {fmt.kind === 'ready'
       ? (
        <>
         <p>Formatted text (it parses to the same typed tree):</p>
         <pre className="exp-expr" data-testid="formatted-text">{fmt.data.formatted}</pre>
         <button type="button" className="btn btn-sm" onClick={() => { set({ expression: fmt.data.formatted }); setFormatted(null); }}>Replace the expression with the formatted text</button>
        </>
       )
       : fmt.kind === 'loading' ? <p role="status">Formatting…</p> : <FaultView state={fmt} expression={form.expression} />}
     </div>
    )}
   </Card>

   {session !== null && (session.orgs.length > 0 || session.elevation !== null) && <ElevationControls />}
   <section aria-labelledby="results-heading" className="exp-results col g12" data-testid="results">
    <h2 id="results-heading" tabIndex={-1} ref={heading}>Result</h2>
    {run !== null && run.key !== scope && <p role="status">The selection was refreshed. Run the query again for the new selection.</p>}
    {view === null && (run === null || run.key === scope) && <p role="status" data-state="idle" className="t2">No query has been run yet. Nothing is shown.</p>}
    {view !== null && (
     <p className="small t2" data-testid="evaluated-with">
      Evaluated by the owned engine with profile <code>{view.request.profile}</code> and feature set <code>{view.request.feature_set}</code> ({featuresLabel(view.features)}); {view.request.evaluation.instant
       ? <>instant at <TimeText ns={view.request.evaluation.time} /></>
       : <>range <TimeText ns={view.request.evaluation.start} /> to <TimeText ns={view.request.evaluation.end} /> (end excluded), step {String(BigInt(view.request.evaluation.step) / 1_000_000_000n)} s</>}; partial results {view.request.allow_partial ? 'allowed' : 'not allowed'}; budget {view.request.budget.max_returned} samples or entries.
     </p>
    )}
    {view !== null && view.elevated && data !== undefined && <Callout tone="info" role="status" testId="elevated-read"><strong>Audited elevated read.</strong> This answer was produced under your scoped instance elevation for organization <code>{view.request.org}</code>; the server committed an audit record before returning it. The elevation ends after fifteen minutes, and on navigation or when the window regains focus.</Callout>}
    {view !== null && view.state.kind === 'loading' && <p role="status" data-state="loading">Running the query…</p>}
    {view !== null && view.state.kind !== 'loading' && data === undefined && <FaultView state={view.state} expression={view.request.expression} />}
    {view !== null && data !== undefined && (
     <>
      <StatusPanel state={view.state} />
      {data.projects.map((pr) => { const name = nameOf(pr.project_id); return <ProjectPanel key={pr.project_id} result={pr} request={view.request} timeZone={context.timezone} {...(name !== undefined ? { name } : {})} />; })}
     </>
    )}
   </section>

   {language === 'logql' && (
    <Card title="Live tail" titleId="live-section-heading">
     {liveRequest !== null
      ? (
       <div className="col g12">
        <LiveLogView request={liveRequest} context={context} />
        <button type="button" className="btn btn-sm" onClick={() => setLiveRequest(null)}>Close the live log view</button>
       </div>
      )
      : live.ok
       ? <button type="button" className="btn" onClick={() => setLiveRequest(live.request)}>Open the live log view for this query</button>
       : <p role="status" data-testid="live-unavailable">{live.problems.join(' ')}</p>}
    </Card>
   )}

   <div className={language === 'promql' ? 'grid-2' : 'col g16'}>
    <Discovery context={context} language={form.language} projects={form.projects} source={form.source} onInsert={(text) => set({ expression: form.expression + text })} />
    {language === 'promql' && <Exemplars context={context} projects={form.projects} profile={form.profileId} featureSet={featureSet ?? ''} expression={form.expression} />}
   </div>
   <SavedViews context={context} registry={registry} form={form} onOpen={(patch) => { setProblems([]); set(patch); }} />
   <ExportPanel context={context} />
  </div>
 );
}

/**
 * The query workbench of one language: Metrics (PromQL) and Logs (LogQL) are two screens over this one component. Everything it holds
 * (form, results, live stream) belongs to the selected scope and is dropped with it. The pinned profile registry is read from the server
 * before any form is shown: there is no copied table to fall back to, so a registry that cannot be read is a stated state, never a form
 * that guesses a feature set.
 */
export function Workbench(props: { context: ViewContext; language: QueryLanguage }): React.JSX.Element {
 const [registry, setRegistry] = React.useState<LoadState<ProfileInfo[]>>({ kind: 'loading' });
 React.useEffect(() => {
  const controller = new AbortController();
  profileRegistry(controller.signal).then(
   (profiles) => setRegistry(profiles.length === 0 ? { kind: 'unsupported', reason: 'no_profiles' } : { kind: 'ready', data: profiles }),
   (error: unknown) => { if (!isAbort(error)) setRegistry(stateOfFault(error)); },
  );
  return () => controller.abort();
 }, []);
 if (registry.kind !== 'ready') {
  return (
   <div data-section="explore" data-language={props.language}>
    <StatusPanel state={registry} />
   </div>
  );
 }
 return <WorkbenchBody key={`${props.language}|${scopeKey(props.context)}`} context={props.context} registry={registry.data} language={props.language} />;
}
