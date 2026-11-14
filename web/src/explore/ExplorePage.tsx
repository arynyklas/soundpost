// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { formatExpression, query, stateOfQueryFault } from '../api/client';
import { ApiFault, QueryFault, type Diagnostic, type FormatResult, type LiveTicketRequest, type LoadState, type ProjectResult, type QueryLanguage, type QueryRequest, type QueryResult, type SourceRange } from '../api/types';
import { latestOnly, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { Discovery } from './Discovery';
import { Exemplars } from './Exemplars';
import { ExportPanel } from './ExportPanel';
import { MAX_BODY_BYTES, buildLiveRequest, buildQueryRequest, defaultForm, type QueryForm } from './form';
import { LiveLogView } from './LiveLogView';
import { LogResult } from './LogResult';
import { MetricResult, TimeText } from './MetricResult';
import { elapsedText, nsToIso, projectState, resultState, splitByRuneRange } from './model';
import { featureSetId, profileById, profilesFor } from './profiles';
import { runLatest, type RunState } from './runner';
import { SavedViews } from './SavedViews';

const FAULT_WORDS: Record<string, string> = {
 quota: 'Quota exceeded. The query was refused rather than shortened, so nothing was returned. Narrow the query or the time window; for log queries set a log page size.',
 timeout: 'The query timed out before it finished. Nothing was returned.',
 cancelled: 'The query was cancelled. Nothing was returned.',
 stale: 'The data the query needed was deleted, or is older than required, while it ran. The query was refused and nothing was returned.',
 invalid: 'The server rejected the request as invalid. Nothing was run.',
 too_large: 'The request is too large for the server. Nothing was run.',
 unavailable: 'A dependency was unavailable. Nothing was returned.',
 conflict: 'The request conflicts with the current state. Nothing was returned.',
};

/** The query text with the failing part marked by rune range. The mark is text plus a stated range, never colour alone. */
function Marked(props: { text: string; range: SourceRange | null | undefined }): React.JSX.Element {
 const cut = props.range ? splitByRuneRange(props.text, props.range.start_rune, props.range.end_rune) : null;
 return (
  <>
   <pre className="expr" data-testid="expression-marked" tabIndex={0} aria-label="Query text with the failing part marked">{cut === null ? props.text : <>{cut.before}<mark data-testid="expression-mark">{cut.hit === '' ? '⌴' : cut.hit}</mark>{cut.after}</>}</pre>
   {props.range ? <p data-testid="expression-range">The marked part is characters {props.range.start_rune} to {props.range.end_rune} (bytes {props.range.start_byte} to {props.range.end_byte}).</p> : null}
  </>
 );
}

export function FaultView(props: { state: LoadState<unknown>; expression: string }): React.JSX.Element {
 const { state } = props;
 if (state.kind !== 'error') return <StatusPanel state={state} />;
 const f = state.fault;
 const language = f instanceof QueryFault ? f.language : null;
 return (
  <div className="status status-error" role="alert" data-state="error" data-code={f.code} aria-live="assertive">
   {language !== null
    ? (
     <>
      <strong>Language error.</strong> <span data-testid="language-detail">{language.detail}</span>
      <span> Category <code>{language.category}</code>{language.languageCode !== '' ? <>, code <code>{language.languageCode}</code></> : null}.</span>
      <Marked text={props.expression} range={language.range} />
     </>
    )
    : <><strong>Error ({f.code}).</strong> <span data-testid="fault-words">{FAULT_WORDS[f.code] ?? 'The request failed. Nothing was returned.'}</span></>}
   {f.requestId !== '' && <span> Request <code>{f.requestId}</code>.</span>}
  </div>
 );
}

export function DiagnosticList(props: { diagnostics: Diagnostic[]; expression: string }): React.JSX.Element | null {
 if (props.diagnostics.length === 0) return null;
 return (
  <ul className="diagnostics" aria-label="Diagnostics" data-testid="diagnostics">
   {props.diagnostics.map((d, i) => {
    const cut = d.source_range ? splitByRuneRange(props.expression, d.source_range.start_rune, d.source_range.end_rune) : null;
    return (
     <li key={i} data-severity={d.severity} data-code={d.code}>
      <strong>{d.severity === 'warning' ? 'Warning' : 'Note'}:</strong> {d.safe_message} (<code>{d.code}</code>)
      {d.source_range && cut !== null && <> at characters {d.source_range.start_rune} to {d.source_range.end_rune}: <mark>{cut.hit}</mark></>}
     </li>
    );
   })}
  </ul>
 );
}

function ProjectPanel(props: { result: ProjectResult; request: QueryRequest }): React.JSX.Element {
 const { result: pr, request } = props;
 const state = projectState(pr);
 const reason = state.kind === 'incomplete' || state.kind === 'stale' ? state.reason : '';
 const headingId = `project-${pr.project_id}`;
 return (
  <section className="panel project-panel" aria-labelledby={headingId} data-project={pr.project_id} data-state={state.kind} data-completeness={pr.completeness}>
   <h3 id={headingId}>Project <code>{pr.project_id}</code></h3>
   <p className="project-state" data-testid="project-state">
    {state.kind === 'ready' && <><strong>Complete.</strong> Every shard answered.</>}
    {state.kind === 'empty' && <><strong>Complete and empty.</strong> Nothing matched in this window. Nothing is missing.</>}
    {state.kind === 'incomplete' && <><strong>Partial.</strong> {reason === 'project_failed' ? 'This project produced no value; it is not an empty or zero result.' : 'Some data did not answer. Missing data is not zero.'}</>}
    {state.kind === 'stale' && <><strong>Stale.</strong> The newest data is older than expected.</>}
   </p>
   {pr.failure && (
    <div role="alert" className="error" data-testid="project-failure" data-code={pr.failure.code}>
     Failure <code>{pr.failure.code}</code>{pr.failure.category ? <>, category <code>{pr.failure.category}</code></> : null}: {pr.failure.safe_message}
     {pr.failure.source_range ? <Marked text={request.expression} range={pr.failure.source_range} /> : null}
    </div>
   )}
   <DiagnosticList diagnostics={pr.diagnostics} expression={request.expression} />
   {pr.stats.limit_reached && <p role="status" className="banner banner-warning" data-testid="limit-reached"><strong>Log page limit reached.</strong> More log entries exist than the {request.log_limit ?? 'requested'} entries on this page. This is the first part of the complete ordered result, not all of it.</p>}
   {pr.value !== null && (pr.value.type === 'streams' ? <LogResult result={pr} /> : <MetricResult result={pr} evaluation={request.evaluation} />)}
   <dl className="scope-bar" aria-label="Project statistics">
    <dt>Freshness</dt>
    <dd>{pr.watermarks.length === 0 ? 'No stored data was read (a literal result).' : <details><summary>{pr.watermarks.length} shard cursors were read through</summary><ul className="cursor-list">{pr.watermarks.map((w) => <li key={w.group}><code>{w.group}:{w.index}</code></li>)}</ul></details>}</dd>
    <dt>Work done</dt>
    <dd>{pr.stats.rows_read} rows read in {pr.stats.pages_read} pages ({pr.stats.bytes_read} bytes), {pr.stats.series_returned} series, {pr.stats.samples_returned} samples, {pr.stats.logs_returned} logs returned, peak memory {pr.stats.peak_memory_bytes} bytes, {elapsedText(pr.stats.elapsed_ns)}{pr.stats.cached ? ', served from the result cache' : ''}</dd>
   </dl>
  </section>
 );
}

const featuresLabel = (features: string[]): string => (features.length === 0 ? 'no optional features' : features.join(', '));

/** What was actually asked, kept with the result it produced, so changing the form never relabels an answer. */
interface RunView { key: string; request: QueryRequest; features: string[]; state: LoadState<QueryResult>; id: number }

function ExploreBody(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const scope = `${scopeKey(context)}|${context.generation}`;
 const [form, setForm] = React.useState<QueryForm>(() => defaultForm(context, 'promql'));
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

 const profile = profileById(form.profileId);
 const featureSet = profile === undefined ? null : featureSetId(profile, form.features);
 const set = (over: Partial<QueryForm>): void => setForm((f) => ({ ...f, ...over }));
 const bodyBytes = new TextEncoder().encode(form.expression).length;

 const chooseLanguage = (language: QueryLanguage): void => set({ language, profileId: profilesFor(language)[0]?.id ?? '', features: [], mode: language === 'logql' ? 'range' : form.mode, source: language === 'promql' ? '' : form.source });
 const toggleFeature = (name: string): void => set({ features: form.features.includes(name) ? form.features.filter((f) => f !== name) : [...form.features, name] });
 const toggleProject = (id: string): void => set({ projects: form.projects.includes(id) ? form.projects.filter((p) => p !== id) : context.projects.filter((p) => p === id || form.projects.includes(p)) });

 const execute = (): void => {
  const built = buildQueryRequest(context, form);
  if (!built.ok) { setProblems(built.problems); return; }
  setProblems([]);
  const request = built.request;
  const features = form.features;
  const id = ++runCounter.current;
  void runLatest(latest.current, () => scopeRef.current, scope, (signal) => query(request, signal), (s: RunState<QueryResult>) => {
   if (s.kind === 'loading') setRun({ key: scope, request, features, state: { kind: 'loading' }, id });
   else if (s.kind === 'done') setRun({ key: scope, request, features, state: resultState(s.value), id });
   else setRun({ key: scope, request, features, state: stateOfQueryFault(s.error), id });
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
 const live = buildLiveRequest(context, form);
 const fmt = formatted !== null && formatted.key === scope ? formatted.state : null;
 const running = view?.state.kind === 'loading';
 const data = view !== null && 'data' in view.state ? view.state.data : undefined;
 return (
  <section className="panel" aria-labelledby="view-heading" data-section="explore">
   <h2 id="view-heading">Explore</h2>
   <p>Full PromQL and LogQL under the pinned language profiles, evaluated by Soundpost&rsquo;s own engine in your scope. The query text stays in this page&rsquo;s memory: it is sent in a POST body only, never placed in a URL, history, storage or a log, and it is gone when you leave the page.</p>
   <form className="explore-form" aria-label="Query" onSubmit={(e) => { e.preventDefault(); execute(); }}>
    <fieldset>
     <legend>Language and profile</legend>
     <div className="field-row">
      <label className="check"><input type="radio" name="language" checked={form.language === 'promql'} onChange={() => chooseLanguage('promql')} />PromQL</label>
      <label className="check"><input type="radio" name="language" checked={form.language === 'logql'} onChange={() => chooseLanguage('logql')} />LogQL</label>
      <label>Pinned profile <select value={form.profileId} onChange={(e) => set({ profileId: e.target.value, features: [] })}>{profilesFor(form.language).map((p) => <option key={p.id} value={p.id}>{p.id}</option>)}</select></label>
     </div>
     {profile !== undefined && profile.features.length > 0 && (
      <fieldset>
       <legend>Registered features ({profile.features.length}); the profile registers a feature set for every combination</legend>
       {profile.features.map((name) => <label className="check" key={name}><input type="checkbox" checked={form.features.includes(name)} onChange={() => toggleFeature(name)} />{name}</label>)}
      </fieldset>
     )}
     <p data-testid="feature-set">Feature set sent: {featureSet === null ? <strong>none registered for this combination</strong> : <code>{featureSet}</code>} ({featuresLabel(form.features)}). The profile is never switched for you.</p>
    </fieldset>
    <label>Query expression
     <textarea value={form.expression} onChange={(e) => set({ expression: e.target.value })} rows={6} spellCheck={false} autoComplete="off" autoCapitalize="off" className="expr-input" aria-describedby="expr-help"
      onKeyDown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); execute(); } }} />
    </label>
    <p id="expr-help" className="muted">{bodyBytes} bytes of the {MAX_BODY_BYTES}-byte request limit. Press Ctrl+Enter to run.</p>
    <fieldset>
     <legend>Evaluation</legend>
     <div className="field-row">
      <label className="check"><input type="radio" name="mode" checked={form.mode === 'instant'} onChange={() => set({ mode: 'instant' })} />Instant</label>
      <label className="check"><input type="radio" name="mode" checked={form.mode === 'range'} onChange={() => set({ mode: 'range' })} />Range over the selected window</label>
      {form.mode === 'instant'
       ? <label>Evaluation time (nanoseconds since the epoch) <input value={form.instantTime} onChange={(e) => set({ instantTime: e.target.value })} inputMode="numeric" autoComplete="off" /><span>{/^(0|[1-9][0-9]{0,18})$/.test(form.instantTime) ? nsToIso(form.instantTime) : 'not a whole number of nanoseconds'}</span></label>
       : <label>Step (seconds) <input value={form.stepSeconds} onChange={(e) => set({ stepSeconds: e.target.value })} inputMode="numeric" autoComplete="off" /></label>}
     </div>
    </fieldset>
    <fieldset>
     <legend>Projects (each is evaluated on its own and shown in its own panel; nothing is merged)</legend>
     {context.projects.map((p) => <label className="check" key={p}><input type="checkbox" checked={form.projects.includes(p)} onChange={() => toggleProject(p)} /><code>{p}</code></label>)}
    </fieldset>
    <fieldset>
     <legend>Budget and results</legend>
     <div className="field-row">
      <label>Result budget (most samples or log entries, whole number) <input value={form.maxReturned} onChange={(e) => set({ maxReturned: e.target.value })} inputMode="numeric" autoComplete="off" /></label>
      {form.language === 'logql' && <label>Log page size (empty: none; a larger result is refused) <input value={form.logLimit} onChange={(e) => set({ logLimit: e.target.value })} inputMode="numeric" autoComplete="off" /></label>}
      {form.language === 'logql' && <label>Log order <select value={form.logOrder} onChange={(e) => set({ logOrder: e.target.value === 'forward' ? 'forward' : 'backward' })}><option value="backward">Newest first</option><option value="forward">Oldest first</option></select></label>}
      {form.language === 'logql' && <label>Restricted source ID (raw.read, one project; empty for ordinary telemetry) <input value={form.source} onChange={(e) => set({ source: e.target.value })} autoComplete="off" spellCheck={false} /></label>}
     </div>
     <label className="check"><input type="checkbox" checked={form.allowPartial} onChange={(e) => set({ allowPartial: e.target.checked })} />Allow partial results. Without this, any missing data or failed project refuses the whole query instead of showing a part.</label>
    </fieldset>
    {problems.length > 0 && <ul role="alert" className="error" data-testid="form-problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
    <div className="field-row">
     <button type="submit" className="primary" disabled={running}>Run query</button>
     <button type="button" onClick={format}>Format expression</button>
     {running && <button type="button" onClick={cancel}>Cancel the running query</button>}
    </div>
   </form>
   {fmt !== null && (
    <div data-testid="format-result">
     {fmt.kind === 'ready'
      ? (
       <>
        <p>Formatted text (it parses to the same typed tree):</p>
        <pre className="expr" data-testid="formatted-text">{fmt.data.formatted}</pre>
        <button type="button" onClick={() => { set({ expression: fmt.data.formatted }); setFormatted(null); }}>Replace the expression with the formatted text</button>
       </>
      )
      : fmt.kind === 'loading' ? <p role="status">Formatting…</p> : <FaultView state={fmt} expression={form.expression} />}
    </div>
   )}
   <section aria-labelledby="results-heading" className="results" data-testid="results">
    <h3 id="results-heading" tabIndex={-1} ref={heading}>Result</h3>
    {run !== null && run.key !== scope && <p role="status">The selection was refreshed. Run the query again for the new selection.</p>}
    {view === null && (run === null || run.key === scope) && <p role="status" data-state="idle">No query has been run yet. Nothing is shown.</p>}
    {view !== null && (
     <p className="muted" data-testid="evaluated-with">
      Evaluated by the owned engine with profile <code>{view.request.profile}</code> and feature set <code>{view.request.feature_set}</code> ({featuresLabel(view.features)}); {view.request.evaluation.instant
       ? <>instant at <TimeText ns={view.request.evaluation.time} /></>
       : <>range <TimeText ns={view.request.evaluation.start} /> to <TimeText ns={view.request.evaluation.end} /> (end excluded), step {String(BigInt(view.request.evaluation.step) / 1_000_000_000n)} s</>}; partial results {view.request.allow_partial ? 'allowed' : 'not allowed'}; budget {view.request.budget.max_returned} samples or entries.
     </p>
    )}
    {view !== null && view.state.kind === 'loading' && <p role="status" data-state="loading">Running the query…</p>}
    {view !== null && view.state.kind !== 'loading' && data === undefined && <FaultView state={view.state} expression={view.request.expression} />}
    {view !== null && data !== undefined && (
     <>
      <StatusPanel state={view.state} />
      {data.projects.map((pr) => <ProjectPanel key={pr.project_id} result={pr} request={view.request} />)}
     </>
    )}
   </section>
   <Discovery context={context} language={form.language} projects={form.projects} source={form.source} onInsert={(text) => set({ expression: form.expression + text })} />
   <Exemplars context={context} language={form.language} projects={form.projects} profile={form.profileId} featureSet={featureSet ?? ''} expression={form.expression} />
   <section className="panel" aria-labelledby="live-section-heading">
    <h3 id="live-section-heading">Live tail</h3>
    {liveRequest !== null
     ? (
      <>
       <LiveLogView request={liveRequest} context={context} />
       <button type="button" onClick={() => setLiveRequest(null)}>Close the live log view</button>
      </>
     )
     : live.ok
      ? <button type="button" onClick={() => setLiveRequest(live.request)}>Open the live log view for this query</button>
      : <p role="status" data-testid="live-unavailable">{live.problems.join(' ')}</p>}
   </section>
   <ExportPanel context={context} />
   <SavedViews context={context} />
  </section>
 );
}

/** The Explore view. Everything it holds (form, results, live stream) belongs to the selected scope and is dropped with it. */
export function ExplorePage(props: { context: ViewContext }): React.JSX.Element {
 return <ExploreBody key={scopeKey(props.context)} context={props.context} />;
}
