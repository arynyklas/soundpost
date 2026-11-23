// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { QueryFault, type Diagnostic, type EvaluationWire, type LoadState, type ProjectResult, type QueryRequest, type SourceRange } from '../api/types';
import { StatusPanel } from '../app/StatusPanel';
import { Callout, Pill, type Tone } from '../ui/primitives';
import { Icon } from '../ui/Icon';
import { LogResult, type LogContext } from './LogResult';
import { MetricResult } from './MetricResult';
import { elapsedText, projectState, splitByRuneRange, staleShards } from './model';

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
   <pre className="exp-expr" data-testid="expression-marked" tabIndex={0} aria-label="Query text with the failing part marked">{cut === null ? props.text : <>{cut.before}<mark data-testid="expression-mark">{cut.hit === '' ? '⌴' : cut.hit}</mark>{cut.after}</>}</pre>
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
     <div className="col">
      <p><strong>Language error.</strong> <span data-testid="language-detail">{language.detail}</span>
       <span> Category <code>{language.category}</code>{language.languageCode !== '' ? <>, code <code>{language.languageCode}</code></> : null}.</span>
       {f.requestId !== '' && <span> Request <code>{f.requestId}</code>.</span>}</p>
      <Marked text={props.expression} range={language.range} />
     </div>
    )
    : <span><strong>Error ({f.code}).</strong> <span data-testid="fault-words">{FAULT_WORDS[f.code] ?? 'The request failed. Nothing was returned.'}</span>{f.requestId !== '' && <span> Request <code>{f.requestId}</code>.</span>}</span>}
  </div>
 );
}

export function DiagnosticList(props: { diagnostics: Diagnostic[]; expression: string }): React.JSX.Element | null {
 if (props.diagnostics.length === 0) return null;
 return (
  <ul className="exp-diagnostics" aria-label="Diagnostics" data-testid="diagnostics">
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

const PILL: Record<'ready' | 'empty' | 'incomplete' | 'stale', { tone: Tone; word: string }> = {
 ready: { tone: 'ok', word: 'Complete' }, empty: { tone: 'ok', word: 'Complete, empty' }, incomplete: { tone: 'high', word: 'Partial' }, stale: { tone: 'high', word: 'Stale' },
};

/** One project's answer: its own state in words, every diagnostic and failure, the value, and the work that produced it. Projects are never merged. */
export function ProjectPanel(props: { result: ProjectResult; request: QueryRequest; timeZone?: string; name?: string }): React.JSX.Element {
 const { result: pr, request } = props;
 const state = projectState(pr);
 const reason = state.kind === 'incomplete' || state.kind === 'stale' ? state.reason : '';
 const headingId = `project-${pr.project_id}`;
 const behind = state.kind === 'stale' ? staleShards(request.min_cursors, pr.watermarks) : [];
 const pill = PILL[state.kind as keyof typeof PILL] ?? PILL.ready;
 const ev: EvaluationWire | undefined = request.evaluation;
 const log: LogContext | undefined = ev !== undefined && !ev.instant
  ? { window: { start: ev.start, end: ev.end }, order: request.log_order ?? 'backward', timeZone: props.timeZone ?? 'UTC' }
  : undefined;
 return (
  <section className="card exp-project" aria-labelledby={headingId} data-project={pr.project_id} data-state={state.kind} data-completeness={pr.completeness}>
   <div className="card-head">
    <h3 id={headingId}>{props.name !== undefined ? props.name : 'Project'} <code>{pr.project_id}</code></h3>
    <Pill tone={pill.tone} icon={state.kind === 'incomplete' || state.kind === 'stale' ? 'warn' : 'check'}>{state.kind === 'ready' && pr.stats.cached ? 'Complete when computed' : pill.word}</Pill>
   </div>
   <div className="card-body col g12">
    <p className="project-state small" data-testid="project-state">
     {state.kind === 'ready' && (pr.stats.cached
      ? <><strong>Complete when computed.</strong> Every shard had answered then (the computation took {elapsedText(pr.stats.elapsed_ns)}); this answer is served from the result cache and the shards were not asked again.</>
      : <><strong>Complete.</strong> Every shard answered.</>)}
     {state.kind === 'empty' && (pr.stats.cached
      ? <><strong>Complete and empty when computed.</strong> Nothing matched in this window then and nothing was missing; this answer is served from the result cache.</>
      : <><strong>Complete and empty.</strong> Nothing matched in this window. Nothing is missing.</>)}
     {state.kind === 'incomplete' && <><strong>Partial.</strong> {reason === 'project_failed' ? 'This project produced no value; it is not an empty or zero result.' : 'Some data did not answer. Missing data is not zero.'}</>}
     {state.kind === 'stale' && <><strong>Stale.</strong> The newest data is older than expected.</>}
    </p>
    {behind.length > 0 && (
     <div className="callout callout-high exp-stale" role="status" data-testid="stale-detail">
      <Icon name="warn" size="s" />
      <div className="col g4">
       <p>{behind.length === 1 ? 'One shard was' : `${behind.length} shards were`} read through a position older than the minimum you named. The data below is what they held at their own position; newer writes of those shards are not in it, so it is not a current or complete answer and an absent value is not zero.</p>
       <ul data-testid="stale-shards">
        {behind.map((s) => <li key={s.group} data-group={s.group} data-read={s.read ?? 'not read'} data-required={s.required}>Shard <code>{s.group}</code>: {`${s.read === null ? 'not read' : `read through ${s.read}`}, minimum ${s.required}`}</li>)}
       </ul>
      </div>
     </div>
    )}
    {pr.failure && (
     <div role="alert" className="error" data-testid="project-failure" data-code={pr.failure.code}>
      Failure <code>{pr.failure.code}</code>{pr.failure.category ? <>, category <code>{pr.failure.category}</code></> : null}: {pr.failure.safe_message}
      {pr.failure.source_range ? <Marked text={request.expression} range={pr.failure.source_range} /> : null}
     </div>
    )}
    <DiagnosticList diagnostics={pr.diagnostics} expression={request.expression} />
    {pr.stats.limit_reached && <Callout tone="high" role="status" testId="limit-reached"><strong>Log page limit reached.</strong> More log entries exist than the {request.log_limit ?? 'requested'} entries on this page. This is the first part of the complete ordered result, not all of it.</Callout>}
    {pr.value !== null && (pr.value.type === 'streams' ? <LogResult result={pr} {...(log ? { log } : {})} /> : <MetricResult result={pr} evaluation={request.evaluation} timeZone={props.timeZone ?? 'UTC'} />)}
    <dl className="props exp-stats" aria-label="Project statistics">
     <dt>Freshness</dt>
     <dd>{pr.watermarks.length === 0 ? 'No stored data was read (a literal result).' : <details className="more"><summary>{pr.watermarks.length} shard cursors were read through</summary><ul className="exp-cursors">{pr.watermarks.map((w) => <li key={w.group}><code>{w.group}:{w.index}</code></li>)}</ul></details>}</dd>
     <dt>Work done</dt>
     <dd>{pr.stats.rows_read} rows read in {pr.stats.pages_read} pages ({pr.stats.bytes_read} bytes), {pr.stats.series_returned} series, {pr.stats.samples_returned} samples, {pr.stats.logs_returned} logs returned, peak memory {pr.stats.peak_memory_bytes} bytes, {elapsedText(pr.stats.elapsed_ns)}{pr.stats.cached ? ', served from the result cache' : ''}</dd>
    </dl>
   </div>
  </section>
 );
}
