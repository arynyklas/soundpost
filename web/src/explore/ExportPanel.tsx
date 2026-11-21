// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { createExport, downloadExport, exportStatus, isAbort } from '../api/client';
import { ApiFault, EXPORT_SIGNALS, type ExportOperation, type ExportSignal } from '../api/types';
import type { ViewContext } from '../app/context';
import { TimeText } from './MetricResult';

/** The most status checks (one per second) before this page stops checking; the export itself is not affected. */
const MAX_CHECKS = 150;
const REASON_WORDS: Record<string, string> = {
 revoked: 'Access was revoked, or the data was deleted, before the export completed. Nothing can be downloaded.',
 timeout: 'The export ran out of time. Nothing can be downloaded.',
 partial: 'A shard answered only partly, so the export was not completed rather than being passed off as complete.',
 too_large: 'The export is larger than the limit. Nothing can be downloaded.',
 unavailable: 'A dependency was unavailable. Nothing can be downloaded.',
};

type State =
 | { kind: 'idle' }
 | { kind: 'creating' }
 | { kind: 'running'; op: ExportOperation; ticket: string; checks: number; project: string }
 | { kind: 'complete'; op: ExportOperation; ticket: string; project: string }
 | { kind: 'downloading'; op: ExportOperation; project: string }
 | { kind: 'downloaded'; id: string; bytes: number }
 | { kind: 'failed'; reason: string }
 | { kind: 'not_found' }
 | { kind: 'error'; code: string; status: number };

function failureOf(error: unknown): State {
 if (error instanceof ApiFault) {
  if (error.status === 403 || error.status === 404) return { kind: 'not_found' };
  return { kind: 'error', code: error.code, status: error.status };
 }
 return { kind: 'error', code: 'network', status: 0 };
}

/** Authenticated asynchronous export of one project's raw records of one signal in the selected window. Authorization is checked
 * when it is created, again when it completes and again for every downloaded chunk: an export revoked or deleted before it finishes
 * is a failure, never a complete file, and a refused download yields no bytes. The file is built in memory only for the download. */
export function ExportPanel(props: { context: ViewContext }): React.JSX.Element {
 const { context } = props;
 const [project, setProject] = React.useState(context.projects[0] ?? '');
 const [signal, setSignal] = React.useState<ExportSignal>('log');
 const [state, setState] = React.useState<State>({ kind: 'idle' });
 const controller = React.useRef<AbortController | null>(null);
 React.useEffect(() => () => { controller.current?.abort(); }, []);

 React.useEffect(() => {
  if (state.kind !== 'running') return undefined;
  const mine = new AbortController();
  const timer = window.setTimeout(() => {
   void (async () => {
    try {
     if (state.checks >= MAX_CHECKS) { setState({ kind: 'error', code: 'checks_exhausted', status: 0 }); return; }
     const op = await exportStatus(context.org, state.project, state.op.id, mine.signal);
     if (mine.signal.aborted) return;
     setState((s) => {
      if (s.kind !== 'running' || s.op.id !== op.id) return s;
      if (op.phase === 'complete') return { kind: 'complete', op, ticket: s.ticket, project: s.project };
      if (op.phase === 'failed') return { kind: 'failed', reason: op.safe_reason ?? 'unavailable' };
      return { ...s, op, checks: s.checks + 1 };
     });
    } catch (error) {
     if (!mine.signal.aborted && !isAbort(error)) setState(failureOf(error));
    }
   })();
  }, 1000);
  return () => { window.clearTimeout(timer); mine.abort(); };
 }, [state, context.org]);

 const start = (): void => {
  controller.current?.abort();
  const mine = new AbortController();
  controller.current = mine;
  setState({ kind: 'creating' });
  createExport(context.org, project, signal, { start: context.start, end: context.end }, mine.signal).then(
   (grant) => { if (!mine.signal.aborted) setState({ kind: 'running', op: grant.operation, ticket: grant.ticket, checks: 0, project }); },
   (error: unknown) => { if (!mine.signal.aborted && !isAbort(error)) setState(failureOf(error)); },
  );
 };
 const download = (): void => {
  if (state.kind !== 'complete') return;
  const { op, ticket } = state;
  controller.current?.abort();
  const mine = new AbortController();
  controller.current = mine;
  setState({ kind: 'downloading', op, project: state.project });
  downloadExport(context.org, state.project, op.id, ticket, mine.signal).then(
   (blob) => {
    if (mine.signal.aborted) return;
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${op.id}.ndjson`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setState({ kind: 'downloaded', id: op.id, bytes: blob.size });
   },
   (error: unknown) => { if (!mine.signal.aborted && !isAbort(error)) setState(failureOf(error)); },
  );
 };
 const busy = state.kind === 'creating' || state.kind === 'running' || state.kind === 'downloading';
 return (
  <section className="panel" aria-labelledby="export-heading" data-section="export" data-export-state={state.kind}>
   <h3 id="export-heading">Export raw records</h3>
   <p>An asynchronous export of one project&rsquo;s raw records of one signal in the selected window (<TimeText ns={context.start} /> to <TimeText ns={context.end} />, end excluded). Your access is checked when the export is created, when it completes and again for every downloaded chunk.</p>
   <form aria-label="Export" onSubmit={(e) => { e.preventDefault(); start(); }}>
    <div className="field-row">
     <label>Project <select value={project} onChange={(e) => setProject(e.target.value)}>{context.projects.map((p) => <option key={p} value={p}>{p}</option>)}</select></label>
     <label>Signal <select value={signal} onChange={(e) => setSignal(e.target.value as ExportSignal)}>{EXPORT_SIGNALS.map((s) => <option key={s} value={s}>{s}</option>)}</select></label>
    </div>
    <button type="submit" disabled={busy}>Start export</button>
   </form>
   <div role="status" aria-live="polite" data-testid="export-status">
    {state.kind === 'idle' && 'No export has been started.'}
    {state.kind === 'creating' && 'Creating the export…'}
    {state.kind === 'running' && <>Running: export <code>{state.op.id}</code>, {state.op.progress} bytes read so far. Checking once a second (check {state.checks} of {MAX_CHECKS}).</>}
    {state.kind === 'complete' && <>Complete: export <code>{state.op.id}</code> is ready in {state.op.chunks} {state.op.chunks === '1' ? 'chunk' : 'chunks'} ({state.op.progress} bytes).</>}
    {state.kind === 'downloading' && 'Downloading: every chunk is authorized again as it is read…'}
    {state.kind === 'downloaded' && <>Downloaded {state.bytes} bytes as <code>{state.id}.ndjson</code>.</>}
   </div>
   {state.kind === 'complete' && <button type="button" className="primary" onClick={download}>Download the export</button>}
   {state.kind === 'failed' && <p role="alert" className="error" data-testid="export-failed" data-reason={state.reason}>The export failed ({state.reason}). {REASON_WORDS[state.reason] ?? 'Nothing can be downloaded.'}</p>}
   {state.kind === 'not_found' && <p role="alert" className="error" data-testid="export-not-found">Not found. This export was not found or is not available to this account. Nothing was downloaded.</p>}
   {state.kind === 'error' && <p role="alert" className="error" data-testid="export-error" data-code={state.code}>{state.code === 'checks_exhausted' ? `This page stopped checking after ${MAX_CHECKS} seconds. Nothing was downloaded.` : `The request failed (${state.code}). Nothing was downloaded.`}</p>}
  </section>
 );
}
