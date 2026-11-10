// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getFrames, isAbort, stateOfFault } from '../api/client';
import type { FramesRequest, FramesView, Id, LoadState } from '../api/types';
import { latestOnly, scopeKey, isId, type Latest, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { parseFrameLines } from '../evidence/model';
import { dataOf, stateOfEvidence } from '../evidence/useEvidence';
import { FramePanel } from './FramePanel';

interface Held { key: string; build: Id; state: LoadState<FramesView> }

/** Resolves sanitized frames of one build through the server. The browser sends artifact IDs, line and column only; the server resolves the exact scoped artifact in its sandbox. This page never fetches a map or a runtime URL. Results are keyed to the scope they were asked for and are discarded when the scope changes. */
export function FrameLookup(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const { context, project } = props;
 const key = `${scopeKey(context)}|${project}|${context.generation}`;
 const [build, setBuild] = React.useState('');
 const [text, setText] = React.useState('');
 const [sources, setSources] = React.useState(false);
 const [error, setError] = React.useState('');
 const [held, setHeld] = React.useState<Held | null>(null);
 const latest = React.useRef<Latest>(latestOnly());
 const heading = React.useRef<HTMLDivElement>(null);
 React.useEffect(() => () => latest.current.stop(), []);
 React.useEffect(() => { latest.current.stop(); }, [key]);
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  const buildId = build.trim();
  if (!isId(buildId)) return setError('The build ID must be 32 lowercase hexadecimal characters.');
  const parsed = parseFrameLines(text);
  if (!parsed.ok) return setError(parsed.error);
  setError('');
  const request: FramesRequest = { org: context.org, project, build: buildId, frames: parsed.value, include_sources: sources };
  const read = latest.current.begin();
  setHeld({ key, build: buildId, state: { kind: 'loading' } });
  getFrames(request, read.signal).then(
   (view) => { if (read.current()) setHeld({ key, build: buildId, state: stateOfEvidence(view) }); },
   (failure: unknown) => { if (read.current() && !isAbort(failure)) setHeld({ key, build: buildId, state: stateOfFault(failure) }); },
  );
 };
 const current = held && held.key === key ? held : null;
 const view = current ? dataOf(current.state) : undefined;
 React.useEffect(() => { if (current && current.state.kind !== 'loading') heading.current?.focus(); }, [current?.state.kind]);
 return (
  <section className="panel" aria-labelledby="frames-heading" data-section="frame-lookup">
   <h3 id="frames-heading">Resolve frames</h3>
   <p>Paste the sanitized frames of an occurrence, one per line. Frames are mapped only through the exact source map of the build you name, inside your own scope. Source text stays withheld unless you ask for it and hold the separate sources grant.</p>
   <form onSubmit={submit} aria-label="Resolve frames">
    <label>Build ID <input name="build" value={build} onChange={(e) => setBuild(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <label>Frames (artifact ID, line, column or -, function) <textarea name="frames" rows={4} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} /></label>
    <label className="check"><input type="checkbox" name="sources" checked={sources} onChange={(e) => setSources(e.target.checked)} /> Also request source context (needs the separate sources grant)</label>
    <button type="submit" className="primary" disabled={current?.state.kind === 'loading'}>{current?.state.kind === 'loading' ? 'Resolving…' : 'Resolve frames'}</button>
    {error && <p role="alert" className="error">{error}</p>}
   </form>
   {current && (
    <div ref={heading} tabIndex={-1} data-testid="frame-results">
     <StatusPanel state={current.state} />
     {view && view.frames.map((f, i) => <FramePanel key={i} frame={f} buildId={current.build} index={i} />)}
    </div>
   )}
  </section>
 );
}
