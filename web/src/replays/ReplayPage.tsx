// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, probeReplay, stateOfFault, streamReplay } from '../api/client';
import { ApiFault, type Id, type LoadState } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { emptySummary, gapSentence, lossText, summarize, toItem, type ReplaySummary } from './model';
import { ReplayHost } from './ReplayHost';
import { ItemQueue } from './queue';

/** How often a replay this page holds is revalidated without reading any chunk. */
export const PROBE_INTERVAL_MS = 3000;

type Phase = 'loading' | 'streaming' | 'ended' | 'failed' | 'not_available';
interface Held { key: string; phase: Phase; summary: ReplaySummary; queue: ItemQueue | null; fault: LoadState<never> | null }
const initial = (key: string): Held => ({ key, phase: 'loading', summary: emptySummary(), queue: null, fault: null });

function stateOf(h: Held): LoadState<null> {
 if (h.fault !== null) return h.fault;
 switch (h.phase) {
  case 'loading': return { kind: 'loading' };
  case 'ended': return { kind: 'unauthorized', status: 404, requestId: '' };
  case 'failed': return { kind: 'error', fault: new ApiFault(200, h.summary.code ?? 'unavailable', '', '') };
  case 'not_available': return { kind: 'unsupported', reason: h.summary.reason ?? 'not_available', data: null };
  case 'streaming': return h.summary.terminal === 'truncated' ? { kind: 'incomplete', data: null, reason: 'replay_truncated' } : { kind: 'ready', data: null };
 }
}

/** One masked replay under the caller's own scope. The server releases chunks only while the reader's replay.read and telemetry.read grants and the replay itself stand; this page hands them to the sandboxed viewer, states what the replay does and does not contain, and clears everything the moment the server says access ended, the replay was deleted or an error ended the stream. */
export function ReplayPage(props: { id: Id; project: Id; context: ViewContext }): React.JSX.Element {
 const { context, project, id } = props;
 const key = `${scopeKey(context)}|${project}|${id}|${context.generation}`;
 const [held, setHeld] = React.useState<Held>(() => initial(key));

 React.useEffect(() => {
  const control = new AbortController();
  const queue = new ItemQueue();
  let alive = true;
  let summary = emptySummary();
  setHeld({ ...initial(key), queue });
  const publish = (phase: Phase, fault: LoadState<never> | null = null): void => { if (alive) setHeld({ key, phase, summary, queue: phase === 'streaming' ? queue : null, fault }); };
  void (async () => {
   try {
    for await (const line of streamReplay(context.org, project, id, control.signal)) {
     if (!alive) return;
     summary = summarize(summary, line);
     switch (line.type) {
      case 'revoke': queue.clear(); control.abort(); return publish('ended');
      case 'error': queue.clear(); control.abort(); return publish('failed');
      case 'not_available': queue.clear(); return publish('not_available');
      default: {
       const item = toItem(line);
       if (item !== null) queue.push(item);
       if (line.type === 'end' || line.type === 'truncated') queue.close();
       publish('streaming');
      }
     }
    }
   } catch (error) {
    if (!alive || isAbort(error)) return;
    queue.clear();
    const state = stateOfFault(error);
    publish(state.kind === 'unauthorized' ? 'ended' : 'failed', state);
   }
  })();
  return () => { alive = false; control.abort(); queue.clear(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);

 // Revalidation: a replay already delivered cannot be recalled by the server, so while content is on screen the page keeps asking, without reading chunks, whether this account may still read it.
 const live = held.key === key && held.phase === 'streaming';
 React.useEffect(() => {
  if (!live) return undefined;
  const control = new AbortController();
  const timer = setInterval(() => {
   probeReplay(context.org, project, id, control.signal).catch((error: unknown) => {
    if (control.signal.aborted || isAbort(error)) return;
    if (error instanceof ApiFault && (error.status === 401 || error.status === 403 || error.status === 404)) {
     setHeld((h) => { if (h.key !== key) return h; h.queue?.clear(); return { ...h, phase: 'ended', queue: null, fault: stateOfFault(error) }; });
    }
   });
  }, PROBE_INTERVAL_MS);
  return () => { clearInterval(timer); control.abort(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [live, key]);

 const h = held.key === key ? held : initial(key);
 const s = h.summary;
 const ended = h.phase === 'ended';
 return (
  <section className="panel" aria-labelledby="replay-heading">
   <h2 id="replay-heading">Replay <code>{id}</code></h2>
   <p>This is a masked reconstruction, not a video. The recorder never captures page text, form values, attributes, URLs, styles or canvas content; the viewer below draws only structure and shows masked text and opaque regions as labels.</p>
   <StatusPanel state={stateOf(h)} />
   {ended && <p role="alert" data-testid="replay-ended" className="banner banner-warning">Playback ended: access to this replay ended or it was deleted. Its content was cleared from this page and nothing further was requested.</p>}
   {h.phase === 'failed' && <p role="alert" data-testid="replay-failed" className="banner banner-warning">The replay stream ended with an error{s.code ? ` (${s.code})` : ''}. Its content was cleared from this page.</p>}
   {s.terminal === 'truncated' && <p data-testid="replay-truncated" className="banner">This response is bounded: only the events before sequence {s.next} were delivered. The rest of the replay was not sent and is not shown.</p>}
   {!ended && h.phase !== 'failed' && (
    <dl className="replay-labels" data-testid="replay-labels" aria-label="What this replay contains">
     <dt>Text</dt><dd data-testid="label-masked">Masked. Text, input values and attributes are never recorded; any text node appears as <code>[masked]</code>.</dd>
     <dt>Opaque regions</dt><dd data-testid="label-opaque">Closed shadow roots, cross-origin frames and unsupported widgets appear as <code>[opaque]</code> blocks. Nothing inside them exists in this replay.</dd>
     <dt>Capture policy revision</dt><dd data-testid="label-policy">{s.policies.length === 0 ? 'unknown (no chunk delivered yet)' : s.policies.join(', ')}</dd>
     <dt>Recording loss</dt><dd data-testid="label-loss">{lossText(s)}</dd>
     <dt>Chunks received</dt><dd data-testid="label-chunks">{s.chunks} ({s.checkpoints} checkpoints)</dd>
    </dl>
   )}
   {!ended && h.phase !== 'failed' && (
    <div data-testid="replay-gaps" aria-label="History gaps">
     <h3>History gaps</h3>
     {s.gaps.length === 0 ? <p>No gap observed in the events received so far. A recorder that lost a chunk would show it here.</p> : <ul>{s.gaps.map((g) => <li key={`${g.from}-${g.through}`} data-gap={`${g.from}-${g.through}`}>{gapSentence(g)}</li>)}</ul>}
    </div>
   )}
   {live && h.queue !== null && <ReplayHost key={key} stream={h.queue} />}
  </section>
 );
}
