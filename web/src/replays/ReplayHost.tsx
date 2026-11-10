// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ReplayItem, ReplayStream } from './model';

/** Same-origin static document built from packages/replay-viewer by web/vite.config.ts and served under its own hash-only, no-network policy. */
export const REPLAY_FRAME_SRC = '/assets/replay-frame.html';
/** Scripts only: never allow-same-origin, allow-forms, allow-popups or allow-top-navigation (packages/replay-viewer VIEWER_SANDBOX). */
export const REPLAY_FRAME_SANDBOX = 'allow-scripts';
const PLAY_INTERVAL_MS = 150;
const START_TIMEOUT_MS = 5000;
const MAX_LOG = 40;

type ViewerStatus = 'loading' | 'ready' | 'gap' | 'unsupported' | 'error';
const STATUSES: readonly string[] = ['loading', 'ready', 'gap', 'unsupported', 'error'];
const STATUS_TEXT: Record<ViewerStatus, string> = {
 loading: 'loading', ready: 'ready (playing a verified chain)', gap: 'paused at a history gap; resumes only at the next verified checkpoint',
 unsupported: 'unsupported recorder version; playback is paused', error: 'replay unavailable',
};

/** Hosts the existing inert replay renderer in a sandboxed, no-network iframe and feeds it the authorized stream one item at a time. The frame decodes, hash-chain verifies and renders every chunk itself; this host only moves items across postMessage and reports the status the frame sends back. Play/Step/Pause pace delivery so a gap and the checkpoint that resumes it can be inspected. */
export function ReplayHost(props: { stream: ReplayStream }): React.JSX.Element {
 const frame = React.useRef<HTMLIFrameElement>(null);
 const iterator = React.useRef<AsyncIterator<ReplayItem> | null>(null);
 const busy = React.useRef(false);
 const playing = React.useRef(false);
 const [started, setStarted] = React.useState(false);
 const [startFailed, setStartFailed] = React.useState(false);
 const [status, setStatus] = React.useState<ViewerStatus | null>(null);
 const [log, setLog] = React.useState<ViewerStatus[]>([]);
 const [delivered, setDelivered] = React.useState(0);
 const [mode, setMode] = React.useState<'paused' | 'playing' | 'finished'>('paused');

 // Attached before the frame can load, and only messages from this frame's own window are read.
 React.useLayoutEffect(() => {
  const onMessage = (event: MessageEvent): void => {
   if (event.source === null || event.source !== frame.current?.contentWindow) return;
   const data: unknown = event.data;
   if (typeof data !== 'object' || data === null || Reflect.get(data, 'soundpost') !== 'status') return;
   const next: unknown = Reflect.get(data, 'status');
   if (typeof next !== 'string' || !STATUSES.includes(next)) return;
   const s = next as ViewerStatus;
   setStarted(true);
   setStatus(s);
   setLog((prev) => (prev[prev.length - 1] === s ? prev : [...prev, s].slice(-MAX_LOG)));
  };
  window.addEventListener('message', onMessage);
  return () => window.removeEventListener('message', onMessage);
 }, []);
 React.useEffect(() => {
  const timer = setTimeout(() => setStartFailed(true), START_TIMEOUT_MS);
  return () => clearTimeout(timer);
 }, []);
 React.useEffect(() => () => {
  playing.current = false;
  const it = iterator.current;
  iterator.current = null;
  void Promise.resolve(it?.return?.()).catch(() => undefined);
 }, []);

 const deliver = async (): Promise<boolean> => {
  if (busy.current) return false;
  busy.current = true;
  try {
   iterator.current ??= props.stream[Symbol.asyncIterator]();
   const next = await iterator.current.next();
   if (next.done === true) { setMode('finished'); playing.current = false; return false; }
   const item = next.value;
   const wire = item.kind === 'chunk' ? { kind: 'chunk', bytes: new Uint8Array(item.bytes).buffer } : item;
   frame.current?.contentWindow?.postMessage({ soundpost: 'replay', item: wire }, '*');
   setDelivered((n) => n + 1);
   return true;
  } catch {
   setMode('finished');
   playing.current = false;
   return false;
  } finally {
   busy.current = false;
  }
 };
 const play = async (): Promise<void> => {
  playing.current = true;
  setMode('playing');
  while (playing.current) {
   if (!(await deliver())) break;
   await new Promise((resolve) => setTimeout(resolve, PLAY_INTERVAL_MS));
  }
  setMode((m) => (m === 'finished' ? m : 'paused'));
 };
 const pause = (): void => { playing.current = false; setMode((m) => (m === 'finished' ? m : 'paused')); };
 const ready = started && !startFailed;
 return (
  <div className="replay-host" data-testid="replay-host" data-mode={mode}>
   <div role="group" aria-label="Playback controls" className="replay-controls">
    <button type="button" disabled={!ready || mode !== 'paused'} onClick={() => { void deliver(); }}>Step to the next event</button>
    {mode === 'playing'
     ? <button type="button" onClick={pause}>Pause</button>
     : <button type="button" className="primary" disabled={!ready || mode === 'finished'} onClick={() => { void play(); }}>Play</button>}
   </div>
   <p role="status" data-testid="viewer-status" data-status={status ?? 'none'}>
    Viewer: {startFailed && !started ? 'the replay viewer did not start; no replay content can be shown' : status === null ? 'starting' : STATUS_TEXT[status]}.
    {' '}Events delivered to the viewer: {delivered}.{mode === 'finished' ? ' All received events were delivered.' : ''}
   </p>
   <ol className="viewer-status-log" data-testid="viewer-status-log" aria-label="Viewer status in order">
    {log.map((s, i) => <li key={`${i}:${s}`} data-status={s}>{s}</li>)}
   </ol>
   <iframe ref={frame} title="Masked replay viewer (sandboxed, no network)" className="replay-frame" data-testid="replay-frame" src={REPLAY_FRAME_SRC} sandbox={REPLAY_FRAME_SANDBOX} referrerPolicy="no-referrer" />
  </div>
 );
}
