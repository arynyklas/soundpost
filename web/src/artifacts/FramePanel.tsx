// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id, SymbolicatedFrame } from '../api/types';
import { frameReasonWords, positionText, sourceWords } from '../evidence/model';

/** One stack frame. The original sanitized frame is always shown; a mapped position only when the exact source map of this build resolved it; source text only when the server released it to a caller holding the separate sources grant, and the page says plainly when it was withheld. Every value is rendered as a text node: frame text, function names and file paths are never markup. */
export function FramePanel(props: { frame: SymbolicatedFrame; buildId: Id; index?: number }): React.JSX.Element {
 const { frame } = props;
 const o = frame.original;
 const mapped = frame.resolved !== undefined && frame.reason === 'resolved';
 const label = props.index === undefined ? 'Frame' : `Frame ${props.index + 1}`;
 return (
  <article className="frame" aria-label={label} data-reason={frame.reason} data-mapped={mapped ? 'yes' : 'no'}>
   <p><span className={mapped ? 'badge badge-resolved' : 'badge badge-unavailable'} data-testid="frame-state">{mapped ? 'Mapped' : 'Not mapped'}</span> <strong>{label}</strong></p>
   <p data-testid="frame-original">Original sanitized frame: <code>{positionText(o.artifact_id, o.line, o.column, o.function)}</code>{o.module_id ? <> in module <code>{o.module_id}</code></> : null}. {o.in_app ? 'Application code.' : 'Library code.'}{o.async ? ' Asynchronous frame.' : ''}</p>
   {mapped && frame.resolved && (
    <p data-testid="frame-mapped">Mapped to <code>{positionText(frame.resolved.source, frame.resolved.line, frame.resolved.column, frame.resolved.function ?? '')}</code> by build <code>{props.buildId}</code>, source map hash <code>{frame.map_sha256}</code>.</p>
   )}
   <p data-testid="frame-reason">{frameReasonWords(frame.reason)}</p>
   <p data-testid="frame-source-state" data-source={frame.source.state}>{sourceWords(frame.source)}</p>
   {frame.source.state === 'present' && frame.source.context !== undefined && (
    <pre className="source-context" tabIndex={0} aria-label={`${label} source context`} data-testid="frame-source">{frame.source.context}</pre>
   )}
  </article>
 );
}
