// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ViewSection } from '../api/types';
import { reasonText } from '../app/StatusPanel';

const LABEL: Record<string, string> = { ready: 'Ready', empty: 'Empty', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };

/** Each part of an evidence view with its own state in words. A part that did not fully answer (partial, stale, not available, unknown), or any part that states a reason (an empty trace window is "not proof that the trace does not exist"), is listed openly with that reason. Only plain ready or empty parts without a reason are kept in a collapsed list, so a healthy view is not a wall of status lines. Nothing is hidden from the DOM or the accessibility tree. */
export function EvidenceSections(props: { sections: ViewSection[] }): React.JSX.Element {
 const open: ViewSection[] = [], done: ViewSection[] = [];
 for (const s of props.sections) (s.reason === undefined && (s.state === 'ready' || s.state === 'empty') ? done : open).push(s);
 const item = (s: ViewSection, withReason: boolean): React.JSX.Element => (
  <li key={s.name} data-section={s.name} data-state={s.state}>
   <strong>{s.name.replace(/_/g, ' ')}</strong>: {LABEL[s.state] ?? 'Unknown'}{withReason && s.reason ? ` — ${reasonText(s.reason)}` : ''}
  </li>
 );
 return (
  <>
   {open.length > 0 && <ul className="sections" aria-label="Parts of this view">{open.map((s) => item(s, true))}</ul>}
   {done.length > 0 && (
    <details className="sections-ok">
     <summary>{done.length === 1 ? '1 part answered' : `${done.length} parts answered`}</summary>
     <ul className="sections" aria-label="Parts of this view">{done.map((s) => item(s, false))}</ul>
    </details>
   )}
  </>
 );
}
