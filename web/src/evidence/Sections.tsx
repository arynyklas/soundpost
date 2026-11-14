// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { ViewSection } from '../api/types';
import { reasonText } from '../app/StatusPanel';

const LABEL: Record<string, string> = { ready: 'Ready', empty: 'Empty', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };

/** Each part of an evidence view with its own state in words; a part that is not built is listed as such and never hidden or shown as healthy. */
export function EvidenceSections(props: { sections: ViewSection[] }): React.JSX.Element {
 return (
  <ul className="sections" aria-label="Parts of this view">
   {props.sections.map((s) => (
    <li key={s.name} data-section={s.name} data-state={s.state}>
     <strong>{s.name.replace(/_/g, ' ')}</strong>: {LABEL[s.state] ?? 'Unknown'}{s.reason ? ` — ${reasonText(s.reason)}` : ''}
    </li>
   ))}
  </ul>
 );
}
