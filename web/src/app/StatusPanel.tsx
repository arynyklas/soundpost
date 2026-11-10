// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { LoadState } from '../api/types';
import { EVIDENCE_REASON } from '../evidence/model';

const REASONS: Record<string, string> = {
 service_not_built: 'The service behind this view is not available in this installation yet.',
 separate_grant_not_built: 'Access to this data needs a separate grant that this installation does not offer yet.',
 view_not_built: 'This part of the view is not available yet.',
 service_registry_not_built: 'Services are not registered in this installation, so a service identity cannot be confirmed.',
 sections_not_available: 'Some parts of this view are not available yet; the parts shown are real.',
 shards_missing: 'Some data did not answer. Missing data is not zero.',
 freshness_stale: 'The newest data is older than expected.',
 no_visible_sources: 'No readable source was found for this selection.',
 restricted_source_discovery_unavailable: 'Discovery does not run for a restricted source.',
 project_failed: 'This project produced no value. It is not an empty or zero result; the failure is listed below.',
 saved_views_not_built: 'Saved views and their exports need the C11 saved-view actions, which this installation does not have. Nothing is saved, in this browser or on the server.',
};
export function reasonText(reason: string): string { return REASONS[reason] ?? EVIDENCE_REASON[reason] ?? 'Not available.'; }

interface Presentation { label: string; text: string; role: 'status' | 'alert' }
function present(state: LoadState<unknown>): Presentation {
 switch (state.kind) {
  case 'loading': return { label: 'Loading', text: 'Loading this view for the selected scope.', role: 'status' };
  case 'ready': return { label: 'Ready', text: 'Showing the answer for the selected scope.', role: 'status' };
  case 'empty': return { label: 'Empty', text: 'Nothing was found in this window. Nothing is missing.', role: 'status' };
  case 'unauthorized': return state.status === 401
   ? { label: 'Signed out', text: 'Your session has ended. Sign in again.', role: 'alert' }
   : { label: 'Not found', text: 'This selection was not found or is not available to this account.', role: 'alert' };
  case 'unsupported': return { label: 'Not available', text: reasonText(state.reason), role: 'status' };
  case 'stale': return { label: 'Stale', text: reasonText(state.reason), role: 'status' };
  case 'incomplete': return { label: 'Partial', text: reasonText(state.reason), role: 'status' };
  case 'rate_limited': return { label: 'Rate limited', text: 'Too many requests. Wait and retry; nothing was changed.', role: 'alert' };
  case 'error': return { label: 'Error', text: 'The request failed. Nothing is shown for this view.', role: 'alert' };
 }
}

/** One explicit panel for every load state. State is always spelled out in words
 * (never color alone) and the request ID of a failure is kept for support. */
export function StatusPanel(props: { state: LoadState<unknown> }): React.JSX.Element {
 const { state } = props;
 const p = present(state);
 const id = state.kind === 'unauthorized' || state.kind === 'rate_limited' ? state.requestId : state.kind === 'error' ? state.fault.requestId : '';
 const code = state.kind === 'error' ? state.fault.code : '';
 return (
  <div className={`status status-${state.kind}`} role={p.role} data-state={state.kind} aria-live={p.role === 'alert' ? 'assertive' : 'polite'}>
   <strong>{p.label}</strong> <span>{p.text}</span>
   {code && <span> Code <code>{code}</code>.</span>}
   {id && <span> Request <code>{id}</code>.</span>}
  </div>
 );
}

const SECTION_LABEL: Record<string, string> = { ready: 'Ready', empty: 'Empty', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };
/** Each section of a view with its own state in words. A part that is not built is
 * listed as such, never hidden and never shown as healthy or zero. */
export function SectionList(props: { sections: { name: string; state: string; reason?: string }[] }): React.JSX.Element {
 return (
  <ul className="sections">
   {props.sections.map((s) => (
    <li key={s.name} data-section={s.name} data-state={s.state}>
     <strong>{s.name}</strong>: {SECTION_LABEL[s.state] ?? 'Unknown'}{s.reason ? ` — ${reasonText(s.reason)}` : ''}
    </li>
   ))}
  </ul>
 );
}
