// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { act, isAbort } from '../api/client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionRequest, type IncidentActionKind, type IncidentView } from '../api/types';
import { buildRequest, emptyDraft, newCommandId, type Draft } from './model';
import { notServed } from './pageModel';

/** What the server has and has not told us about the last submission. Nothing here is a committed status: `committed` exists only after the server
 * acknowledged the action. */
export type Outcome =
 | { kind: 'idle' }
 | { kind: 'invalid'; text: string }
 | { kind: 'pending' }
 | { kind: 'conflict'; expected: string; current: string; requestId: string }
 | { kind: 'unknown'; request: ActionRequest }
 | { kind: 'refused'; status: number; detail: string; code: string; requestId: string }
 | { kind: 'not_available'; reason: string }
 | { kind: 'committed'; revision: string; action: IncidentActionKind };

export interface IncidentActions {
 view: IncidentView;
 /** The action whose dialog is open. */
 open: IncidentActionKind | null;
 draft: Draft;
 outcome: Outcome;
 pending: boolean;
 reloading: boolean;
 openAction: (kind: IncidentActionKind) => void;
 close: () => void;
 set: (patch: Partial<Draft>) => void;
 submit: () => void;
 resend: (request: ActionRequest) => void;
 reload: () => void;
}

/** The state of every action dialog of one incident. One action is in flight at a time; every new submission is a new command, only the explicit resend of an
 * unknown outcome reuses one. The draft survives a conflict and a reload. */
export function useIncidentActions(view: IncidentView, onCommitted: (view: IncidentView) => void, onReload: () => void, reloading: boolean): IncidentActions {
 const [open, setOpen] = React.useState<IncidentActionKind | null>(null);
 const [draft, setDraft] = React.useState<Draft>(() => emptyDraft('ack'));
 const [outcome, setOutcome] = React.useState<Outcome>({ kind: 'idle' });
 const live = React.useRef<AbortController | null>(null);
 React.useEffect(() => () => live.current?.abort(), []);

 const send = async (request: ActionRequest): Promise<void> => {
  live.current?.abort();
  const controller = new AbortController();
  live.current = controller;
  setOutcome({ kind: 'pending' });
  try {
   const response = await act(request, controller.signal);
   if (controller.signal.aborted) return;
   if (response.state === 'not_available' || !response.incident) { setOutcome({ kind: 'not_available', reason: response.reason ?? 'not_available' }); return; }
   setOutcome({ kind: 'committed', revision: response.incident.version, action: request.kind as IncidentActionKind });
   setDraft(emptyDraft('ack'));
   setOpen(null);
   onCommitted(response.incident);
  } catch (error) {
   if (isAbort(error) || controller.signal.aborted) return;
   if (error instanceof VersionConflict) setOutcome({ kind: 'conflict', expected: request.expected_version, current: error.currentVersion, requestId: error.requestId });
   else if (error instanceof OutcomeUnknown) setOutcome({ kind: 'unknown', request });
   else if (error instanceof ApiFault && notServed(error.status, error.detail)) setOutcome({ kind: 'not_available', reason: 'action_not_served' });
   else if (error instanceof ApiFault) setOutcome({ kind: 'refused', status: error.status, detail: error.detail, code: error.code, requestId: error.requestId });
   else setOutcome({ kind: 'refused', status: 0, detail: '', code: 'unavailable', requestId: '' });
  }
 };

 return {
  view, open, draft, outcome, reloading, pending: outcome.kind === 'pending',
  openAction: (kind) => { setDraft(emptyDraft(kind)); setOutcome({ kind: 'idle' }); setOpen(kind); },
  close: () => { setOpen(null); setOutcome((o) => (o.kind === 'unknown' || o.kind === 'committed' ? o : { kind: 'idle' })); },
  set: (patch) => setDraft((d) => ({ ...d, ...patch })),
  submit: () => {
   if (outcome.kind === 'pending' || open === null) return;
   const built = buildRequest(view, { ...draft, kind: open }, newCommandId(), Date.now());
   if (!built.ok) { setOutcome({ kind: 'invalid', text: built.error }); return; }
   void send(built.request);
  },
  resend: (request) => { void send(request); },
  reload: onReload,
 };
}
