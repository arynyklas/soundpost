// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { adminCommand, adminRead, describeAdminFailure, type AdminCommitted, type AdminKind, type AdminRead, type Built } from './admin';
import { AuditedForm } from './AuditedForm';

/** One organization-scoped admin read, keyed to the scope it was asked for. `reload` reads again and keeps the answer on screen until the
 * new one arrives, so a form being used is never torn down by a refresh. */
export function useAdminRead(context: ViewContext, kind: AdminKind): { load: LoadState<AdminRead>; reload: () => void } {
 const key = `${scopeKey(context)}|${kind}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<AdminRead> }>({ key: '', load: { kind: 'loading' } });
 const [tick, setTick] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  adminRead(context.org, kind, ctl.signal).then(
   (view) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: view } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, tick]);
 return { load: held.key === key ? held.load : { kind: 'loading' }, reload: () => setTick((n) => n + 1) };
}

export interface AdminChange { kind: string; payload: Record<string, unknown> }

/** One audited admin command: fields, a reason and a save (see AuditedForm). `epoch` is the organization policy epoch of the read that showed these fields: the save is
 * refused if the organization changed since. A destination or a source policy sends through its own route (`send`) under the same words. */
export function AdminForm(props: { name: string; label: string; org: Id; epoch: string; build: () => Built<AdminChange>; send?: (sent: { commandId: Id; reason: string; change: AdminChange }, signal: AbortSignal) => Promise<AdminCommitted>; onCommitted: (done: AdminCommitted) => void; onStale: () => void; submitLabel: string; children: React.ReactNode }): React.JSX.Element {
 return (
  <AuditedForm<AdminCommitted>
   name={props.name} label={props.label} submitLabel={props.submitLabel} describe={describeAdminFailure} onStale={props.onStale} onCommitted={props.onCommitted}
   check={() => { const built = props.build(); return built.ok ? null : built.error; }}
   fingerprint={() => { const built = props.build(); return JSON.stringify([built.ok ? built.value : built.error, props.epoch]); }}
   run={(commandId, reason, signal) => {
    const built = props.build();
    if (!built.ok) return Promise.reject(new Error(built.error));
    if (props.send) return props.send({ commandId, reason, change: built.value }, signal);
    return adminCommand({ org: props.org, command_id: commandId, expected_epoch: props.epoch, kind: built.value.kind, payload: { ...built.value.payload, reason } }, signal);
   }}
   saved={(done) => `Saved. The server committed this change${done.revision ? ` at control revision ${done.revision}` : ''}.${done.phase === 'fencing' ? ' It is still taking effect (fencing): this is not complete yet.' : ''}`}>
   {props.children}
  </AuditedForm>
 );
}
