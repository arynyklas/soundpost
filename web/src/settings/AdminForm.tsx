// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { newCommandId } from '../incidents/model';
import { adminCommand, adminRead, describeAdminFailure, type AdminCommitted, type AdminKind, type AdminRead, type Built } from './admin';
import { validReason } from './policy';

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
type Phase = { kind: 'idle' } | { kind: 'pending' } | { kind: 'saved'; committed: AdminCommitted } | { kind: 'failed'; text: string; failure: string };

/** One audited admin command: fields, a reason and a save. Nothing is shown as saved until the server answers committed; a refused or stale
 * save says nothing was changed and keeps what was typed; an unknown outcome keeps its command ID so saving again is the same command.
 * `epoch` is the organization policy epoch of the read that showed these fields: the save is refused if the organization changed since. */
export function AdminForm(props: { name: string; label: string; org: Id; epoch: string; build: () => Built<AdminChange>; send?: (sent: { commandId: Id; reason: string; change: AdminChange }, signal: AbortSignal) => Promise<AdminCommitted>; onCommitted: (done: AdminCommitted) => void; onStale: () => void; submitLabel: string; children: React.ReactNode }): React.JSX.Element {
 const [reason, setReason] = React.useState('');
 const [phase, setPhase] = React.useState<Phase>({ kind: 'idle' });
 const command = React.useRef<{ fingerprint: string; id: Id } | null>(null);
 const live = React.useRef(true);
 React.useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (phase.kind === 'pending') return;
  const built = props.build();
  if (!built.ok) { setPhase({ kind: 'failed', text: built.error, failure: 'local' }); return; }
  if (!validReason(reason)) { setPhase({ kind: 'failed', text: 'A reason of 1 to 512 bytes, without control characters, is required: it is kept in the audit record.', failure: 'local' }); return; }
  const fingerprint = JSON.stringify([built.value, reason, props.epoch]);
  if (command.current === null || command.current.fingerprint !== fingerprint) command.current = { fingerprint, id: newCommandId() };
  const sent = command.current;
  setPhase({ kind: 'pending' });
  const send = async (): Promise<AdminCommitted> => {
   const signal = new AbortController().signal;
   if (props.send) return props.send({ commandId: sent.id, reason, change: built.value }, signal);
   return adminCommand({ org: props.org, command_id: sent.id, expected_epoch: props.epoch, kind: built.value.kind, payload: { ...built.value.payload, reason } }, signal);
  };
  send().then(
   (done) => {
    command.current = null;
    if (!live.current) return;
    setPhase({ kind: 'saved', committed: done });
    setReason('');
    props.onCommitted(done);
   },
   (error: unknown) => {
    const failure = describeAdminFailure(error);
    if (failure.kind !== 'unknown_outcome') command.current = null;
    if (!live.current) return;
    setPhase({ kind: 'failed', text: failure.text, failure: failure.kind });
    if (failure.kind === 'conflict') props.onStale();
   },
  );
 };
 const pending = phase.kind === 'pending';
 return (
  <form aria-label={props.label} data-write={props.name} data-write-phase={phase.kind} aria-busy={pending} onSubmit={submit} className="panel">
   {props.children}
   <label>Reason (kept in the audit record) <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={512} autoComplete="off" /></label>
   <button type="submit" className="primary" disabled={pending}>{pending ? 'Saving…' : props.submitLabel}</button>
   {pending && <p role="status">Waiting for the server. Nothing is saved until it confirms.</p>}
   {phase.kind === 'saved' && <p role="status" data-write-result="committed">Saved. The server committed this change{phase.committed.revision ? ` at control revision ${phase.committed.revision}` : ''}.{phase.committed.phase === 'fencing' ? ' It is still taking effect (fencing): this is not complete yet.' : ''}</p>}
   {phase.kind === 'failed' && <p role="alert" className="error" data-write-result={phase.failure}>{phase.text}</p>}
  </form>
 );
}
