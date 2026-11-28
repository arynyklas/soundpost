// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort } from '../api/client';
import type { Id } from '../api/types';
import { newCommandId } from '../incidents/model';
import { validReason } from './policy';

type Phase<R> = { kind: 'idle' } | { kind: 'pending' } | { kind: 'saved'; result: R } | { kind: 'failed'; text: string; failure: string };

export interface Failure { kind: string; text: string }
const REASON_WORDS = 'A reason of 1 to 512 bytes, without control characters, is required: it is kept in the audit record.';

/** One audited change: fields, a reason and a save. Nothing is shown as saved until the server answers committed; a refused or stale save says nothing was changed and keeps
 * what was typed; an unknown outcome keeps its command ID, so saving again is the same command and the server applies it once. Every settings write goes through this one form. */
export function AuditedForm<R>(props: {
 name: string; label: string; submitLabel: string;
 /** The problem with what was typed, or null. Nothing is sent while there is one. */
 check: () => string | null;
 /** Everything that makes this command a different command: typed values and the version it is based on. */
 fingerprint: () => string;
 run: (command: Id, reason: string, signal: AbortSignal) => Promise<R>;
 describe: (error: unknown) => Failure;
 saved: (result: R) => string;
 onCommitted: (result: R) => void;
 onStale: () => void;
 children: React.ReactNode;
}): React.JSX.Element {
 const [reason, setReason] = React.useState('');
 const [phase, setPhase] = React.useState<Phase<R>>({ kind: 'idle' });
 const command = React.useRef<{ fingerprint: string; id: Id } | null>(null);
 const live = React.useRef(true);
 React.useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
 const submit = (event: React.FormEvent<HTMLFormElement>): void => {
  event.preventDefault();
  if (phase.kind === 'pending') return;
  const problem = props.check();
  if (problem !== null) { setPhase({ kind: 'failed', text: problem, failure: 'local' }); return; }
  if (!validReason(reason)) { setPhase({ kind: 'failed', text: REASON_WORDS, failure: 'local' }); return; }
  const fingerprint = JSON.stringify([props.fingerprint(), reason]);
  if (command.current === null || command.current.fingerprint !== fingerprint) command.current = { fingerprint, id: newCommandId() };
  const sent = command.current;
  setPhase({ kind: 'pending' });
  props.run(sent.id, reason, new AbortController().signal).then(
   (result) => {
    command.current = null;
    if (!live.current) return;
    setPhase({ kind: 'saved', result });
    setReason('');
    props.onCommitted(result);
   },
   (error: unknown) => {
    if (isAbort(error)) return;
    const failure = props.describe(error);
    if (failure.kind !== 'unknown_outcome') command.current = null;
    if (!live.current) return;
    setPhase({ kind: 'failed', text: failure.text, failure: failure.kind });
    if (failure.kind === 'conflict') props.onStale();
   },
  );
 };
 const pending = phase.kind === 'pending';
 return (
  <form aria-label={props.label} data-write={props.name} data-write-phase={phase.kind} aria-busy={pending} onSubmit={submit} className="set-form">
   <div className="set-fields">{props.children}</div>
   <label className="set-reason">Reason (kept in the audit record) <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={512} autoComplete="off" /></label>
   <div className="row wrap set-actions">
    <button type="submit" className="btn-primary" disabled={pending}>{pending ? 'Saving…' : props.submitLabel}</button>
   </div>
   {pending && <p role="status" className="set-note">Waiting for the server. Nothing is saved until it confirms.</p>}
   {phase.kind === 'saved' && <p role="status" className="set-note set-note-ok" data-write-result="committed">{props.saved(phase.result)}</p>}
   {phase.kind === 'failed' && <p role="alert" className="error" data-write-result={phase.failure}>{phase.text}</p>}
  </form>
 );
}
