// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { capabilities, getOperation, isAbort, stateOfFault } from '../api/client';
import type { Id, LifecycleOperation, LoadState, VisibleSource } from '../api/types';
import { formatNs, isId, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { describeReason } from '../incidents/model';

/** What an operation's phase means, in words. Only a complete operation with physical erasure done
 * is reported as finished; fencing, held and failed are never success, and a logically complete
 * deletion is not physical erasure. */
export function operationWords(op: LifecycleOperation, tz: string): { label: string; text: string; success: boolean } {
 if (op.state !== 'ready') return { label: 'Not available', success: false, text: describeReason(op.reason ?? 'lifecycle_operation_store_not_wired') };
 const physical = formatNs(op.physical_deadline, tz), backup = formatNs(op.backup_deadline, tz);
 switch (op.phase) {
  case 'fencing': return { label: 'Pending (fencing)', success: false, text: `Reads of the affected data are already denied, but the fence is not complete: ${op.applied_barriers} confirmed, ${op.pending_groups} group${op.pending_groups === 1 ? '' : 's'} still pending. This is not success, and nothing has been erased yet.` };
  case 'held': return { label: 'Held', success: false, text: `A legal hold (${op.holds} hold${op.holds === 1 ? '' : 's'}) prevents erasure. The data has not been erased. Backup copies are retained at least until ${backup}.` };
  case 'failed': return { label: 'Failed', success: false, text: `The operation failed${op.safe_fault ? ` (${op.safe_fault})` : ''}. It is not complete and nothing may be assumed erased.` };
  case 'complete':
   if (op.physical === 'done') return { label: 'Complete', success: true, text: `Logical deletion and physical erasure of the primary stores are done. Backup copies remain until ${backup}.` };
   if (op.physical === 'held') return { label: 'Logically complete, erasure held', success: false, text: `Reads are denied, but a legal hold prevents physical erasure. The bytes are not erased. Backup copies remain until ${backup}.` };
   return { label: 'Logically complete, erasure pending', success: false, text: `Reads are denied. Physical erasure is still pending and is due by ${physical}; backup copies remain until ${backup}. The bytes are not erased yet.` };
  default: return { label: 'Not available', success: false, text: describeReason(op.reason ?? 'lifecycle_operation_store_not_wired') };
 }
}

const POLL_MS = 2000;
/** Polls one operation (scoped by the server to this organization's administrators) until it
 * reaches a phase that will not change on its own. */
function OperationPanel(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const [value, setValue] = React.useState('');
 const [id, setId] = React.useState<Id | ''>('');
 const [error, setError] = React.useState('');
 const [state, setState] = React.useState<{ key: string; load: LoadState<LifecycleOperation> }>({ key: '', load: { kind: 'loading' } });
 const key = `${c.org}|${id}|${c.generation}`;
 React.useEffect(() => {
  if (!id) return;
  const ctl = new AbortController();
  let timer = 0;
  setState({ key, load: { kind: 'loading' } });
  const poll = (): void => {
   getOperation(c.org, id, ctl.signal).then(
    (op) => {
     if (ctl.signal.aborted) return;
     setState({ key, load: op.state === 'ready' ? { kind: 'ready', data: op } : { kind: 'unsupported', reason: op.reason ?? 'lifecycle_operation_store_not_wired', data: op } });
     if (op.state === 'ready' && op.phase === 'fencing') timer = window.setTimeout(poll, POLL_MS);
    },
    (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setState({ key, load: stateOfFault(e) }); },
   );
  };
  poll();
  return () => { ctl.abort(); clearTimeout(timer); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 const load: LoadState<LifecycleOperation> = state.key === key ? state.load : { kind: 'loading' };
 const op = load.kind === 'ready' ? load.data : undefined;
 const words = op ? operationWords(op, c.timezone) : undefined;
 return (
  <section aria-labelledby="operation-heading" data-section="operations">
   <h3 id="operation-heading">Restriction, revocation and deletion progress</h3>
   <form aria-label="Look up an operation" onSubmit={(e) => { e.preventDefault(); const v = value.trim(); if (!isId(v)) return setError('Operation ID must be 32 lowercase hexadecimal characters.'); setError(''); setId(v); }}>
    <label>Operation ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
    <button type="submit">Show progress</button>
    {error && <p role="alert" className="error">{error}</p>}
   </form>
   {id && <StatusPanel state={load} />}
   {op && words && (
    <div data-testid="operation" data-phase={op.phase}>
     <p><strong>{words.label}.</strong> {words.text}</p>
     <p>Operation <code>{op.id}</code>, generation {op.generation}. Physical erasure is due by {formatNs(op.physical_deadline, c.timezone)}; backup copies expire by {formatNs(op.backup_deadline, c.timezone)}.</p>
     {op.residual_stores && op.residual_stores.length > 0 && <p>Local stores that may still hold a copy: {op.residual_stores.join(', ')}.</p>}
    </div>
   )}
  </section>
 );
}

/** Project settings as far as committed routes allow: the readable source capabilities and the
 * progress of long-running operations. Policies, notification destinations, retention, SSO and
 * organization/team administration have no committed read route, so they are listed as not
 * available instead of being drawn from invented data. */
export function ProjectSettings(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const [held, setHeld] = React.useState<{ key: string; byProject: Record<string, LoadState<VisibleSource[]>> }>({ key: '', byProject: {} });
 const key = `${scopeKey(c)}|${c.generation}`;
 React.useEffect(() => {
  const ctl = new AbortController();
  setHeld({ key, byProject: {} });
  for (const project of c.projects) {
   capabilities(c.org, project, ctl.signal).then(
    (r) => { if (!ctl.signal.aborted) setHeld((h) => h.key === key ? { key, byProject: { ...h.byProject, [project]: r.sources.length ? { kind: 'ready', data: r.sources } : { kind: 'empty', data: [] } } } : h); },
    (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld((h) => h.key === key ? { key, byProject: { ...h.byProject, [project]: stateOfFault(e) } } : h); },
   );
  }
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 return (
  <section className="panel" aria-labelledby="view-heading">
   <h2 id="view-heading">Project settings</h2>
   <p>Source capabilities this account may read. A project with no readable source is empty, not unhealthy.</p>
   {c.projects.map((project) => {
    const state: LoadState<VisibleSource[]> = held.key === key ? held.byProject[project] ?? { kind: 'loading' } : { kind: 'loading' };
    return (
     <div key={project} data-project={project}>
      <h3>Project <code>{project}</code></h3>
      <StatusPanel state={state} />
      {'data' in state && state.data.length > 0 && <ul>{state.data.map((s) => <li key={s.id}><code>{s.id}</code> — class {s.class}, kinds {s.kinds.join(', ')}{s.replay ? ', replay' : ''}</li>)}</ul>}
     </div>
    );
   })}
   <h3>Policies and administration</h3>
   <ul className="sections" data-section="settings-not-available">
    {['Notification destinations and policy', 'Retention settings', 'Source policy, template and replay enablement', 'Single sign-on mapping', 'Organization and team administration'].map((name) => (
     <li key={name}><strong>{name}</strong>: Not available — the administration routes this page would read do not exist in this installation yet, so nothing is shown rather than a guess. No destination secret is ever shown.</li>
    ))}
   </ul>
   <OperationPanel context={c} />
  </section>
 );
}
