// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getOperation, isAbort, stateOfFault } from '../api/client';
import type { Id, LifecycleOperation, LoadState } from '../api/types';
import { formatNs, isId, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { describeReason } from '../incidents/model';
import { memberName, useShell } from '../shell/ShellContext';
import { DataTable, Pill, Person } from '../ui/primitives';
import { useAdminRead } from './AdminForm';
import { Panel } from './SettingsUi';

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

/** Whether an operation can still change on its own: it is fencing, or logically complete with the
 * physical erasure still pending. Held, failed and a finished erasure do not change by themselves. */
export function keepPolling(op: LifecycleOperation): boolean {
 return op.state === 'ready' && (op.phase === 'fencing' || (op.phase === 'complete' && op.physical === 'pending'));
}

const POLL_MS = 2000;
/** Polls one operation (scoped by the server to this organization's administrators) until it
 * reaches a state that will not change on its own (see keepPolling). */
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
     if (keepPolling(op)) timer = window.setTimeout(poll, POLL_MS);
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
  <div data-section="operations">
   <Panel title="Restriction, revocation and deletion progress">
    <div className="col g12">
     <p className="small t2">A deletion, restriction or revocation takes effect in stages. Look one up by its operation ID to see how far it is: nothing is reported as finished before it is.</p>
     <form aria-label="Look up an operation" className="set-form set-inline" onSubmit={(e) => { e.preventDefault(); const v = value.trim(); if (!isId(v)) return setError('Operation ID must be 32 lowercase hexadecimal characters.'); setError(''); setId(v); }}>
      <label className="grow">Operation ID <input value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} /></label>
      <button type="submit" className="btn">Show progress</button>
     </form>
     {error && <p role="alert" className="error">{error}</p>}
     {id && <StatusPanel state={load} />}
     {op && words && (
      <div data-testid="operation" data-phase={op.phase} className="col g12 set-op">
       <p><strong>{words.label}.</strong> {words.text}</p>
       <p className="small t2">Operation <code>{op.id}</code>, generation {op.generation}. Physical erasure is due by {formatNs(op.physical_deadline, c.timezone)}; backup copies expire by {formatNs(op.backup_deadline, c.timezone)}.</p>
       {op.over_erased && op.over_erased.length > 0 && <p className="small t2">Opaque control states erased without a recorded window: {op.over_erased.map((e) => `${e.book} ${e.count}`).join(', ')}.</p>}
       {op.residual_stores && op.residual_stores.length > 0 && <p className="small t2">Local stores that may still hold a copy: {op.residual_stores.join(', ')}.</p>}
      </div>
     )}
    </div>
   </Panel>
  </div>
 );
}

const SHOWN = 25;
function AuditPanel(props: { context: ViewContext }): React.JSX.Element {
 const { load } = useAdminRead(props.context, 'audit');
 const { names } = useShell();
 const audits = load.kind === 'ready' ? load.data.audits : undefined;
 const recent = audits ? [...audits].reverse().slice(0, SHOWN) : [];
 return (
  <div data-section="org-audit">
   <Panel title="Audit trail" footer={audits && audits.length > SHOWN ? `The ${SHOWN} most recent of ${audits.length} audited changes` : undefined}>
    <div className="col g12">
     {load.kind !== 'ready' && <StatusPanel state={load} />}
     {audits && (recent.length === 0
      ? <p role="status" data-state="empty" className="set-empty">No audited change yet.</p>
      : <DataTable label="Recent audited changes" rows={recent} rowKey={(a) => a.id} rowAttrs={(a) => ({ 'data-audit-action': a.action })} columns={[
       { key: 'when', header: 'When', rowHeader: false, cell: (a) => <span className="nowrap">{formatNs(a.timeNs, props.context.timezone)}</span> },
       { key: 'action', header: 'Change', cell: (a) => <b>{a.action.replace(/_/g, ' ')}</b> },
       { key: 'by', header: 'By', cell: (a) => <Person id={a.principal} name={memberName(names, a.principal)} /> },
       { key: 'outcome', header: 'Outcome', cell: (a) => <Pill tone={a.allowed ? 'ok' : 'crit'} icon={a.allowed ? 'check' : 'x'}>{a.allowed ? 'Allowed' : 'Refused'}</Pill> },
       { key: 'reason', header: 'Reason', cell: (a) => <span className="t2">{a.reason}</span> },
      ]} />)}
    </div>
   </Panel>
  </div>
 );
}

/** Audit and operations: the audited changes of the organization (administrators only: anyone else sees them as not found) and the progress of a long-running operation. */
export function OperationsPage(props: { context: ViewContext }): React.JSX.Element {
 return (
  <div data-settings-page="operations" className="col g16">
   <AuditPanel context={props.context} />
   <OperationPanel context={props.context} />
  </div>
 );
}
