// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { PHASE_WORDS, getCutover, kindCounts, orderedSpans, ownerStatement, restoreWarning, sideWords, type CutoverView } from './cutover';

/** Read-only: who owns normal notifications, the committed timeline, the delivery accounting, the shadow decisions and the legacy history boundary.
 * Nothing here advances the cutover; only the operator flow does. Every state is spelled out in words, never by colour alone. */
export function CutoverPanel(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const c = props.context;
 const key = `${scopeKey(c)}|${props.project}|${c.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<CutoverView> }>({ key: '', load: { kind: 'loading' } });
 React.useEffect(() => {
  const ctl = new AbortController();
  getCutover(c.org, props.project, ctl.signal).then(
   (view) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: view } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 const load: LoadState<CutoverView> = held.key === key ? held.load : { kind: 'loading' };
 const tz = c.timezone;
 const heading = `cutover-${props.project}`;
 return (
  <section aria-labelledby={heading} data-section="cutover" data-project-cutover={props.project} className="panel">
   <h4 id={heading}>Notification cutover</h4>
   <p>Read-only. The cutover is advanced only by the operator flow; nothing on this page changes it.</p>
   {load.kind === 'loading' && <p role="status">Loading the cutover state…</p>}
   {load.kind !== 'ready' && load.kind !== 'loading' && <StatusPanel state={load} />}
   {load.kind === 'ready' && <CutoverBody view={load.data} tz={tz} />}
  </section>
 );
}

function when(ns: string | undefined, tz: string): string {
 if (ns === undefined || ns === '0') return 'open';
 try { return formatNs(ns, tz); } catch { return `${ns} ns`; }
}

function CutoverBody(props: { view: CutoverView; tz: string }): React.JSX.Element {
 const { view, tz } = props;
 const c = view.cutover;
 const owner = ownerStatement(c);
 const warning = restoreWarning(c);
 const kinds = kindCounts(view.shadow.by_kind);
 const spans = orderedSpans(view.history.spans);
 return (
  <>
   <div data-cutover-owner={owner.owner ?? 'none'} data-cutover-phase={c?.phase ?? 'none'}>
    <h5>Who owns normal notifications now</h5>
    <p><strong>{owner.headline}</strong>{owner.owner !== null && <> Owner <code>{owner.owner}</code>.</>} {owner.detail}</p>
    {c && (
     <dl>
      <dt>Phase</dt><dd>{PHASE_WORDS[c.phase]} (<code>{c.phase}</code>), epoch {c.epoch}, revision {c.revision}, entered {when(c.entered_at_ns, tz)}</dd>
      <dt>Old (legacy) owner</dt><dd><code>{c.old_owner}</code></dd>
      <dt>New owner</dt><dd><code>{c.new_owner}</code></dd>
      <dt>Active owners</dt><dd>{c.active_owners.length === 0 ? 'none (handover)' : c.active_owners.map((o) => <code key={o}>{o} </code>)}</dd>
     </dl>
    )}
   </div>
   {warning && <p role="alert" className="error" data-cutover-restore-pending={c?.restore.pending}><strong>Restore pending.</strong> {warning}</p>}
   {c && c.restore.acknowledged !== undefined && !warning && <p role="status">Restore generation <code>{c.restore.acknowledged}</code> was acknowledged.</p>}

   {c && (
    <>
     <table aria-label="Cutover timeline" data-cutover-timeline>
      <caption>Timeline of committed transitions, oldest first</caption>
      <thead><tr><th scope="col">Revision</th><th scope="col">From</th><th scope="col">To</th><th scope="col">Epoch</th><th scope="col">At</th><th scope="col">Operator</th><th scope="col">Command</th><th scope="col">Digest</th><th scope="col">Evidence digest</th></tr></thead>
      <tbody>
       {c.timeline.length === 0 && <tr><td colSpan={9}>No transition has been committed yet.</td></tr>}
       {c.timeline.map((s) => (
        <tr key={s.revision}><td>{s.revision}</td><td>{s.from === '' ? 'Created (no previous phase)' : PHASE_WORDS[s.from]}</td><td>{PHASE_WORDS[s.to]}</td><td>{s.epoch}</td><td>{when(s.at_ns, tz)}</td><td><code>{s.principal}</code></td><td><code>{s.command}</code></td><td><code>{s.digest}</code></td><td>{s.evidence_digest ? <code>{s.evidence_digest}</code> : 'none'}</td></tr>
       ))}
      </tbody>
     </table>
     <table aria-label="Cutover frontier">
      <caption>Frontier: the position of each source at the barrier</caption>
      <thead><tr><th scope="col">Source</th><th scope="col">Version</th><th scope="col">Cursor group</th><th scope="col">Cursor index</th></tr></thead>
      <tbody>
       {c.frontier.length === 0 && <tr><td colSpan={4}>No source position is recorded.</td></tr>}
       {c.frontier.map((f) => <tr key={f.source}><td><code>{f.source}</code></td><td>{f.version}</td><td><code>{f.cursor.group}</code></td><td>{f.cursor.index}</td></tr>)}
      </tbody>
     </table>
    </>
   )}

   <table aria-label="Delivery accounting" data-cutover-accounting>
    <caption>Delivery accounting of the product's own deliveries</caption>
    <thead><tr><th scope="col">Pending</th><th scope="col">Claimed (in flight)</th><th scope="col">Lapsed</th><th scope="col">Unknown outcome</th><th scope="col">Unknown digest</th></tr></thead>
    <tbody><tr><td>{view.accounting.pending}</td><td>{view.accounting.claimed}</td><td>{view.accounting.lapsed}</td><td>{view.accounting.unknown}</td><td><code>{view.accounting.unknown_digest}</code></td></tr></tbody>
   </table>

   <div data-cutover-shadow={view.shadow.observing ? 'observing' : 'ended'}>
    <h5>Shadow decisions</h5>
    <p>Shadow decisions are recorded and never sent. {view.shadow.observing ? 'The product is observing: new decisions are shadow decisions.' : 'The product is not observing now; the decisions below were made earlier.'} Decisions recorded: {view.shadow.decisions}.</p>
    <table aria-label="Shadow decisions by kind">
     <caption>Shadow decisions by kind</caption>
     <thead><tr><th scope="col">Kind</th><th scope="col">Decisions</th></tr></thead>
     <tbody>
      {kinds.length === 0 && <tr><td colSpan={2}>None.</td></tr>}
      {kinds.map((k) => <tr key={k.kind}><td>{k.kind}</td><td>{k.count}</td></tr>)}
     </tbody>
    </table>
    <table aria-label="Recent shadow decisions" data-cutover-recent>
     <caption>The newest shadow decisions (at most 50; the counts above cover all of them)</caption>
     <thead><tr><th scope="col">Decided</th><th scope="col">Kind</th><th scope="col">Subject</th><th scope="col">Recipient</th><th scope="col">Delivery</th><th scope="col">Digest</th></tr></thead>
     <tbody>
      {view.shadow.recent.length === 0 && <tr><td colSpan={6}>No shadow decision.</td></tr>}
      {view.shadow.recent.map((r) => <tr key={r.id}><td>{when(r.decided_ns, tz)}</td><td>{r.kind}</td><td>{r.subject}</td><td>{r.recipient ? <code>{r.recipient}</code> : 'none'}</td><td><code>{r.id}</code></td><td><code>{r.digest}</code></td></tr>)}
     </tbody>
    </table>
   </div>

   <div data-cutover-history>
    <h5>History boundary</h5>
    <p>Legacy history is read-only and lives outside this product{view.history.legacy_owner ? <> (legacy owner <code>{view.history.legacy_owner}</code>)</> : null}. The product has no importer for it and deletes none of it.</p>
    <table aria-label="History spans">
     <caption>Who owned normal notifications, oldest first</caption>
     <thead><tr><th scope="col">Side</th><th scope="col">Owner</th><th scope="col">Phase</th><th scope="col">From</th><th scope="col">To</th></tr></thead>
     <tbody>
      {spans.length === 0 && <tr><td colSpan={5}>No boundary: the product is the only owner and there is no legacy history to join.</td></tr>}
      {spans.map((s, i) => <tr key={`${s.from_ns}-${i}`}><td>{sideWords(s.side)}</td><td>{s.owner ? <code>{s.owner}</code> : 'none'}</td><td>{PHASE_WORDS[s.phase]}</td><td>{when(s.from_ns, tz)}</td><td>{s.to_ns === undefined ? 'open' : when(s.to_ns, tz)}</td></tr>)}
     </tbody>
    </table>
   </div>
  </>
 );
}
