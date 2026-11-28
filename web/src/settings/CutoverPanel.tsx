// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { isAbort, stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { projectLabel, useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { Callout, Card, cx } from '../ui/primitives';
import { PATH_WORDS, PHASE_WORDS, getCutover, kindCounts, orderedSpans, ownerStatement, phasePath, restoreWarning, sideWords, type CutoverView } from './cutover';
import { Facts, PlainTable } from './SettingsUi';

/** Read-only: who owns normal notifications, the committed timeline, the delivery accounting, the shadow decisions and the legacy history boundary.
 * Nothing here advances the cutover; only the operator flow does. Every state is spelled out in words, never by colour alone. */
export function CutoverPanel(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const c = props.context;
 const { names } = useShell();
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
 const heading = `cutover-${props.project}`;
 return (
  <div data-section="cutover" data-project-cutover={props.project}>
   <Card title="Notification cutover" titleId={heading} actions={<span className="small t3">Project {projectLabel(names, props.project)}</span>}>
    <div className="col g16">
     <p className="small t2">Read-only. The cutover is advanced only by the operator flow; nothing on this page changes it.</p>
     {load.kind === 'loading' && <p role="status">Loading the cutover state…</p>}
     {load.kind !== 'ready' && load.kind !== 'loading' && <StatusPanel state={load} />}
     {load.kind === 'ready' && <CutoverBody view={load.data} tz={c.timezone} />}
    </div>
   </Card>
  </div>
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
   <div data-cutover-owner={owner.owner ?? 'none'} data-cutover-phase={c?.phase ?? 'none'} className="col g12">
    <h3>Who owns normal notifications now</h3>
    <p><strong>{owner.headline}</strong>{owner.owner !== null && <> Owner <code>{owner.owner}</code>.</>} {owner.detail}</p>
    {c && (
     <Facts items={[
      ['Phase', <>{PHASE_WORDS[c.phase]} (<code>{c.phase}</code>), epoch {c.epoch}, revision {c.revision}, entered {when(c.entered_at_ns, tz)}</>],
      ['Old (legacy) owner', <code>{c.old_owner}</code>],
      ['New owner', <code>{c.new_owner}</code>],
      ['Active owners', c.active_owners.length === 0 ? 'none (handover)' : <span className="row wrap">{c.active_owners.map((o) => <code key={o}>{o}</code>)}</span>],
     ]} />
    )}
   </div>
   {c && (
    <ol className="steps set-phases" aria-label="Phases of the cutover, in order">
     {phasePath(c).map((p, i) => (
      <li key={p.phase} data-phase-state={p.state}>
       <span className={cx('no', p.state === 'passed' && 'no-ok', p.state === 'current' && 'no-cur')}>{p.state === 'passed' ? <Icon name="check" size="xs" /> : i + 1}</span>
       <div className="col g4"><b>{PHASE_WORDS[p.phase]}</b><span className="small t2"><code>{p.phase}</code></span></div>
       <span className="small t3">{PATH_WORDS[p.state]}</span>
      </li>
     ))}
    </ol>
   )}
   {warning && <Callout tone="crit" role="alert"><span data-cutover-restore-pending={c?.restore.pending}><strong>Restore pending.</strong> {warning}</span></Callout>}
   {c && c.restore.acknowledged !== undefined && !warning && <p role="status">Restore generation <code>{c.restore.acknowledged}</code> was acknowledged.</p>}

   {c && (
    <>
     <PlainTable label="Cutover timeline" caption="Timeline of committed transitions, oldest first" tableAttrs={{ 'data-cutover-timeline': '' }}
      columns={['Revision', 'From', 'To', 'Epoch', 'At', 'Operator', 'Command', 'Digest', 'Evidence digest']} empty="No transition has been committed yet."
      rows={c.timeline.map((s) => [s.revision, s.from === '' ? 'Created (no previous phase)' : PHASE_WORDS[s.from], PHASE_WORDS[s.to], s.epoch, when(s.at_ns, tz), <code key="p">{s.principal}</code>, <code key="c">{s.command}</code>, <code key="d">{s.digest}</code>, s.evidence_digest ? <code key="e">{s.evidence_digest}</code> : 'none'])} />
     <PlainTable label="Cutover frontier" caption="Frontier: the position of each source at the barrier" columns={['Source', 'Version', 'Cursor group', 'Cursor index']} empty="No source position is recorded."
      rows={c.frontier.map((f) => [<code key="s">{f.source}</code>, f.version, <code key="g">{f.cursor.group}</code>, f.cursor.index])} />
    </>
   )}

   <PlainTable label="Delivery accounting" caption="Delivery accounting of the product's own deliveries" tableAttrs={{ 'data-cutover-accounting': '' }}
    columns={['Pending', 'Claimed (in flight)', 'Lapsed', 'Unknown outcome', 'Unknown digest']} empty="No accounting."
    rows={[[view.accounting.pending, view.accounting.claimed, view.accounting.lapsed, view.accounting.unknown, <code key="u">{view.accounting.unknown_digest}</code>]]} />

   <div data-cutover-shadow={view.shadow.observing ? 'observing' : 'ended'} className="col g12">
    <h3>Shadow decisions</h3>
    <p>Shadow decisions are recorded and never sent. {view.shadow.observing ? 'The product is observing: new decisions are shadow decisions.' : 'The product is not observing now; the decisions below were made earlier.'} Decisions recorded: {view.shadow.decisions}.</p>
    <PlainTable label="Shadow decisions by kind" columns={['Kind', 'Decisions']} empty="None." rows={kinds.map((k) => [k.kind, k.count])} />
    <PlainTable label="Recent shadow decisions" caption="The newest shadow decisions (at most 50; the counts above cover all of them)" tableAttrs={{ 'data-cutover-recent': '' }}
     columns={['Decided', 'Kind', 'Subject', 'Recipient', 'Delivery', 'Digest']} empty="No shadow decision."
     rows={view.shadow.recent.map((r) => [when(r.decided_ns, tz), r.kind, r.subject, r.recipient ? <code key="r">{r.recipient}</code> : 'none', <code key="i">{r.id}</code>, <code key="d">{r.digest}</code>])} />
   </div>

   <div data-cutover-history className="col g12">
    <h3>History boundary</h3>
    <p>Legacy history is read-only and lives outside this product{view.history.legacy_owner ? <> (legacy owner <code>{view.history.legacy_owner}</code>)</> : null}. The product has no importer for it and deletes none of it.</p>
    <PlainTable label="History spans" caption="Who owned normal notifications, oldest first" columns={['Side', 'Owner', 'Phase', 'From', 'To']} empty="No boundary: the product is the only owner and there is no legacy history to join."
     rows={spans.map((s) => [sideWords(s.side), s.owner ? <code key="o">{s.owner}</code> : 'none', PHASE_WORDS[s.phase], when(s.from_ns, tz), s.to_ns === undefined ? 'open' : when(s.to_ns, tz)])} />
   </div>
  </>
 );
}
