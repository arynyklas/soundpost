// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { EVENTS, listDeliveries, listEndpoints, saveEndpoint, testEndpoint, type DeliveryView, type EndpointList, type EndpointView } from '../api/events';
import { stateOfFault } from '../api/client';
import type { Id, LoadState } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { Content, PageHead } from '../shell/Frames';
import { useShell } from '../shell/ShellContext';
import { Icon } from '../ui/Icon';
import { DataTable, Dialog, EmptyState, NotAvailable, Pill } from '../ui/primitives';
import { describeAdminFailure } from './admin';
import { AuditedForm } from './AuditedForm';
import { Panel } from './SettingsUi';
import { buildEndpointSave, deliveryWords, emptyEndpointDraft, endpointDraftOf, endpointWords, rotationWords, type EndpointDraft } from './webhooks';

type Loaded = LoadState<EndpointList> | { kind: 'not_built' };

function useEndpoints(context: ViewContext): { load: Loaded; reload: () => void } {
 const key = `${scopeKey(context)}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: Loaded }>({ key: '', load: { kind: 'loading' } });
 const [tick, setTick] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  listEndpoints(context.org, ctl.signal).then(
   (r) => { if (!ctl.signal.aborted) setHeld({ key, load: r.kind === 'ok' ? { kind: 'ready', data: r.data } : r.kind === 'not_built' ? { kind: 'not_built' } : stateOfFault(r.fault) }); },
   (e: unknown) => { if (!ctl.signal.aborted && !(e instanceof DOMException && e.name === 'AbortError')) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, tick]);
 return { load: held.key === key ? held.load : { kind: 'loading' }, reload: () => setTick((n) => n + 1) };
}

function EndpointForm(props: { org: Id; events: readonly string[]; existing?: EndpointView; reload: () => void; tz: string }): React.JSX.Element {
 const e = props.existing;
 const [draft, setDraft] = React.useState<EndpointDraft>(() => (e ? endpointDraftOf(e) : emptyEndpointDraft()));
 const [fresh, setFresh] = React.useState<Id>(() => newCommandId());
 const id = e?.id ?? fresh;
 const set = (key: 'name' | 'url' | 'secret') => (ev: React.ChangeEvent<HTMLInputElement>): void => setDraft((d) => ({ ...d, [key]: ev.target.value }));
 const flip = (name: string): void => setDraft((d) => ({ ...d, events: d.events.includes(name) ? d.events.filter((x) => x !== name) : [...d.events, name] }));
 return (
  <AuditedForm<{ rotated: boolean }>
   name={e ? `endpoint-${e.id}` : 'endpoint-new'} label={e ? `Change event endpoint ${e.id}` : 'Add an event endpoint'} submitLabel={e ? 'Save endpoint' : 'Add endpoint'} describe={describeAdminFailure} onStale={props.reload}
   check={() => { const built = buildEndpointSave(id, draft, e); return built.ok ? null : built.error; }}
   fingerprint={() => JSON.stringify([id, draft, e?.version ?? '0'])}
   run={async (commandId, reason, signal) => {
    const built = buildEndpointSave(id, draft, e);
    if (!built.ok) throw new Error(built.error);
    await saveEndpoint({ org: props.org, commandId, expectedVersion: e?.version ?? '0', reason, endpoint: built.value }, signal);
    return { rotated: e !== undefined && built.value.secret !== undefined };
   }}
   saved={(r) => (r.rotated ? 'Saved. The server committed this change: the secret was rotated, and until the overlap ends every request carries two signatures.' : 'Saved. The server committed this change.')}
   onCommitted={() => { if (e) setDraft((d) => ({ ...d, secret: '', url: '' })); else { setDraft(emptyEndpointDraft()); setFresh(newCommandId()); } props.reload(); }}>
   <label>Name <input value={draft.name} onChange={set('name')} maxLength={64} autoComplete="off" data-autofocus /></label>
   <label>Address (https, no credentials, query or fragment){e ? ` — now ${e.host}; leave empty to keep the stored address` : ''} <input value={draft.url} onChange={set('url')} autoComplete="off" spellCheck={false} /></label>
   <fieldset className="set-perm-set">
    <legend>Events</legend>
    <div className="set-checks">
     {props.events.map((n) => <label className="check" key={n}><input type="checkbox" checked={draft.events.includes(n)} onChange={() => flip(n)} /> <code>{n}</code> <span className="t3">{EVENTS.find((x) => x.name === n)?.about ?? ''}</span></label>)}
    </div>
   </fieldset>
   <label>{e ? 'New secret (write-only; sending one rotates it: both secrets sign for 24 hours; leave empty to keep the sealed one)' : 'Secret (write-only, 16 to 256 bytes; sealed on save and never shown again)'} <input type="password" value={draft.secret} onChange={set('secret')} autoComplete="new-password" spellCheck={false} /></label>
   <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(ev) => setDraft((d) => ({ ...d, enabled: ev.target.checked }))} /> Enabled</label>
   {e && <p className="small t2">{rotationWords(e, (ns) => formatNs(ns, props.tz))}</p>}
  </AuditedForm>
 );
}

function EndpointActions(props: { org: Id; events: readonly string[]; endpoint: EndpointView; reload: () => void; tz: string; selected: boolean; onShow: () => void }): React.JSX.Element {
 const [open, setOpen] = React.useState(false);
 return (
  <span className="row wrap">
   <button type="button" className="btn btn-sm" aria-pressed={props.selected} aria-label={`Show deliveries of ${props.endpoint.name}`} onClick={props.onShow}><Icon name="send" size="xs" />Deliveries</button>
   <button type="button" className="btn btn-sm" aria-label={`Change event endpoint ${props.endpoint.name}`} onClick={() => setOpen(true)}><Icon name="edit" size="xs" />Change</button>
   <Dialog open={open} onClose={() => setOpen(false)} title={`Change endpoint ${props.endpoint.name}`} tall>
    <div className="modal-body"><EndpointForm org={props.org} events={props.events} existing={props.endpoint} reload={props.reload} tz={props.tz} /></div>
   </Dialog>
  </span>
 );
}

function DeliveryRow(props: { d: DeliveryView; tz: string }): React.JSX.Element {
 const d = props.d, w = deliveryWords(d);
 return (
  <li data-delivery-phase={d.phase} data-delivery-uncertain={String(d.uncertain)}>
   <Pill tone={w.tone} {...(w.tone === 'ok' ? { icon: 'check' as const } : w.tone === 'crit' ? { icon: 'x' as const } : w.tone === 'unk' ? { icon: 'question' as const } : {})}>{w.label}</Pill>
   <div className="col g4 grow">
    <span className="ellipsis"><code>{d.event}</code>{d.entity ? <> · <code>{d.entity}</code></> : null}</span>
    <span className="xsmall t3">{d.attempts === null ? 'attempts not reported' : `${d.attempts} attempt${d.attempts === 1 ? '' : 's'}`}{d.code ? `, closed with ${d.code}` : d.lastCode ? `, last attempt ${d.lastCode}` : ''}{d.at ? ` · ${formatNs(d.at, props.tz)}` : ''}{w.text ? ` · ${w.text}` : ''}{d.possibleDuplicate && !d.uncertain ? ' · The receiver may already have it: deduplicate by delivery ID.' : ''}</span>
   </div>
  </li>
 );
}

type Deliveries = { kind: 'loading' } | { kind: 'not_built' } | { kind: 'ready'; items: DeliveryView[] } | { kind: 'fault'; state: LoadState<unknown> };

function DeliveriesPanel(props: { org: Id; endpoint: EndpointView | undefined; tz: string }): React.JSX.Element {
 const endpoint = props.endpoint;
 const [tick, setTick] = React.useState(0);
 const [state, setState] = React.useState<{ key: string; d: Deliveries }>({ key: '', d: { kind: 'loading' } });
 const [note, setNote] = React.useState('');
 const key = `${endpoint?.id ?? ''}|${tick}`;
 React.useEffect(() => {
  if (!endpoint) return;
  const ctl = new AbortController();
  listDeliveries(props.org, endpoint.id, ctl.signal).then(
   (r) => { if (!ctl.signal.aborted) setState({ key, d: r.kind === 'ok' ? { kind: 'ready', items: r.data } : r.kind === 'not_built' ? { kind: 'not_built' } : { kind: 'fault', state: stateOfFault(r.fault) } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !(e instanceof DOMException && e.name === 'AbortError')) setState({ key, d: { kind: 'fault', state: stateOfFault(e) } }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key]);
 React.useEffect(() => { setNote(''); }, [endpoint?.id]);
 const d: Deliveries = state.key === key ? state.d : { kind: 'loading' };
 const test = (): void => {
  if (!endpoint) return;
  setNote('Sending…');
  testEndpoint({ org: props.org, endpoint: endpoint.id, commandId: newCommandId() }, new AbortController().signal).then(
   () => { setNote('A test event was requested. The leader creates it within a few seconds: refresh the list to see what happened to it; this is not a claim that the receiver got it.'); setTick((n) => n + 1); },
   () => setNote('The test event was not confirmed as requested. Nothing is shown as sent.'),
  );
 };
 return (
  <Panel title="Deliveries">
   <div className="col g12">
    {!endpoint ? <p className="small t2">Choose “Deliveries” on an endpoint to see what happened to its recent events.</p> : (
     <>
      <p className="small"><b>{endpoint.name}</b> <span className="t3">{endpoint.host}</span></p>
      {d.kind === 'loading' && <p role="status" className="small t2">Loading the deliveries…</p>}
      {d.kind === 'not_built' && <p role="status" data-state="unsupported" className="small t2">The delivery list is not available yet in this installation. Nothing is shown in its place.</p>}
      {d.kind === 'fault' && <StatusPanel state={d.state} />}
      {d.kind === 'ready' && (d.items.length === 0
       ? <p role="status" data-state="empty" className="small t2">No delivery was made to this endpoint yet.</p>
       : <ul className="feed set-feed" aria-label={`Recent deliveries to ${endpoint.name}`}>{d.items.map((x, i) => <DeliveryRow key={`${x.id ?? i}`} d={x} tz={props.tz} />)}</ul>)}
      <div className="row wrap"><button type="button" className="btn btn-sm" onClick={test} disabled={!endpoint.enabled}>Send a test event</button><button type="button" className="btn btn-sm" onClick={() => setTick((n) => n + 1)}><Icon name="refresh" size="xs" />Refresh</button></div>
      {!endpoint.enabled && <p className="xsmall t3">The endpoint is paused: enable it to send a test event.</p>}
      {note !== '' && <p role="status" className="xsmall t2">{note}</p>}
     </>
    )}
   </div>
  </Panel>
 );
}

const REQUEST_EXAMPLE = `POST <endpoint address>
Content-Type: application/json
Soundpost-Event: <event name>
Soundpost-Delivery-ID: <stable hex delivery id>
Soundpost-Timestamp: <unix seconds of this attempt>
Soundpost-Signature: v1=<hex>[,v1=<hex>]

{"version":1,"delivery_id":"<id>","event":"<event name>","occurred_at":"<ns>",
 "org":"<id>","project":"<id>","incident|issue|release":"<id>",
 "severity":"minor|major|critical","release_id":"<id>","service":"<id>",
 "revision":"<n>","url":"<link to the console>"}`;

/** Event webhooks: signed events for the organization's own scripts, over POST /api/v1/events/webhooks (organization administrators). Events carry identifiers and links only, never a
 * title, message, note or user text. Delivery goes through the same durable notification outbox as every destination: retried, and an uncertain outcome stays visible. A secret is
 * write-only; sending a new one rotates it, and for 24 hours both sign. An installation that does not serve the route yet says so. */
export function EventsRoute(props: { context: ViewContext }): React.JSX.Element {
 const c = props.context;
 const shell = useShell();
 const { load, reload } = useEndpoints(c);
 const [adding, setAdding] = React.useState(false);
 const [shown, setShown] = React.useState<Id | ''>('');
 const list = load.kind === 'ready' ? load.data : undefined;
 const selected = list?.endpoints.find((e) => e.id === shown);
 return (
  <>
   <PageHead crumb={<><a href={shell.href('settings')}>Settings</a><span aria-hidden="true">›</span></>} title="Event webhooks" sub="signed events for your own automation"
    actions={list ? <button type="button" className="btn btn-primary ml-auto" onClick={() => setAdding(true)}><Icon name="plus" size="s" />New endpoint</button> : undefined} />
   <Content>
    {load.kind === 'not_built' && <NotAvailable title="Event webhooks are not available yet">This installation does not serve event webhooks yet. Nothing is shown in their place.</NotAvailable>}
    {load.kind !== 'ready' && load.kind !== 'not_built' && <StatusPanel state={load} />}
    {list && (
     <div className="grid-side">
      <div className="col g16">
       <Panel title="Endpoints">
        {list.endpoints.length === 0
         ? <EmptyState icon="send" title="No endpoint">No event is sent anywhere. Add an endpoint to receive signed events.</EmptyState>
         : <DataTable label="Event webhook endpoints" rows={list.endpoints} rowKey={(e) => e.id} rowAttrs={(e) => ({ 'data-endpoint': e.id, 'data-endpoint-state': e.enabled ? e.state : 'paused' })} columns={[
          { key: 'name', header: 'Name', cell: (e) => <div className="cell-title"><span className="a">{e.name}</span><span className="s"><code>{e.host}</code></span></div> },
          { key: 'events', header: 'Events', cell: (e) => <span className="set-perms">{e.events.map((n) => <code key={n}>{n}</code>)}</span> },
          { key: 'state', header: 'State', cell: (e) => { const w = endpointWords(e); return <div className="col g4"><Pill tone={w.tone}>{w.label}</Pill><span className="xsmall t3">{w.text}</span></div>; } },
          { key: 'secret', header: 'Secret', cell: (e) => <div className="col g4"><Pill tone="line" icon="lock">{e.hasSecret ? 'write-only (never shown)' : 'not set'}</Pill><span className="xsmall t3">{rotationWords(e, (ns) => formatNs(ns, c.timezone))}</span></div> },
          { key: 'act', header: <span className="sr-only">Actions</span>, label: 'Actions', cell: (e) => <EndpointActions org={c.org} events={list.events} endpoint={e} reload={reload} tz={c.timezone} selected={shown === e.id} onShow={() => setShown(shown === e.id ? '' : e.id)} /> },
         ]} />}
       </Panel>
       <Panel title="Events">
        <ul className="set-events" aria-label="Events an endpoint can receive">
         {list.events.map((n) => <li key={n}><code>{n}</code><span className="t3"> · {EVENTS.find((x) => x.name === n)?.about ?? ''}</span></li>)}
        </ul>
        <p className="xsmall t3 set-sub">Identifiers and links only: never a title, a message, a note or user text. <code>test.ping</code> is sent by the test button. An organization has at most 32 endpoints. Saving and testing need a sign-in within the last five minutes: if refused, <a href={shell.href('account')}>reauthenticate on the account page</a> and try again.</p>
       </Panel>
       <Panel title="What a request looks like">
        <div className="col g12">
         <pre className="snippet" tabIndex={0} role="region" aria-label="Request headers and body of an event webhook">{REQUEST_EXAMPLE}</pre>
         <ul className="consequences">
          <li><Icon name="lock" size="s" /><span><b>Signature:</b> <code>v1=</code> is the hex HMAC-SHA256 of <code>&quot;&lt;timestamp&gt;.&lt;delivery id&gt;.&lt;exact body&gt;&quot;</code> under the endpoint&apos;s secret. While a secret is being rotated there are two <code>v1=</code> values; accept a request that matches either.</span></li>
          <li><Icon name="copy" size="s" /><span><b>Repeats:</b> a retry sends the same bytes and the same delivery ID. The receiver must deduplicate by delivery ID.</span></li>
          <li><Icon name="clock" size="s" /><span><b>Retries:</b> an event is retried up to 12 attempts within 24 hours. An outcome that is not known is shown as uncertain, never as accepted.</span></li>
          <li><Icon name="send" size="s" /><span><b>Address:</b> https, no credentials, query or fragment; private, loopback, link-local and metadata addresses are refused and redirects are not followed.</span></li>
         </ul>
        </div>
       </Panel>
      </div>
      <aside className="col g16" aria-label="Deliveries of an endpoint">
       <DeliveriesPanel org={c.org} endpoint={selected} tz={c.timezone} />
      </aside>
     </div>
    )}
   </Content>
   {list && (
    <Dialog open={adding} onClose={() => setAdding(false)} title="New event endpoint" tall>
     <div className="modal-body"><EndpointForm org={c.org} events={list.events} reload={reload} tz={c.timezone} /></div>
    </Dialog>
   )}
  </>
 );
}
