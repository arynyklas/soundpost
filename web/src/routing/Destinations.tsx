// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { getPolicies, isAbort, listDestinations, saveDestination, stateOfFault } from '../api/client';
import type { DestinationSave, Id, LoadState, ManagedDestination } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { describeAdminFailure, type AdminCommitted } from '../settings/admin';
import { AuditedForm } from '../settings/AuditedForm';
import { CHANNELS, buildDestinationChange, buildNewDestination, channelLabel, destinationWords, emptyNewDestination, withSaved, type NewDestinationDraft } from '../settings/destinations';
import { Panel } from '../settings/SettingsUi';
import { Icon } from '../ui/Icon';
import { Dialog, Pill } from '../ui/primitives';

interface Read { destinations: ManagedDestination[]; manage: boolean }

/** The organization's destinations read through the project the screen is shown for, keyed to the scope it was asked for. `reload` reads again and
 * keeps the answer on screen until the new one arrives, so a form being used is never torn down by a refresh. */
function useDestinations(context: ViewContext, project: Id): { load: LoadState<Read>; reload: () => void } {
 const key = `${scopeKey(context)}|${project}|${context.generation}`;
 const [held, setHeld] = React.useState<{ key: string; load: LoadState<Read> }>({ key: '', load: { kind: 'loading' } });
 const [tick, setTick] = React.useState(0);
 React.useEffect(() => {
  const ctl = new AbortController();
  Promise.all([listDestinations(context.org, project, ctl.signal), getPolicies(context.org, project, ctl.signal)]).then(
   ([destinations, policy]) => { if (!ctl.signal.aborted) setHeld({ key, load: { kind: 'ready', data: { destinations, manage: policy.manage_destinations } } }); },
   (e: unknown) => { if (!ctl.signal.aborted && !isAbort(e)) setHeld({ key, load: stateOfFault(e) }); },
  );
  return () => ctl.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [key, tick]);
 return { load: held.key === key ? held.load : { kind: 'loading' }, reload: () => setTick((n) => n + 1) };
}

interface FormProps { context: ViewContext; project: Id; reload: () => void; onSaved: (saved: ManagedDestination) => void }

/** One save of one destination over POST /api/v1/destinations. `version` is the version the page read: a destination changed since is a conflict and nothing is changed. */
function saveFor(props: FormProps, version: string): (sent: { commandId: Id; reason: string; change: { payload: Record<string, unknown> } }, signal: AbortSignal) => Promise<AdminCommitted> {
 return async (sent, signal) => {
  const saved = await saveDestination({ org: props.context.org, project_id: props.project, command_id: sent.commandId, expected_version: version, reason: sent.reason, destination: sent.change.payload as unknown as DestinationSave }, signal);
  props.onSaved(saved);
  return {};
 };
}

function ChangeForm(props: FormProps & { destination: ManagedDestination }): React.JSX.Element {
 const d = props.destination;
 const [enabled, setEnabled] = React.useState(d.enabled);
 const [secret, setSecret] = React.useState('');
 React.useEffect(() => { setEnabled(d.enabled); }, [d.enabled, d.version]);
 return (
  <AuditedForm<AdminCommitted>
   name={`destination-${d.id}`} label={`Change destination ${d.id}`} submitLabel="Save destination" describe={describeAdminFailure} onStale={props.reload}
   check={() => { const built = buildDestinationChange(d, enabled, secret); return built.ok ? null : built.error; }}
   fingerprint={() => JSON.stringify([enabled, secret, d.version])}
   run={(commandId, reason, signal) => { const built = buildDestinationChange(d, enabled, secret); return built.ok ? saveFor(props, d.version)({ commandId, reason, change: { payload: { ...built.value } } }, signal) : Promise.reject(new Error(built.error)); }}
   saved={() => 'Saved. The server committed this change.'}
   onCommitted={() => { setSecret(''); props.reload(); }}>
   <label className="check"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} data-autofocus /> Enabled</label>
   <label>New secret (write-only; sealed on save and never shown again; leave empty to keep the sealed one) <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" spellCheck={false} /></label>
  </AuditedForm>
 );
}

function NewForm(props: FormProps): React.JSX.Element {
 const [draft, setDraft] = React.useState<NewDestinationDraft>(emptyNewDestination());
 const [fresh, setFresh] = React.useState<Id>(() => newCommandId());
 const set = (key: keyof NewDestinationDraft) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>): void => setDraft((v) => ({ ...v, [key]: e.target.value }));
 return (
  <AuditedForm<AdminCommitted>
   name="destination-new" label="Add a notification destination" submitLabel="Add destination" describe={describeAdminFailure} onStale={props.reload}
   check={() => { const built = buildNewDestination(fresh, draft); return built.ok ? null : built.error; }}
   fingerprint={() => JSON.stringify([fresh, draft])}
   run={(commandId, reason, signal) => { const built = buildNewDestination(fresh, draft); return built.ok ? saveFor(props, '0')({ commandId, reason, change: { payload: { ...built.value } } }, signal) : Promise.reject(new Error(built.error)); }}
   saved={() => 'Saved. The server committed this destination.'}
   onCommitted={() => { setDraft(emptyNewDestination()); setFresh(newCommandId()); props.reload(); }}>
   <label>Type <select value={draft.channel} onChange={set('channel')} data-autofocus>{CHANNELS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}</select></label>
   {draft.channel === 'webhook' && <label>Endpoint (https, no credentials, query or fragment) <input value={draft.endpoint} onChange={set('endpoint')} autoComplete="off" spellCheck={false} /></label>}
   {draft.channel === 'smtp' && <label>Recipient address <input value={draft.address} onChange={set('address')} autoComplete="off" spellCheck={false} /></label>}
   {draft.channel === 'telegram' && <label>Telegram chat (numeric ID or @channel) <input value={draft.address} onChange={set('address')} autoComplete="off" spellCheck={false} /></label>}
   <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft((v) => ({ ...v, enabled: e.target.checked }))} /> Enabled</label>
   <label>Secret (write-only; sealed on save and never shown again) <input type="password" value={draft.secret} onChange={set('secret')} autoComplete="new-password" spellCheck={false} /></label>
  </AuditedForm>
 );
}

function DestinationRow(props: FormProps & { destination: ManagedDestination; manage: boolean }): React.JSX.Element {
 const d = props.destination;
 const [open, setOpen] = React.useState(false);
 return (
  <li data-destination={d.id} data-destination-channel={d.channel} data-destination-enabled={String(d.enabled)} data-destination-secret={d.has_secret ? 'set' : 'none'} data-destination-version={d.version}>
   <div className="row wrap set-dest-head">
    <Pill tone={d.enabled ? 'ok' : 'line'} icon={d.enabled ? 'check' : 'pause'}>{d.enabled ? 'Enabled' : 'Paused'}</Pill>
    <b className="grow ellipsis">{channelLabel(d.channel)}</b>
    {props.manage && <button type="button" className="btn btn-sm" onClick={() => setOpen(true)} aria-label={`Change ${channelLabel(d.channel)} destination ${d.display || d.id}`}><Icon name="edit" size="xs" />Change</button>}
   </div>
   <span className="xsmall t3">{destinationWords(d)}</span>
   {props.manage && (
    <Dialog open={open} onClose={() => setOpen(false)} title={`Change ${channelLabel(d.channel)} destination`}>
     <div className="modal-body"><ChangeForm {...props} destination={d} /></div>
    </Dialog>
   )}
  </li>
 );
}

/** Notification destinations: the channels (signed webhook, email, Telegram) every project of the organization notifies, over POST /api/v1/destinations.
 * Each destination carries its own version and a save is based on the version this screen read, so a destination changed by someone else is a visible
 * conflict, never an overwrite. Saving needs organization administration (a destination routes every project of the organization), so an account that
 * holds only policy.write on the project reads the list and is told it cannot change it. The endpoint path and the secret are never shown or returned.
 * The list is configuration only: this screen has no per-destination delivery health to report, so it states none. */
export function DestinationsPanel(props: { context: ViewContext; project: Id }): React.JSX.Element {
 const { load, reload } = useDestinations(props.context, props.project);
 const [saved, setSaved] = React.useState<ManagedDestination | null>(null);
 const [adding, setAdding] = React.useState(false);
 // A newer read from the server replaces what a save answered: the list is always the server's own.
 React.useEffect(() => { setSaved(null); }, [load]);
 const data = load.kind === 'ready' ? load.data : undefined;
 const shown = data ? (saved ? withSaved(data.destinations, saved) : data.destinations) : [];
 const form: FormProps = { context: props.context, project: props.project, reload, onSaved: setSaved };
 return (
  <div data-settings-page="destinations">
   <Panel title="Destinations" actions={data?.manage ? <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}><Icon name="plus" size="xs" />New destination</button> : undefined}>
    <div className="col g12">
     {load.kind !== 'ready' && <StatusPanel state={load} />}
     {data && (
      <>
       <p className="small t2">Destinations belong to the organization: every enabled destination receives the notifications of every project of it. A secret is sealed when saved and is never shown.{data.manage ? ' You administer this organization.' : ' Only organization administrators change destinations: you can read them through your policy.write grant on this project.'}</p>
       {shown.length === 0
        ? <p role="status" data-state="empty" className="set-empty">No destination is configured: notifications stay in the product queue and are never sent.</p>
        : <ul className="feed set-feed" aria-label="Destinations of the organization">{shown.map((d) => <DestinationRow key={d.id} {...form} destination={d} manage={data.manage} />)}</ul>}
       <p className="xsmall t3">Three kinds exist: e-mail (SMTP), Telegram and signed HTTPS webhook. This list shows configuration; delivery results per destination are not reported here.</p>
      </>
     )}
    </div>
   </Panel>
   {data?.manage && (
    <Dialog open={adding} onClose={() => setAdding(false)} title="New notification destination">
     <div className="modal-body"><NewForm {...form} /></div>
    </Dialog>
   )}
  </div>
 );
}
