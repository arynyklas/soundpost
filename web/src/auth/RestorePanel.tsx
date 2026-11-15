// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { request, RequestFailure, type Session } from './api';

/** One quarantined item exactly as POST /api/v1/restore/items names it (internal/auth/restore_view.go). */
export interface RestoreItem { kind: string; org?: string; user?: string; project?: string; source?: string; id?: string; key?: string; label: string }
interface RestoreView { pending: number; items: RestoreItem[] }
interface Reconciled { kind: string; audit: string; credential?: string }

const KIND_WORDS: Record<string, string> = { account: 'Account', org_admin: 'Organization administrator', membership: 'Membership', grant: 'Project grant', team: 'Team', integration: 'Integration', reader: 'Source reader', source: 'Source' };
/** Single sign-on providers of the backup are never reactivated from here: the identity authority they trusted may no longer be the current one. */
export const offersReauthorization = (item: RestoreItem): boolean => !(item.kind === 'integration' && (item.key ?? '').startsWith('sso:'));
/** The body of POST /api/v1/restore/reconcile: the item's own identifiers (auth.Reconciliation) and the reason. */
export function reconciliation(item: RestoreItem, reason: string): Record<string, string> {
 const body: Record<string, string> = { Kind: item.kind, Reason: reason };
 if (item.org) body.Org = item.org;
 if (item.user) body.User = item.user;
 if (item.project) body.Project = item.project;
 if (item.source) body.Source = item.source;
 if (item.id) body.ID = item.id;
 if (item.key) body.Key = item.key;
 return body;
}

/** The restored-installation state: what the backup held that is still inactive, and one audited reauthorization per item. */
export function RestorePanel(props: { csrf: string; pending: number; /** A scoped panel (settings pages): its own region name and heading, the items it lists and the sentence that introduces them. */ label?: string; title?: string; intro?: string; only?: (item: RestoreItem) => boolean }): React.JSX.Element {
 const csrf = React.useRef(props.csrf);
 React.useEffect(() => { csrf.current = props.csrf; }, [props.csrf]);
 const [view, setView] = React.useState<RestoreView | null>(null);
 const [loadError, setLoadError] = React.useState('');
 const [chosen, setChosen] = React.useState<RestoreItem | null>(null);
 const [busy, setBusy] = React.useState(false);
 const [error, setError] = React.useState('');
 const [done, setDone] = React.useState('');
 const [credential, setCredential] = React.useState('');
 const load = React.useCallback(async (): Promise<void> => {
  try { setView(await request<RestoreView>('restore/items', {}, csrf.current)); setLoadError(''); }
  catch (e) { setView(null); setLoadError(e instanceof RequestFailure && e.status === 403 ? 'Only an instance administrator who is not itself a restored account can list or reauthorize restored access.' : e instanceof Error ? e.message : 'The restored items could not be read.'); }
 }, []);
 React.useEffect(() => { void load(); }, [load, props.pending]);
 async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
  event.preventDefault();
  if (!chosen) return;
  const form = event.currentTarget, data = new FormData(form), reason = String(data.get('reason') ?? '');
  if (!reason || new TextEncoder().encode(reason).length > 512) { setError('Reason must contain 1–512 UTF-8 bytes.'); return; }
  setBusy(true); setError(''); setDone(''); setCredential('');
  try {
   // Fresh authentication first (it rotates the session), then one reconciliation that commits its audit in the same transaction.
   const session = await request<Session>('reauthenticate', { Password: String(data.get('password') ?? ''), Code: String(data.get('code') ?? '') }, csrf.current);
   csrf.current = session.csrf;
   const result = await request<Reconciled>('restore/reconcile', reconciliation(chosen, reason), csrf.current);
   setDone(`Reinstated: ${chosen.label}. Audit record ${result.audit}. Nothing beyond this one item was reinstated.`);
   if (result.credential) setCredential(result.credential);
   setChosen(null); form.reset();
   await load();
  } catch (e) { setError(e instanceof Error ? e.message : 'The reauthorization was not confirmed.'); }
  finally { setBusy(false); }
 }
 const items = (view?.items ?? []).filter(props.only ?? (() => true));
 const Heading = props.title ? 'h3' : 'h2';
 return <section className="panel notice" aria-label={props.label ?? 'Restored installation'} data-restore-pending={view ? String(view.pending) : props.pending}>
  <Heading>{props.title ?? 'Restored installation: access is bootstrap-only'}</Heading>
  <p>{props.intro ?? 'This installation was restored from a backup. Every earlier session, token, source credential and sender is inactive, and the accounts, memberships, grants, teams and integrations the backup held stay inactive until an instance administrator reauthorizes them here, one item at a time, with fresh authentication and an audit record. Logouts, revocations and demotions made after the backup are not undone by a restore.'}</p>
  <p role="status" aria-live="polite">{view ? (props.only ? `${items.length} of the ${view.pending} inactive item${view.pending === 1 ? '' : 's'} of this installation ${items.length === 1 ? 'belongs' : 'belong'} here.` : `${view.pending} item${view.pending === 1 ? '' : 's'} still inactive.`) : loadError ? '' : 'Reading the restored items…'}</p>
  {loadError && <p role="alert" className="error">{loadError}</p>}
  {done && <p role="status" data-restore-done="true">{done}</p>}
  {credential && <p>New source credential, shown once: <output className="secret">{credential}</output></p>}
  {items.length > 0 && <ul aria-label="Inactive restored items">{items.map((item) => <li key={`${item.kind}|${item.org ?? ''}|${item.user ?? ''}|${item.project ?? ''}|${item.source ?? ''}|${item.id ?? ''}|${item.key ?? ''}`} data-restore-kind={item.kind}>
   <strong>{KIND_WORDS[item.kind] ?? item.kind}</strong>: {item.label}{' '}
   {offersReauthorization(item) ? <button type="button" disabled={busy} aria-label={`Reauthorize ${KIND_WORDS[item.kind] ?? item.kind}: ${item.label}`} onClick={() => { setChosen(item); setError(''); setDone(''); }}>Reauthorize</button> : <span>Not offered here: register a single sign-on provider again against the current identity authority.</span>}
  </li>)}</ul>}
  {chosen && <form onSubmit={(event) => { void submit(event); }} aria-busy={busy} className="panel">
   <h3>Reauthorize: {chosen.label}</h3>
   <label>Reason<textarea name="reason" required maxLength={512} /></label>
   <label>Current password<input type="password" name="password" required autoComplete="current-password" /></label>
   <label>Authenticator or recovery code<input name="code" autoComplete="one-time-code" /></label>
   {error && <p role="alert" className="error">{error}</p>}
   <button className="primary" disabled={busy}>{busy ? 'Committing audited reauthorization…' : 'Reauthenticate and reauthorize'}</button>
   <button type="button" disabled={busy} onClick={() => { setChosen(null); setError(''); }}>Cancel</button>
  </form>}
  {!chosen && error && <p role="alert" className="error">{error}</p>}
 </section>;
}
