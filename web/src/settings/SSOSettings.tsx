// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import type { Id } from '../api/types';
import type { ViewContext } from '../app/context';
import { StatusPanel } from '../app/StatusPanel';
import { newCommandId } from '../incidents/model';
import { buildSso, ssoDraft, type AdminSetting, type SsoDraft } from './admin';
import { AdminForm, useAdminRead } from './AdminForm';

const emptyDraft = (): SsoDraft => ({ issuer: '', clientId: '', redirectUrl: `${window.location.origin}/api/v1/oidc/callback`, subjects: '' });

function ProviderForm(props: { org: Id; epoch: string; reload: () => void; providerId: Id | 'new'; initial: SsoDraft }): React.JSX.Element {
 const [draft, setDraft] = React.useState<SsoDraft>(props.initial);
 const [secret, setSecret] = React.useState('');
 const [fresh, setFresh] = React.useState<Id>(() => newCommandId());
 const id = props.providerId === 'new' ? fresh : props.providerId;
 const set = (key: keyof SsoDraft) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>): void => setDraft((d) => ({ ...d, [key]: e.target.value }));
 return (
  <AdminForm name={`sso-${props.providerId}`} label={props.providerId === 'new' ? 'Add a single sign-on provider' : `Change provider ${props.providerId}`} org={props.org} epoch={props.epoch} submitLabel={props.providerId === 'new' ? 'Add provider' : 'Save provider'} onStale={props.reload}
   onCommitted={() => { setSecret(''); if (props.providerId === 'new') { setDraft(emptyDraft()); setFresh(newCommandId()); } props.reload(); }}
   build={() => {
    const built = buildSso(draft);
    if (!built.ok) return built;
    if (secret.length > 4096) return { ok: false, error: 'The client secret is too long.' };
    return { ok: true, value: { kind: 'sso', payload: { id, config: built.value, ...(secret !== '' ? { secret } : {}) } } };
   }}>
   <label>Issuer (https) <input value={draft.issuer} onChange={set('issuer')} autoComplete="off" spellCheck={false} /></label>
   <label>Client ID <input value={draft.clientId} onChange={set('clientId')} autoComplete="off" spellCheck={false} /></label>
   <label>Redirect URL (https) <input value={draft.redirectUrl} onChange={set('redirectUrl')} autoComplete="off" spellCheck={false} /></label>
   <label>Client secret (write-only; sealed on save and never shown; leave empty to keep the sealed one) <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" spellCheck={false} /></label>
   <label>Identity mapping, one “subject = user ID” per line <textarea value={draft.subjects} onChange={set('subjects')} rows={4} spellCheck={false} /></label>
  </AdminForm>
 );
}

function provider(setting: AdminSetting): { id: Id; draft: SsoDraft; mapped: number } {
 const draft = ssoDraft(setting.config);
 return { id: setting.key.slice('sso:'.length), draft, mapped: draft.subjects === '' ? 0 : draft.subjects.split('\n').length };
}

/** Single sign-on: the identity providers an organization trusts and which identity maps to which account. An identity that is not mapped
 * is not signed in, and nothing here reads or returns a client secret: it is written once and sealed. */
export function SSOSettings(props: { context: ViewContext }): React.JSX.Element {
 const { load, reload } = useAdminRead(props.context, 'sso');
 const data = load.kind === 'ready' ? load.data : undefined;
 return (
  <div data-settings-page="sso">
   <h3>Single sign-on for organization <code>{props.context.org}</code></h3>
   {load.kind !== 'ready' && <StatusPanel state={load} />}
   {data && (
    <>
     <p data-testid="admin-revision" data-epoch={data.epoch}>Read at organization policy epoch {data.epoch}. An identity that no mapping names cannot sign in through a provider.</p>
     <section aria-labelledby="sso-list" data-section="sso">
      <h4 id="sso-list">Providers</h4>
      {data.settings.length === 0 ? <p role="status" data-state="empty">No single sign-on provider is configured.</p> : (
       <ul>{data.settings.map((s) => {
        const p = provider(s);
        return (
         <li key={s.key} data-sso={p.id}>
          <code>{p.id}</code> — issuer {p.draft.issuer}, client {p.draft.clientId}; {p.mapped} identity mapping{p.mapped === 1 ? '' : 's'}; client secret write-only (never shown).
          <ProviderForm org={props.context.org} epoch={data.epoch} reload={reload} providerId={p.id} initial={p.draft} />
         </li>
        );
       })}</ul>
      )}
      <ProviderForm org={props.context.org} epoch={data.epoch} reload={reload} providerId="new" initial={emptyDraft()} />
     </section>
    </>
   )}
  </div>
 );
}
