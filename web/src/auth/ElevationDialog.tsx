// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { request, type Id, type Session } from './api';
export interface ElevationState { id:string; expires:string; orgs:Id[] }
/** What the session boundary shares with the console: the session, the elevation state and the account actions the Account page and the sidebar use. */
export interface SessionValue {
 session: Session;
 /** Counts the revalidations that found the session still valid: a view reads again for the same scope, it is not mounted again. */
 epoch: number;
 refresh: () => Promise<void>;
 /** The active audited elevation, or null; cleared by focus/navigation, expiry and sign-out. */
 elevation: ElevationState | null;
 elevate: (value: ElevationState) => void;
 fail: (message: string) => void;
 /** Organizations the account administers (empty for everyone else), and the sentence that says why a list is empty. */
 orgs: { id: string; name: string }[];
 orgState: string;
 error: string;
 busy: boolean;
 secret: string;
 codes: string[];
 clearCodes: () => void;
 clearElevation: () => void;
 action: (kind: 'logout' | 'totp/start' | 'totp/confirm', event?: React.FormEvent<HTMLFormElement>) => Promise<void>;
}
export const SessionContext=React.createContext<SessionValue|null>(null);
export function ElevationDialog(props:{orgs:Id[];onElevated:()=>void}):React.JSX.Element {
 const context=React.useContext(SessionContext); const [open,setOpen]=React.useState(false);const [busy,setBusy]=React.useState(false);const [error,setError]=React.useState('');const ref=React.useRef<HTMLParagraphElement>(null);
 React.useEffect(()=>{if(error)ref.current?.focus();},[error]);
 async function submit(event:React.FormEvent<HTMLFormElement>):Promise<void>{
  event.preventDefault();if(!context)return;const form=event.currentTarget;const data=new FormData(form);const reason=String(data.get('reason')??'');if(!reason||new TextEncoder().encode(reason).length>512){setError('Reason must contain 1–512 UTF-8 bytes.');return;}setBusy(true);setError('');
  try{const session=await request<Session>('reauthenticate',{Password:String(data.get('password')??''),Code:String(data.get('code')??'')},context.session.csrf);await context.refresh();const orgs=data.getAll('org').map(String);const result=await request<{id:string;expires:string}>('elevation',{Reason:reason,Orgs:orgs},session.csrf);context.elevate({...result,orgs});form.reset();setOpen(false);props.onElevated();}catch(e){const message=e instanceof Error?e.message:'Elevation was not confirmed.';/* The reauthentication refreshed the console and remounted this form, so the refusal is reported by the boundary that outlives it. */context.fail(message);setError(message);}finally{setBusy(false);}
 }
 return <section aria-label="Instance elevation"><button onClick={()=>setOpen(!open)} aria-expanded={open}>Request scoped elevation</button>{open&&<form onSubmit={event=>{void submit(event);}} aria-busy={busy} className="panel"><h2>Audited instance access</h2><p>Instance administrators only. Fresh password and MFA verification rotates your session. Access expires after fifteen minutes and never grants wildcard access.</p><fieldset><legend>Select authorized organizations</legend>{props.orgs.length===0?<p>No organizations are available for this account.</p>:props.orgs.map(org=><label className="check" key={org}><input type="checkbox" name="org" value={org}/><code>{org}</code></label>)}</fieldset><label>Reason<textarea name="reason" required maxLength={512}/></label><label>Current password<input type="password" name="password" required autoComplete="current-password"/></label><label>Authenticator or recovery code<input name="code" autoComplete="one-time-code"/></label>{error&&<p role="alert" tabIndex={-1} ref={ref} className="error">{error}</p>}<button className="primary" disabled={busy||props.orgs.length===0}>{busy?'Committing audited request…':'Reauthenticate and elevate'}</button><button type="button" disabled={busy} onClick={()=>setOpen(false)}>Cancel</button></form>}</section>;
}
/** The request form and, while an elevation is active, the notice that says so with the control that clears it. Offered on the account page and beside the
 * Explore query (an elevated read happens where it is asked: navigating clears the elevation, so it cannot be requested on one page and spent on another). */
export function ElevationControls():React.JSX.Element|null {
 const s=React.useContext(SessionContext);
 if(!s)return null;
 const {elevation}=s;
 return <>
  <ElevationDialog orgs={s.orgs.map(org=>org.id)} onElevated={()=>s.fail('')}/>
  {elevation&&<section className="notice" aria-live="polite">
   <h2>Scoped elevation active</h2>
   <p>Expires {new Date(Number(BigInt(elevation.expires)*1000n)).toLocaleTimeString()}. Selected organizations: {elevation.orgs.join(', ')}.</p>
   <button type="button" onClick={()=>{s.clearElevation();void s.refresh();}}>Clear elevated view</button>
  </section>}
 </>;
}
