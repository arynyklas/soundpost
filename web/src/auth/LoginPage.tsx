// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { request } from './api';
export function LoginPage(): React.JSX.Element {
 const [mode,setMode] = React.useState<'local'|'bootstrap'|'sso'>('local');
 const [busy,setBusy] = React.useState(false);
 const [error,setError] = React.useState('');
 const errorRef = React.useRef<HTMLParagraphElement>(null);
 React.useEffect(()=>{if(new URLSearchParams(location.search).get('auth')==='failed'){history.replaceState(null,'','/');setError('Single sign-on was not accepted. Contact your administrator if you need an explicit account mapping.');}},[]);
 React.useEffect(() => { if(error) errorRef.current?.focus(); },[error]);
 async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
  event.preventDefault(); const form=event.currentTarget; const entries=Object.fromEntries(new FormData(form).entries());
  setError('');setBusy(true);
  try {
   if(mode === 'sso') { const result=await request<{url:string}>('oidc/start',{org_id:String(entries.org??''),provider_id:String(entries.provider??'')}); const target=new URL(result.url); if(target.protocol !== 'https:') throw new Error('Provider did not return an HTTPS destination.'); location.assign(target.href); }
   else { await request(mode === 'bootstrap' ? 'bootstrap' : 'login', mode === 'bootstrap' ? {Token:String(entries.token??''),Email:String(entries.email??''),Password:String(entries.password??'')} : {Email:String(entries.email??''),Password:String(entries.password??''),Code:String(entries.code??'')}); form.reset(); location.replace('/'); }
  } catch(e) { setError(e instanceof Error ? e.message : 'Sign in failed.'); } finally {setBusy(false);}
 }
 return <main id="main" className="login"><header><span className="wordmark">Soundpost</span><p>Investigation console</p></header><section className="panel"><h1>Access your installation</h1><p>Use your administrator-provided account. Organization membership alone does not grant telemetry access.</p><nav aria-label="Sign-in method">{(['local','sso','bootstrap'] as const).map(value => <button key={value} type="button" aria-pressed={mode===value} disabled={busy} onClick={()=>{setMode(value);setError('');}}>{value==='local'?'Local account':value==='sso'?'Single sign-on':'First boot'}</button>)}</nav><form onSubmit={event=>{void submit(event);}} aria-busy={busy}>
 {mode==='sso'?<><label>Organization ID<input name="org" required pattern="[0-9a-f]{32}" autoComplete="off"/></label><label>Provider ID<input name="provider" required pattern="[0-9a-f]{32}" autoComplete="off"/></label><p>Only explicitly mapped accounts receive access. Ask your administrator for these identifiers.</p></>:<>{mode==='bootstrap'&&<><p>Use the installation’s one-use private bootstrap token. There is no default password. This does not restore old account permissions.</p><label>Bootstrap token<input name="token" type="password" required autoComplete="off"/></label></>}<label>Email<input name="email" type="email" required autoComplete="username"/></label><label>Password<input name="password" type="password" required minLength={mode==='bootstrap'?16:1} autoComplete={mode==='bootstrap'?'new-password':'current-password'}/></label>{mode==='local'&&<label>Authenticator or recovery code<input name="code" autoComplete="one-time-code" spellCheck={false}/><span>Required only when multi-factor authentication is enabled.</span></label>}</>}
 {error&&<p role="alert" tabIndex={-1} ref={errorRef} className="error">{error}</p>}<button className="primary" disabled={busy}>{busy?'Contacting authority…':mode==='sso'?'Continue to provider':mode==='bootstrap'?'Initialize administrator':'Sign in'}</button></form></section><p className="muted">Credentials stay on this HTTPS origin. Recovery codes are single use.</p></main>;
}
