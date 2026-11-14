// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { LoginPage } from './LoginPage';
import { ElevationDialog, SessionContext, type ElevationState } from './ElevationDialog';
import { request, RequestFailure, type Session } from './api';
export function SessionBoundary(props:{children:React.ReactNode}):React.JSX.Element {
 const [session,setSession]=React.useState<Session|null>(null);const [checking,setChecking]=React.useState(true);const [error,setError]=React.useState('');const [orgs,setOrgs]=React.useState<{id:string;name:string}[]>([]);const [orgState,setOrgState]=React.useState('');const [elevation,setElevation]=React.useState<ElevationState|null>(null);const [secret,setSecret]=React.useState('');const [codes,setCodes]=React.useState<string[]>([]);const [busy,setBusy]=React.useState(false);const generation=React.useRef(0);
 const [unavailable,setUnavailable]=React.useState('');
 const currentSession=React.useRef<Session|null>(null);
 React.useEffect(()=>{currentSession.current=session;},[session]);
 React.useEffect(()=>{if(error){const alert=document.querySelector<HTMLElement>('[role="alert"]');alert?.setAttribute('tabindex','-1');alert?.focus();}},[error]);
 const refresh=React.useCallback(async():Promise<void>=>{
  setUnavailable('');
  const version=++generation.current;setChecking(true);setSession(null);setOrgs([]);setSecret('');setCodes([]);
  try{const current=await request<Session>('session');if(version!==generation.current)return;setSession(current);setError('');try{const result=await request<{organizations?:{id:string;name:string}[]}>('admin/read',{kind:'organizations'},current.csrf);if(version!==generation.current)return;setOrgs(result.organizations??[]);setOrgState(result.organizations?.length?'':'No administered organizations were returned. Membership is not a data grant.');}catch(e){if(version!==generation.current)return;setOrgState(e instanceof Error?e.message:'Organization access unavailable.');if(e instanceof RequestFailure&&e.status===401){setSession(null);setElevation(null);}}}catch(e){if(version!==generation.current)return;setElevation(null);if(!(e instanceof RequestFailure&&e.status===401))setError(e instanceof Error?e.message:'Session validation unavailable.');}finally{if(version===generation.current)setChecking(false);}
 },[]);
 const checkSession=React.useCallback(async():Promise<void>=>{
  const version=generation.current;
  try{
   const current=await request<Session>('session');
   if(version!==generation.current)return;
   const previous=currentSession.current;
   if(!previous||previous.user!==current.user){await refresh();return;}
   setUnavailable('');
   if(previous.csrf!==current.csrf||previous.expires!==current.expires)setSession(current);
  }catch(e){
   if(version!==generation.current)return;
   if(e instanceof RequestFailure&&(e.status===401||e.status===403)){
    setUnavailable('');setSession(null);setElevation(null);setSecret('');setCodes([]);setOrgs([]);
   }else{
    setUnavailable('Access validation is temporarily unavailable. Protected views are paused; your session has not been discarded.');
   }
  }
 },[refresh]);
 React.useEffect(()=>{void refresh();const revalidate=():void=>{setElevation(null);void refresh();};window.addEventListener('focus',revalidate);window.addEventListener('popstate',revalidate);window.addEventListener('hashchange',revalidate);const interval=window.setInterval(()=>{void checkSession();},5000);return()=>{generation.current++;window.removeEventListener('focus',revalidate);window.removeEventListener('popstate',revalidate);window.removeEventListener('hashchange',revalidate);window.clearInterval(interval);};},[refresh,checkSession]);
 React.useEffect(()=>{if(!elevation)return;const delay=Number(BigInt(elevation.expires)*1000n-BigInt(Date.now()));const timeout=window.setTimeout(()=>{setElevation(null);void refresh();},Math.max(0,Math.min(delay,2147483647)));return()=>window.clearTimeout(timeout);},[elevation,refresh]);
 async function action(kind:'logout'|'totp/start'|'totp/confirm',event?:React.FormEvent<HTMLFormElement>):Promise<void>{event?.preventDefault();if(!session)return;setBusy(true);setError('');try{const body=kind==='totp/confirm'?{Code:String(new FormData(event!.currentTarget).get('code')??'')}:{};const result=await request<{secret?:string;recovery_codes?:string[]}>(kind,body,session.csrf);if(kind==='logout'){setElevation(null);await refresh();}else if(kind==='totp/start')setSecret(result.secret??'');else{setSecret('');setCodes(result.recovery_codes??[]);}}catch(e){setError(e instanceof Error?e.message:'Request failed.');if(e instanceof RequestFailure&&e.status===401)await refresh();}finally{setBusy(false);}}
 if(checking)return <main id="main" className="login"><h1>Soundpost</h1><p role="status">Revalidating access…</p></main>;
 if(unavailable)return <main id="main" className="login"><h1>Access validation unavailable</h1><p role="alert" className="error">{unavailable}</p><button onClick={()=>{void checkSession();}}>Retry access validation</button></main>;
 if(!session)return <>{error&&<p role="alert" className="error">{error} <button onClick={()=>{void refresh();}}>Retry</button></p>}<LoginPage/></>;
 return <SessionContext.Provider value={{session,refresh,elevate:setElevation}}><div className="console"><header className="console-header"><span className="wordmark">Soundpost</span><span>Access console</span><button disabled={busy} onClick={()=>{void action('logout');}}>Sign out</button></header><main id="main"><h1>Account access</h1><dl><dt>Account ID</dt><dd><code>{session.user}</code></dd><dt>Session expires</dt><dd>{new Date(Number(BigInt(session.expires)*1000n)).toLocaleString()}</dd></dl>{error&&<p role="alert" className="error">{error}</p>}<section className="panel"><h2>Organization access</h2>{orgState&&<p>{orgState}</p>}{orgs.length>0&&<ul>{orgs.map(org=><li key={org.id}>{org.name} <code>{org.id}</code></li>)}</ul>}<p>Administrative visibility does not imply permission to read telemetry, replay, artifacts or profiles.</p></section><ElevationDialog orgs={orgs.map(org=>org.id)} onElevated={()=>setError('')}/>{elevation&&<section className="notice" aria-live="polite"><h2>Scoped elevation active</h2><p>Expires {new Date(Number(BigInt(elevation.expires)*1000n)).toLocaleTimeString()}. Selected organizations: {elevation.orgs.join(', ')}.</p><button onClick={()=>{setElevation(null);void refresh();}}>Clear elevated view</button></section>}<section className="panel"><h2>Multi-factor authentication</h2><p>Enrollment replaces the current authenticator only after a valid confirmation. Keep recovery codes offline.</p><button disabled={busy} onClick={()=>{void action('totp/start');}}>Start authenticator enrollment</button>{secret&&<form onSubmit={event=>{void action('totp/confirm',event);}}><label>Enrollment secret<output className="secret">{secret}</output></label><label>Authenticator code<input name="code" required autoComplete="one-time-code"/></label><button disabled={busy}>Confirm authenticator</button></form>}{codes.length>0&&<div><h3>Save these one-use recovery codes now</h3><ul>{codes.map(code=><li key={code}><code>{code}</code></li>)}</ul><button onClick={()=>setCodes([])}>I saved these offline; hide codes</button></div>}</section><section key={elevation?.id??'ordinary'}>{props.children}</section></main></div></SessionContext.Provider>;
}
