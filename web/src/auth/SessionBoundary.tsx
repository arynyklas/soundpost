// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import * as React from 'react';
import { LoginPage } from './LoginPage';
import { SessionContext, type ElevationState } from './ElevationDialog';
import { classifyRevalidation } from './revalidation';
import { request, RequestFailure, type Session } from './api';
export function SessionBoundary(props:{children:React.ReactNode}):React.JSX.Element {
 const [session,setSession]=React.useState<Session|null>(null);const [checking,setChecking]=React.useState(true);const [error,setError]=React.useState('');const [orgs,setOrgs]=React.useState<{id:string;name:string}[]>([]);const [orgState,setOrgState]=React.useState('');const [elevation,setElevation]=React.useState<ElevationState|null>(null);const [secret,setSecret]=React.useState('');const [codes,setCodes]=React.useState<string[]>([]);const [busy,setBusy]=React.useState(false);const generation=React.useRef(0);
 const [unavailable,setUnavailable]=React.useState('');const [epoch,setEpoch]=React.useState(0);
 const currentSession=React.useRef<Session|null>(null);
 React.useEffect(()=>{currentSession.current=session;},[session]);
 React.useEffect(()=>{if(error){const alert=document.querySelector<HTMLElement>('[role="alert"]');alert?.setAttribute('tabindex','-1');alert?.focus();}},[error]);
 const refresh=React.useCallback(async():Promise<void>=>{
  setUnavailable('');
  const version=++generation.current;setChecking(true);setSession(null);setElevation(null);setOrgs([]);setSecret('');setCodes([]);
  try{const current=await request<Session>('session');if(version!==generation.current)return;setSession(current);setError('');try{const result=await request<{organizations?:{id:string;name:string}[]}>('admin/read',{kind:'organizations'},current.csrf);if(version!==generation.current)return;setOrgs(result.organizations??[]);setOrgState(result.organizations?.length?'':'No administered organizations were returned. Membership is not a data grant.');}catch(e){if(version!==generation.current)return;setOrgState(e instanceof Error?e.message:'Organization access unavailable.');if(e instanceof RequestFailure&&e.status===401){setSession(null);setElevation(null);}}}catch(e){if(version!==generation.current)return;setElevation(null);if(!(e instanceof RequestFailure&&e.status===401))setError(e instanceof Error?e.message:'Session validation unavailable.');}finally{if(version===generation.current)setChecking(false);}
 },[]);
 const checkSession=React.useCallback(async(reread=false):Promise<void>=>{
  const version=generation.current;
  try{
   const current=await request<Session>('session');
   if(version!==generation.current)return;
   const previous=currentSession.current;
   const outcome=classifyRevalidation(previous,current);
   if(outcome==='remount'){await refresh();return;}
   setUnavailable('');
   if(outcome==='update')setSession(current);
   // A return to the window (focus after blur; a navigation already makes every view read again) also re-reads what the account may see: the views read again for the same scope (a revoked grant clears them), the organization list is read again.
   if(reread){
    setEpoch(value=>value+1);
    try{const result=await request<{organizations?:{id:string;name:string}[]}>('admin/read',{kind:'organizations'},current.csrf);if(version!==generation.current)return;setOrgs(result.organizations??[]);setOrgState(result.organizations?.length?'':'No administered organizations were returned. Membership is not a data grant.');}catch(e){if(version!==generation.current)return;setOrgState(e instanceof Error?e.message:'Organization access unavailable.');if(e instanceof RequestFailure&&e.status===401){setSession(null);setElevation(null);setSecret('');setCodes([]);setOrgs([]);}}
   }
  }catch(e){
   if(version!==generation.current)return;
   if(e instanceof RequestFailure&&(e.status===401||e.status===403)){
    setUnavailable('');setSession(null);setElevation(null);setSecret('');setCodes([]);setOrgs([]);
   }else{
    setUnavailable('Access validation is temporarily unavailable. Protected views are paused; your session has not been discarded.');
   }
  }
 },[refresh]);
 React.useEffect(()=>{void refresh();const revalidate=():void=>{setElevation(null);void checkSession();};let away=false;const leave=():void=>{away=true;};const returned=():void=>{const back=away;away=false;setElevation(null);void checkSession(back);};window.addEventListener('blur',leave);window.addEventListener('focus',returned);window.addEventListener('popstate',revalidate);window.addEventListener('hashchange',revalidate);const interval=window.setInterval(()=>{void checkSession();},5000);return()=>{generation.current++;window.removeEventListener('blur',leave);window.removeEventListener('focus',returned);window.removeEventListener('popstate',revalidate);window.removeEventListener('hashchange',revalidate);window.clearInterval(interval);};},[refresh,checkSession]);
 React.useEffect(()=>{if(!elevation)return;const delay=Number(BigInt(elevation.expires)*1000n-BigInt(Date.now()));const timeout=window.setTimeout(()=>{setElevation(null);void refresh();},Math.max(0,Math.min(delay,2147483647)));return()=>window.clearTimeout(timeout);},[elevation,refresh]);
 async function action(kind:'logout'|'totp/start'|'totp/confirm',event?:React.FormEvent<HTMLFormElement>):Promise<void>{event?.preventDefault();if(!session)return;setBusy(true);setError('');try{const body=kind==='totp/confirm'?{Code:String(new FormData(event!.currentTarget).get('code')??'')}:{};const result=await request<{secret?:string;recovery_codes?:string[]}>(kind,body,session.csrf);if(kind==='logout'){setElevation(null);await refresh();}else if(kind==='totp/start')setSecret(result.secret??'');else{setSecret('');setCodes(result.recovery_codes??[]);}}catch(e){setError(e instanceof Error?e.message:'Request failed.');if(e instanceof RequestFailure&&e.status===401)await refresh();}finally{setBusy(false);}}
 if(checking)return <main id="main" className="login"><h1>Soundpost</h1><p role="status">Revalidating access…</p></main>;
 if(unavailable)return <main id="main" className="login"><h1>Access validation unavailable</h1><p role="alert" className="error">{unavailable}</p><button onClick={()=>{void checkSession();}}>Retry access validation</button></main>;
 if(!session)return <>{error&&<p role="alert" className="error">{error} <button onClick={()=>{void refresh();}}>Retry</button></p>}<LoginPage/></>;
 return <SessionContext.Provider value={{session,epoch,refresh,elevation,elevate:setElevation,fail:setError,orgs,orgState,error,busy,secret,codes,clearCodes:()=>setCodes([]),clearElevation:()=>setElevation(null),action}}><React.Fragment key={elevation?.id??'ordinary'}>{props.children}</React.Fragment></SessionContext.Provider>;
}
