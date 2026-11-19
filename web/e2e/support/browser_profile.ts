// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Fixture of the browser profiler capability e2e. The REAL browser SDK profiler (packages/browser, bundled by bun) runs on an ordinary page of a web
// origin of its own, in the Playwright browser under test; the page is served over HTTPS with the `Document-Policy: js-profiling` header (the header
// a real site sends to opt in; engines without the API ignore it). The SDK delivers its records itself, through its own transport, to the real
// ingest route with the credential of a browser source onboarded for exactly this origin. This file builds no capability and no chunk.
import {createServer} from 'node:https';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import type {AddressInfo} from 'node:net';
import type {Page,Response} from '@playwright/test';
import {field,id,origin,postJson,SECOND} from './real';
import type {ProfileOutcome} from './browser_profile_page';

export type {ProfileOutcome};
export interface ProfileApp{origin:string;close():Promise<void>}
export interface DeliveredRecord{id:string;kind:string;payload:Record<string,unknown>}
/** One POST of the SDK to the ingest route, as the browser saw it: the HTTP status and what the batch carried. */
export interface Delivery{status:number;kinds:string[];records:DeliveredRecord[]}
export interface ProfileRun{outcome:ProfileOutcome;deliveries:Delivery[];requestOrigins:string[]}

const PAGE=`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Ordinary page</title></head><body>
<main><h1>An ordinary page</h1><p>A named busy loop runs here while the SDK profiler samples this engine.</p></main>
<script type="module" src="/page.js"></script></body></html>`;

let bundled:string|undefined;
function bundle():string{
 if(bundled!==undefined)return bundled;
 const root=resolve(process.cwd(),'..');
 const dir=mkdtempSync(join(tmpdir(),'sp-browser-profile-page-'));
 execFileSync(process.env.SOUNDPOST_BUN??'bun',['build',join(root,'web/e2e/support/browser_profile_page.ts'),'--outdir',dir,'--target=browser','--format=esm'],{stdio:'pipe',cwd:root});
 bundled=readFileSync(join(dir,'browser_profile_page.js'),'utf8');
 return bundled;
}

/** Serve the ordinary page over HTTPS on a free loopback port (the harness's private leaf certificate). `documentPolicy` is the Document-Policy header value, or none. */
export async function profileApp(documentPolicy:string|undefined='js-profiling'):Promise<ProfileApp>{
 const pki=process.env.E2E_PKI;
 if(pki===undefined)throw Error('E2E_PKI is not set: the harness exports the private CA directory');
 const script=bundle();
 const server=createServer({key:readFileSync(`${pki}/leaf.key`),cert:readFileSync(`${pki}/leaf.pem`)},(req,res)=>{
  if(req.url==='/'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store',...(documentPolicy===undefined?{}:{'document-policy':documentPolicy})});res.end(PAGE);return;}
  if(req.url==='/page.js'){res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store'});res.end(script);return;}
  res.writeHead(404);res.end();
 });
 await new Promise<void>((ok)=>server.listen(0,'127.0.0.1',ok));
 const port=(server.address() as AddressInfo).port;
 return {origin:`https://127.0.0.1:${port}`,close:()=>new Promise<void>((ok)=>{server.close(()=>ok());server.closeAllConnections();})};
}

/** A BROWSER source for profile records whose CORS allow-list is exactly `appOrigin`; returns what the SDK is configured from (the public part of the onboarding). */
export async function onboardBrowserProfileSource(page:Page,org:string,project:string,appOrigin:string):Promise<Record<string,unknown>>{
 const source=id(),service=id(),environment=id(),build=id(),instance='browser-instance';
 const kinds=['profile_chunk','capability','loss'];
 const policy={revision:'1',enabled:true,class:'structured',kinds,templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build],instance_pseudonym:[instance]},labels:{},operations:[],dependencies:[],codes:[],retention_days:{profile_chunk:7,capability:30,loss:30},max_bytes:'1073741824',max_series:'1000',replay:false,expires_ns:'0'};
 const r=await postJson(page,'/api/v1/sources',{command_id:id(),org,project,source,browser:true,origins:[appOrigin],expires_ns:(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND).toString(),policy,reason:'Browser profiler capability e2e'});
 const credential=field(r.json,'credential'),descriptor=field(r.json,'descriptor');
 if(r.status!==200||typeof credential!=='string')throw Error(`browser profile source onboarding: HTTP ${r.status} ${r.text}`);
 return {org,project,source,credential,build,endpoint:`${origin()}/ingest/v1/batches`,policy:field(r.json,'policy'),trusted_keys:field(r.json,'trusted_keys'),descriptor,resource:{service_id:service,environment_id:environment,build_id:build,instance_pseudonym:instance,labels:[]}};
}

interface PageApi{run(config:unknown,workMs:number):Promise<ProfileOutcome>}
async function deliveryOf(response:Response):Promise<Delivery|undefined>{
 const request=response.request();
 if(request.method()!=='POST'||!new URL(request.url()).pathname.endsWith('/ingest/v1/batches'))return undefined;
 const text=request.postData();
 const body=text===null?undefined:JSON.parse(text) as {records?:DeliveredRecord[]};
 const records=body?.records??[];
 return {status:response.status(),kinds:records.map((r)=>r.kind),records};
}

/**
 * Open the ordinary page, run the real SDK profiler in it for `workMs` of busy loop, let the SDK deliver, and report what the SDK said (`outcome`) and
 * what the browser actually sent to the ingest route (`deliveries`, each with the status the real server answered). `requestOrigins` is the origin of
 * every request the page made, so a caller can assert that the page only talked to its own origin and the real server.
 */
export async function runProfile(page:Page,app:ProfileApp,config:Record<string,unknown>,workMs=800):Promise<ProfileRun>{
 const pending:Promise<Delivery|undefined>[]=[];
 const requestOrigins:string[]=[];
 page.on('request',(request)=>{requestOrigins.push(new URL(request.url()).origin);});
 page.on('response',(response)=>{pending.push(deliveryOf(response));});
 await page.goto(`${app.origin}/`);
 await page.waitForFunction(()=>Reflect.get(window,'__ready')===true);
 const outcome=await page.evaluate(({c,ms})=>{const api:PageApi=Reflect.get(window,'__soundpostProfile');return api.run(c,ms);},{c:config,ms:workMs});
 const deliveries=(await Promise.all(pending)).filter((d):d is Delivery=>d!==undefined);
 return {outcome,deliveries,requestOrigins:[...new Set(requestOrigins)]};
}
