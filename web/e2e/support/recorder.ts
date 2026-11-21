// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Drives the REAL browser SDK recorder (packages/browser, bundled by bun) in the real Chrome of the e2e against a page of canary text. The page is
// served over HTTPS by a small server of its own (same private leaf certificate as the real server) so the SDK delivers from a real web origin
// that the browser source's CORS allow-list names; the chunks reach the real server through the SDK's own transport and ingest route.
import {createServer} from 'node:https';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import type {AddressInfo} from 'node:net';
import type {Page} from '@playwright/test';
import {field,id,origin,postJson,SECOND} from './real';

export interface RecorderApp{origin:string;close():Promise<void>}
export interface PageOutcome{replayPolicyAllowed:boolean;chunksEmitted:number;queuedBeforeFlush:number;flush:{pending:number;lost:number;receipts:number};diagnostics:Record<string,number>}

/** Text of the page that must never reach the server in any form: every one is masked by the recorder before anything is buffered. */
export const PAGE_CANARIES={heading:'CANARY-HEADING-7f3a91',typed:'CANARY-TYPED-PASSWORD-55c2',area:'CANARY-NOTE-BODY-9d10',paragraph:'CANARY-PARAGRAPH-e41b',klass:'canary-class-b82c',attribute:'CANARY-ATTRIBUTE-0aa7'} as const;

const PAGE=`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Recorder fixture</title></head><body>
<main><h1 id="heading">${PAGE_CANARIES.heading}</h1>
<p class="${PAGE_CANARIES.klass}" data-secret="${PAGE_CANARIES.attribute}">${PAGE_CANARIES.paragraph}</p>
<label for="name">Name</label><input id="name" type="password" autocomplete="off">
<label for="note">Note</label><textarea id="note" rows="3" cols="30"></textarea>
<button id="go" type="button">Place order</button><div id="result" role="status"></div></main>
<script type="module" src="/page.js"></script></body></html>`;

/** Bundle the page script once per process: the real recorder and SDK source files, browser target, no transforms of their own. */
let bundled:string|undefined;
function bundle():string{
 if(bundled!==undefined)return bundled;
 const root=resolve(process.cwd(),'..');
 const dir=mkdtempSync(join(tmpdir(),'sp-recorder-page-'));
 execFileSync(process.env.SOUNDPOST_BUN??'bun',['build',join(root,'web/e2e/support/recorder-page.ts'),'--outdir',dir,'--target=browser','--format=esm'],{stdio:'pipe',cwd:root});
 bundled=readFileSync(join(dir,'recorder-page.js'),'utf8');
 return bundled;
}

/** Serve the fixture page over HTTPS on a free loopback port. The origin is known before the browser source that allows it is onboarded. */
export async function recorderApp():Promise<RecorderApp>{
 const pki=process.env.E2E_PKI;
 if(pki===undefined)throw Error('E2E_PKI is not set: the harness exports the private CA directory');
 const script=bundle();
 const server=createServer({key:readFileSync(`${pki}/leaf.key`),cert:readFileSync(`${pki}/leaf.pem`)},(req,res)=>{
  if(req.url==='/'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store'});res.end(PAGE);return;}
  if(req.url==='/page.js'){res.writeHead(200,{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store'});res.end(script);return;}
  res.writeHead(404);res.end();
 });
 await new Promise<void>((ok)=>server.listen(0,'127.0.0.1',ok));
 const port=(server.address() as AddressInfo).port;
 return {origin:`https://127.0.0.1:${port}`,close:()=>new Promise<void>((ok)=>{server.close(()=>ok());server.closeAllConnections();})};
}

/** A BROWSER source for replay chunks whose CORS allow-list is exactly `appOrigin`; returns what the SDK is configured from (the public part of the onboarding). */
export async function onboardBrowserReplaySource(page:Page,org:string,project:string,appOrigin:string):Promise<Record<string,unknown>>{
 const source=id(),service=id(),environment=id(),build=id(),instance='browser-instance';
 const kinds=['replay_chunk','capability','loss'];
 const policy={revision:'1',enabled:true,class:'structured',kinds,templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build],instance_pseudonym:[instance]},labels:{},operations:[],dependencies:[],codes:[],retention_days:{replay_chunk:14,capability:30,loss:30},max_bytes:'1073741824',max_series:'1000',replay:true,expires_ns:'0'};
 const r=await postJson(page,'/api/v1/sources',{command_id:id(),org,project,source,browser:true,origins:[appOrigin],expires_ns:(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND).toString(),policy,reason:'Real recorder e2e fixture'});
 const credential=field(r.json,'credential'),descriptor=field(r.json,'descriptor');
 if(r.status!==200||typeof credential!=='string')throw Error(`browser source onboarding: HTTP ${r.status} ${r.text}`);
 const config={org,project,source,credential,build,endpoint:`${origin()}/ingest/v1/batches`,policy:field(r.json,'policy'),trusted_keys:field(r.json,'trusted_keys'),descriptor,resource:{service_id:service,environment_id:environment,build_id:build,instance_pseudonym:instance,labels:[]}};
 return config;
}

interface PageApi{start(config:unknown):{replay:string;session:string};finish():Promise<PageOutcome>}
export interface Recording{replay:string;session:string;outcome:PageOutcome;requests:string[]}
/**
 * Open the fixture page, start the real recorder in it, run `interact` (real input through the browser), then let the SDK flush. `requests` is
 * every request URL the page made, so a caller can assert that the only place the page talked to is the real server.
 */
export async function record(page:Page,app:RecorderApp,config:Record<string,unknown>,interact:(page:Page)=>Promise<void>):Promise<Recording>{
 const requests:string[]=[];
 page.on('request',(request)=>requests.push(request.url()));
 await page.goto(`${app.origin}/`);
 await page.waitForFunction(()=>Reflect.get(window,'__ready')===true);
 const ids=await page.evaluate((c)=>{const api:PageApi=Reflect.get(window,'__soundpost');return api.start(c);},config);
 await interact(page);
 await page.waitForTimeout(1500); // the recorder's event flush interval is 1s
 const outcome=await page.evaluate(()=>{const api:PageApi=Reflect.get(window,'__soundpost');return api.finish();});
 return {...ids,outcome,requests};
}
