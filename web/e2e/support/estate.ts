// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The REAL reference estate (examples/reference) as an e2e fixture: a Bun gateway (packages/bun serve/fetch), a Python API (sdk/python WSGI,
// psycopg and httpx integrations) over a real PostgreSQL 16 server, an uninstrumented HTTPS dependency, and the order page built by Vite
// with packages/build (its source map uploaded through the real artifact route), driven by the e2e browser. Every span, error and frame in the
// organization this module fills was made by those programs through the committed SDKs and read back through the product's own routes: no span
// is composed here and no state is injected (tools/smoke/journeys.go is the same estate under the release smoke).
//
// What the host must provide (the run refuses, it never substitutes):
//   E2E_ESTATE_DATABASE_URL  an admin DSN of a PostgreSQL 16 server (postgresql://USER:PASSWORD@HOST:PORT/postgres); the run creates and drops its own database
//   E2E_PYTHON               a Python 3.12-3.14 with psycopg 3, httpx and cryptography at the versions of examples/reference/requirements.lock
//   E2E_BUN                  Bun 1.3.14 (default `bun`; the gateway refuses another runtime)
//   E2E_PKI                  the harness's private CA and leaf (ca.pem, leaf.pem, leaf.key), exported by web/e2e-harness/h.sh
import {execFile,spawn} from 'node:child_process';
import type {ChildProcess} from 'node:child_process';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {request as httpsRequest} from 'node:https';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {promisify} from 'node:util';
import type {Browser,Page} from '@playwright/test';
import {field,id,login,owner,origin,postJson,createOrg,createProject,adminCommand,SECOND} from './real';
import {member,type Member} from './evidence';

const run=promisify(execFile);
const ROOT=resolve(process.cwd(),'..');
const REF=join(ROOT,'examples','reference');
const OPERATIONS=['request','http.call','db.execute','job.run','ui.action'];
const DEPENDENCIES=['api','postgres','dependency','gateway'];

function need(name:string):string{
 const v=process.env[name];
 if(v===undefined||v==='')throw Error(`${name} is not set: the reference estate needs it (see web/e2e/support/estate.ts); no substitute is used`);
 return v;
}
const pki=():{ca:string;cert:string;key:string}=>{const d=need('E2E_PKI');return {ca:join(d,'ca.pem'),cert:join(d,'leaf.pem'),key:join(d,'leaf.key')};};

async function freePort():Promise<number>{
 return new Promise((done,fail)=>{
  const s=createServer();
  s.once('error',fail);
  s.listen(0,'127.0.0.1',()=>{const a=s.address();const p=typeof a==='object'&&a!==null?a.port:0;s.close(()=>done(p));});
 });
}

/** One child process of the estate; its output is kept (bounded) and read only by the run's own diagnostics. */
class Proc{
 readonly out:string[]=[];
 readonly err:string[]=[];
 private code:number|null|undefined;
 private readonly ended:Promise<void>;
 constructor(readonly name:string,private readonly child:ChildProcess){
  const keep=(into:string[])=>(b:Buffer)=>{into.push(...b.toString('utf8').split('\n').filter((l)=>l!==''));if(into.length>200)into.splice(0,into.length-200);};
  child.stdout?.on('data',keep(this.out));
  child.stderr?.on('data',keep(this.err));
  this.ended=new Promise((done)=>{child.once('exit',(c)=>{this.code=c;done();});child.once('error',()=>{this.code=-1;done();});});
 }
 get exited():boolean{return this.code!==undefined;}
 /** SIGTERM (the apps flush their SDK and print one JSON flush line), then SIGKILL after 40 s. Returns the exit code. */
 async stop():Promise<number|null>{
  if(this.code===undefined){
   this.child.kill('SIGTERM');
   const timer=setTimeout(()=>{if(this.code===undefined)this.child.kill('SIGKILL');},40_000);
   await this.ended;
   clearTimeout(timer);
  }
  return this.code??null;
 }
 /** The last `flush` line the app printed on its way out, or null. */
 flush():{pending:number;lost:number;receipts:number}|null{
  for(const l of [...this.out].reverse()){
   try{const f=field(JSON.parse(l) as unknown,'flush');if(typeof f==='object'&&f!==null){const o=f as Record<string,unknown>;return {pending:Number(o.pending),lost:Number(o.lost),receipts:typeof o.receipts==='number'?o.receipts:Number(o.receipts)};}}catch{/* not a JSON line */}
  }
  return null;
 }
 describe():string{return `${this.name}: exit=${String(this.code)} stdout=${this.out.slice(-3).join(' | ')} stderr=${this.err.slice(-3).join(' | ')}`;}
}

async function healthy(url:string,p:Proc,timeoutMs=60_000):Promise<void>{
 const {ca}=pki();
 const caText=readFileSync(ca,'utf8');
 const deadline=Date.now()+timeoutMs;
 for(;;){
  if(p.exited)throw Error(`${p.name} exited before it was ready: ${p.describe()}`);
  const ok=await new Promise<boolean>((done)=>{
   const r=httpsRequest(url,{ca:caText,timeout:2000},(res)=>{res.resume();done(res.statusCode===200);});
   r.on('error',()=>done(false));r.on('timeout',()=>{r.destroy();done(false);});r.end();
  });
  if(ok)return;
  if(Date.now()>deadline)throw Error(`${p.name} was not ready at ${url}: ${p.describe()}`);
  await new Promise((r)=>setTimeout(r,250));
 }
}

export interface EstateSource{name:string;id:string;service:string;build:string;config:Record<string,unknown>}
interface Wire{credential:string;policy:unknown;trusted_keys:unknown;descriptor:unknown}

/** One source of the estate through the real onboarding route, with the configuration its program loads (the shape of tools/smoke journeys writeConfig). */
async function onboard(owners:Page,org:string,project:string,name:string,env:string,build:string,kinds:string[],browser:boolean,origins:string[]):Promise<EstateSource>{
 const source=id(),service=id(),instance=`${name}-1`;
 const retention:Record<string,number>={};for(const k of kinds)retention[k]=14;
 const policy={revision:'1',enabled:true,class:'structured',kinds,templates:[],resources:{service_id:[service],environment_id:[env],build_id:[build],instance_pseudonym:[instance]},labels:{},operations:OPERATIONS,dependencies:DEPENDENCIES,codes:OPERATIONS,retention_days:retention,max_bytes:String(1<<30),max_series:'1000',replay:false,expires_ns:'0'};
 const r=await postJson(owners,'/api/v1/sources',{command_id:id(),org,project,source,browser,origins,expires_ns:(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND).toString(),policy,reason:'reference estate e2e'});
 const credential=field(r.json,'credential');
 if(r.status!==200||typeof credential!=='string')throw Error(`onboarding the ${name} source: HTTP ${r.status} ${r.text}`);
 const w=r.json as Wire;
 const config={org,project,source,credential:w.credential,build,endpoint:`${origin()}/ingest/v1/batches`,ca_file:pki().ca,policy:w.policy,trusted_keys:w.trusted_keys,descriptor:w.descriptor,
  resource:{service_id:service,environment_id:env,build_id:build,instance_pseudonym:instance}};
 return {name,id:source,service,build,config};
}

export interface Order{trace:string;span:string;build:string;pageErrors:{name:string}[];result:string;flush:{pending:number;lost:number;receipts:number}}
export interface Estate{
 org:string;project:string;
 /** An organization administrator who also holds telemetry.read and artifacts.read (the person who investigates). */
 analyst:Member;
 gateway:string;
 /** The same gateway in front of an API process that runs WITHOUT the SDK: its server spans never exist (an unavailable producer). */
 darkGateway:string;
 /** The build the page was served as, its uploaded asset and map digest (from the build's own upload receipts). */
 web:{build:string;asset:string;artifact:string;mapSha256:string;generatedSha256:string};
 /** One priced order placed through the real page, and the unpriced one whose receipt the page cannot render (a real thrown error). */
 priced:Order;unpriced:Order;
 /** A priced order placed through the page served by the gateway whose API produces no telemetry. */
 dark:Order;
 /** The error occurrence the unpriced page threw, as the real trace read lists it (an available link target of the page's action span). */
 occurrence:string;
 /** What each program reported when it flushed its SDK on the way out (the flush line it prints on SIGTERM). */
 flushed:Record<string,{pending:number;lost:number;receipts:number}|null>;
 /** Drops this run's PostgreSQL database; the programs are already stopped. */
 close():Promise<void>;
}

async function orderThrough(browser:Browser,gateway:string,item:'sku-100'|'sku-404'):Promise<Order>{
 const ctx=await browser.newContext({ignoreHTTPSErrors:true});
 try{
  const page=await ctx.newPage();
  const pageErrors:{name:string}[]=[];
  page.on('pageerror',(e)=>pageErrors.push({name:e.name}));
  await page.goto(`${gateway}/`);
  await page.waitForFunction(()=>Boolean((window as unknown as {__reference?:{ready:boolean}}).__reference?.ready),undefined,{timeout:30_000});
  await page.selectOption('#item',item);
  await page.fill('#note','estate journey note');
  await page.click('#place-order');
  await page.waitForFunction(()=>(document.getElementById('result')?.textContent??'')!=='',undefined,{timeout:30_000});
  if(item==='sku-404'){const until=Date.now()+5000;while(pageErrors.length===0&&Date.now()<until)await page.waitForTimeout(50);}
  const ref=await page.evaluate(()=>{const v=(window as unknown as {__reference:{buildId:string;traceId:string;spanId:string}}).__reference;return {build:v.buildId,trace:v.traceId,span:v.spanId};});
  const flush=await page.evaluate(()=>(window as unknown as {__reference:{flush():Promise<{pending:number;lost:number;receipts:number}>}}).__reference.flush());
  const result=(await page.locator('#result').textContent())??'';
  return {...ref,pageErrors,result,flush};
 }finally{await ctx.close();}
}

/**
 * Starts the estate, places three orders through the real page (priced; unpriced, whose failure is thrown in the real minified bundle; priced through the
 * gateway whose API runs without telemetry), stops the programs (each flushes its SDK on SIGTERM and must report nothing pending or lost) and returns the
 * ids the investigation starts from. `owners` is a signed-in instance owner session.
 */
export async function seedEstate(owners:Page,browser:Browser):Promise<Estate>{
 const adminDsn=need('E2E_ESTATE_DATABASE_URL');
 const python=need('E2E_PYTHON');
 const bun=process.env.E2E_BUN??'bun';
 const {ca,cert,key}=pki();
 const o=owner();
 const work=mkdtempSync(join(tmpdir(),'sp-estate-'));
 const procs:Proc[]=[];
 const dbName=`estate_${id().slice(0,12)}`;
 let dropped=false;
 const drop=async():Promise<void>=>{if(dropped)return;dropped=true;await run(python,[join(process.cwd(),'e2e','support','estate_db.py'),'drop',adminDsn,dbName],{timeout:60_000}).catch(()=>undefined);};
 try{
  // The database of this run.
  const created=await run(python,[join(process.cwd(),'e2e','support','estate_db.py'),'create',adminDsn,dbName,join(REF,'api','schema.sql')],{timeout:120_000});
  const dsn=created.stdout.trim().split('\n').pop()??'';
  if(!dsn.startsWith('postgresql://'))throw Error('no database DSN');

  // The organization, project, the investigator and the builder (a user holding artifacts.write whose token the web build uses).
  await login(owners,o.email,o.password);
  const org=await createOrg(owners,'reference estate e2e org'),project=await createProject(owners,org,'reference');
  const analyst=await member(owners,org,project,'estate-analyst',['artifacts.read','telemetry.read','profiles.read'],true);
  const builder=await member(owners,org,project,'estate-builder',['artifacts.write','artifacts.read']);

  const [gwPort,darkPort,apiPort,darkApiPort,depPort]=[await freePort(),await freePort(),await freePort(),await freePort(),await freePort()];
  const gateway=`https://127.0.0.1:${gwPort}`,darkGateway=`https://127.0.0.1:${darkPort}`;
  const env=id(),webBuild=id();
  await login(owners,o.email,o.password);
  const gw=await onboard(owners,org,project,'gateway',env,id(),['span','error'],false,[]);
  const gwDark=await onboard(owners,org,project,'gateway-dark',env,id(),['span','error'],false,[]);
  const api=await onboard(owners,org,project,'api',env,id(),['span','error'],false,[]);
  const web=await onboard(owners,org,project,'web',env,webBuild,['span','error'],true,[gateway,darkGateway]);
  const webBuildSource=await onboard(owners,org,project,'webbuild',env,webBuild,['span'],false,[]);
  const cfgDir=join(work,'cfg');mkdirSync(cfgDir,{mode:0o700});
  const cfg=(s:EstateSource):string=>{const p=join(cfgDir,`${s.name}.json`);writeFileSync(p,JSON.stringify(s.config),{mode:0o600});return p;};

  // The private artifact-write credential the build uses (issued by the instance owner to the builder, for this project only).
  const issued=await postJson(owners,'/api/v1/admin/tokens/issue',{org_id:org,principal:builder.id,projects:[project],permissions:['artifacts.write'],expires:String(Math.floor(Date.now()/1000)+2*3600),reason:'reference estate e2e build'});
  const token=field(issued.json,'Token')??field(issued.json,'token');
  if(issued.status!==200||typeof token!=='string')throw Error(`artifact token: HTTP ${issued.status} ${issued.text}`);

  // The real Vite build; its source map goes to the node through the real artifact route.
  const outDir=join(work,'web-dist');
  const built=await run(process.execPath,[join(REF,'web','build.mjs')],{cwd:ROOT,timeout:240_000,env:{...process.env,REFERENCE_ORG:org,REFERENCE_PROJECT:project,REFERENCE_SOURCE:webBuildSource.id,REFERENCE_BUILD_ID:webBuild,REFERENCE_ENDPOINT:origin(),REFERENCE_ARTIFACT_TOKEN:token,REFERENCE_OUT_DIR:outDir}});
  const res=JSON.parse(built.stdout.trim().split('\n').pop()??'{}') as {build_id?:string;upload?:string;assets?:{file:string;artifact_id:string;map_sha256:string;generated_sha256:string}[]};
  const asset=res.assets?.[0];
  if(res.upload!=='ok'||asset===undefined||res.build_id!==webBuild)throw Error(`web build: ${built.stdout.slice(-300)}`);
  const pageConfig={...web.config,artifact_ids:Object.fromEntries((res.assets??[]).map((a)=>[a.file,a.artifact_id]))};
  const pageConfigPath=join(cfgDir,'web-config.json');
  writeFileSync(pageConfigPath,JSON.stringify(pageConfig),{mode:0o600});

  // The programs.
  const pyEnv={...process.env,PYTHONPATH:join(ROOT,'sdk','python','src'),REFERENCE_DATABASE_URL:dsn,PYTHONDONTWRITEBYTECODE:'1'};
  const start=async(name:string,port:number,cmd:string,args:string[],env:NodeJS.ProcessEnv):Promise<Proc>=>{
   const p=new Proc(name,spawn(cmd,args,{cwd:ROOT,env,stdio:['ignore','pipe','pipe']}));
   procs.push(p);
   await healthy(`https://127.0.0.1:${port}/healthz`,p);
   return p;
  };
  const listen=(p:number)=>`127.0.0.1:${p}`;
  await start('dependency',depPort,python,[join(REF,'dependency','server.py'),'--listen',listen(depPort),'--cert',cert,'--key',key],pyEnv);
  const depUrl=`https://127.0.0.1:${depPort}`;
  await start('api',apiPort,python,[join(REF,'api','serve.py'),'--listen',listen(apiPort),'--cert',cert,'--key',key,'--config',cfg(api),'--ca',ca,'--dependency-url',depUrl],pyEnv);
  // The same API code WITHOUT --config: no SDK, so none of its spans exists.
  await start('api-dark',darkApiPort,python,[join(REF,'api','serve.py'),'--listen',listen(darkApiPort),'--cert',cert,'--key',key,'--ca',ca,'--dependency-url',depUrl],pyEnv);
  const gatewayArgs=(config:EstateSource,port:number,apiPortOf:number):string[]=>[join(REF,'gateway','server.ts'),'--listen',listen(port),'--cert',cert,'--key',key,'--config',cfg(config),'--ca',ca,'--api-url',`https://127.0.0.1:${apiPortOf}`,'--web-dir',outDir,'--web-config',pageConfigPath];
  await start('gateway',gwPort,bun,gatewayArgs(gw,gwPort,apiPort),process.env);
  await start('gateway-dark',darkPort,bun,gatewayArgs(gwDark,darkPort,darkApiPort),process.env);

  // The orders, through the real page in the browser under test.
  const priced=await orderThrough(browser,gateway,'sku-100');
  const unpriced=await orderThrough(browser,gateway,'sku-404');
  const dark=await orderThrough(browser,darkGateway,'sku-100');

  // Stop the programs: each flushes its SDK; a trace is complete only when nothing was pending or lost.
  const flushed:Record<string,{pending:number;lost:number;receipts:number}|null>={};
  for(const p of [...procs].reverse()){await p.stop();flushed[p.name]=p.flush();}
  for(const n of ['gateway','gateway-dark','api']){
   const f=flushed[n];
   if(f===null||f===undefined||f.pending!==0||f.lost!==0)throw Error(`${n} did not flush cleanly: ${JSON.stringify(f)} ${procs.find((p)=>p.name===n)?.describe()}`);
  }
  // The runner's issue producer groups the page's failure into an issue asynchronously: wait until the real trace read lists the error occurrence of the
  // unpriced trace as an available link target (never by a fixed sleep).
  const reader=await browser.newContext({ignoreHTTPSErrors:true});
  let occurrence='';
  try{
   const rp=await reader.newPage();
   await login(rp,analyst.email,analyst.password);
   const deadline=Date.now()+120_000;
   while(occurrence===''){
    const r=await postJson(rp,'/api/v1/traces/view',{org,project,trace:unpriced.trace,window:ESTATE_WINDOW});
    const targets=field(r.json,'targets');
    const hit=Array.isArray(targets)?targets.find((t)=>field(t,'kind')==='error'&&field(t,'available')===true&&typeof field(t,'issue_id')==='string'):undefined;
    if(hit!==undefined)occurrence=String(field(hit,'id'));
    else if(Date.now()>deadline)throw Error(`the issue producer never made the failure of the unpriced order a link target: HTTP ${r.status} ${r.text.slice(0,300)}`);
    else await rp.waitForTimeout(500);
   }
  }finally{await reader.close();}
  await drop();
  rmSync(work,{recursive:true,force:true});
  return {org,project,analyst,gateway,darkGateway,web:{build:webBuild,asset:asset.file,artifact:asset.artifact_id,mapSha256:asset.map_sha256,generatedSha256:asset.generated_sha256},priced,unpriced,dark,occurrence,flushed,close:drop};
 }catch(e){
  for(const p of procs)await p.stop().catch(()=>undefined);
  await drop();
  rmSync(work,{recursive:true,force:true});
  throw e;
 }
}

/** The window of a deep link into the estate's organization: from the first nanosecond to year 2027 (the spans carry the real clock of the run). */
export const ESTATE_WINDOW={start:'1',end:'1800000000000000000'};
export function estateLink(e:Estate,view:string,extra:Record<string,string>={}):string{
 return `/#${new URLSearchParams({org:e.org,projects:e.project,start:ESTATE_WINDOW.start,end:ESTATE_WINDOW.end,tz:'UTC',view,...extra})}`;
}
/** adminCommand is re-exported for specs that change the estate organization's grants. */
export {adminCommand};
