// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture shared by the 05.09 journey and accessibility specs. Everything goes through public routes: orgs,
// projects, users and grants through the real admin commands, sources through POST /api/v1/sources, metrics, logs, spans,
// closed-format replay chunks and a native profile through the real POST /ingest/v1/batches. No route is faked and no
// temporary seed route exists. seedJourney is the telemetry-reader organization; seedRealJourney is the organization the runner,
// the release registry, the symbolication worker and the real Python SDK fill (incident, release, mapped frame, scheduled-job retry).
import {execFile} from 'node:child_process';
import {mkdtempSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {promisify} from 'node:util';
import type {APIRequestContext,Browser,Page} from '@playwright/test';
import {at,field,id,login,onboardSdkJobSource,postJson,sdkConfig,seedExplore,spanId,type ExploreSeed} from './real';
import {REAL_CLASS,REAL_CODE,ingestStoredFailure,seedEvidence,type EvidenceSeed,type Member} from './evidence';
import {NATIVE_PROFILE,onboardReplaySource,seedProfiles,seedReplays,setPermissions,type ReplaySeed} from './replay';
import {domain,ingestTrace,onboardSpanSource,seedTraces,type TraceSeed} from './trace';

export interface JourneySeed{explore:ExploreSeed;traces:TraceSeed;replays:ReplaySeed;profile:string;start:bigint;end:bigint}

/** One org, project P1 (everything is ingested here) and P2 (metrics only), a reader holding telemetry.read, replay.read and
 * profiles.read on P1 and telemetry.read on P2. One window [T0-1s, T0+70s) holds every record. */
export async function seedJourney(owners:Page,api:APIRequestContext):Promise<JourneySeed>{
 const explore=await seedExplore(owners,api);
 const spans=await onboardSpanSource(owners,explore.org,explore.p1);
 const traces=await seedTraces(api,spans);
 const replaySource=await onboardReplaySource(owners,explore.org,explore.p1);
 const replays=await seedReplays(api,replaySource);
 await seedProfiles(api,replaySource);
 await setPermissions(owners,explore.org,explore.reader.id,explore.p1,true,['telemetry.read','replay.read','profiles.read']);
 return {explore,traces,replays,profile:NATIVE_PROFILE,start:at(-1),end:at(70)};
}

/** The URL fragment a native deep link carries: scope and window, never data. */
export function deepLink(seed:JourneySeed,view:string,extra:Record<string,string>={}):string{
 const {org,p1}=seed.explore;
 return `/#${new URLSearchParams({org,projects:p1,start:String(seed.start),end:String(seed.end),tz:'UTC',view,...extra})}`;
}

export interface RealJourneySeed{
 ev:EvidenceSeed;
 /** The organization administrator who also holds telemetry.read and artifacts.read: the person who walks the real journeys. */
 reader:Member;
 /** frontend -> API -> PostgreSQL: three real spans of one trace, and one real failure of the real bundle recorded in the API span. */
 trace:{trace:string;frontend:string;api:string;query:string;occurrence:string};
 /** The incident the runner opened from the ingested errors (first row of the queue). */
 incident:string;
 /** One run produced by the real Python SDK: attempt 1 raises, the retry succeeds. */
 job:{job:string;run:string;failedAttempt:string;retryAttempt:string;error:string};
 /** The whole stored range: the real ingest times are 2024 fixtures and the wall clock together. */
 start:string;end:string;
}

/** The window of a deep link of the real-journey organization: from the first nanosecond to year 2027. */
export const REAL_WINDOW={start:'1',end:'1800000000000000000'};

/**
 * The organization the three real journeys run in, filled only through real routes: the evidence fixture (source policy, real bundle and
 * map uploaded, releases registered, issues the runner's producer makes), a span source for a three-span trace whose API span carries the
 * real failure (real stack, artifact and release), and the real Python SDK's job API (see job-history.spec.ts) for a failed attempt and its retry.
 */
export async function seedRealJourney(owners:Page,browser:Browser,api:APIRequestContext):Promise<RealJourneySeed>{
 const ev=await seedEvidence(owners,browser);
 const ctx=await browser.newContext();
 const rp=await ctx.newPage();
 await login(rp,ev.analyst.email,ev.analyst.password);

 const spans=await onboardSpanSource(owners,ev.org,ev.project);
 const d=domain();
 const trace={trace:id(),frontend:spanId(),api:spanId(),query:spanId()};
 await ingestTrace(api,spans,trace.trace,[
  {span:trace.frontend,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d},
  {span:trace.api,parent:trace.frontend,kind:'server',operation:'op.api',startMs:5,endMs:95,domain:d},
  {span:trace.query,parent:trace.api,kind:'client',operation:'op.query',dependency:'postgres',startMs:10,endMs:70,domain:d},
 ]);
 const occurrence=await ingestStoredFailure(api,ev.errorSource,{at:at(20),class:REAL_CLASS,mechanism:'uncaught_exception',handled:false,fatal:true,code:REAL_CODE,release:ev.real.release,trace:trace.trace,span:trace.api,artifact:ev.artifact,frames:ev.real.bundle.frames});

 // The runner's issue producer groups the occurrence into the issue of the real failure; wait until the real evidence route lists it.
 const deadline=Date.now()+90_000;
 for(;;){
  const r=await postJson(rp,'/api/v1/evidence/issue',{org:ev.org,project:ev.project,issue:ev.real.issue});
  const listed=field(r.json,'occurrences');
  if(r.status===200&&Array.isArray(listed)&&listed.some((o)=>field(o,'occurrence_id')===occurrence))break;
  if(Date.now()>deadline)throw Error(`the producer never grouped occurrence ${occurrence}: HTTP ${r.status} ${r.text}`);
  await rp.waitForTimeout(500);
 }

 // The incident the runner opened: the queue lists it.
 let incident='';
 while(incident===''){
  const r=await postJson(rp,'/api/v1/queue',{org:ev.org,projects:[ev.project],limit:50});
  const entries=field(r.json,'entries');
  const first=Array.isArray(entries)?field(entries[0],'incident_id'):undefined;
  if(typeof first==='string')incident=first;
  else if(Date.now()>deadline)throw Error(`the runner opened no incident: HTTP ${r.status} ${r.text}`);
  else await rp.waitForTimeout(500);
 }

 // The real Python SDK job API: attempt 1 raises, attempt 2 succeeds; delivered over its own HTTPS transport with durable receipts.
 const sdkSource=await onboardSdkJobSource(owners,ev.org,ev.project);
 const job=id();
 const dir=mkdtempSync(join(tmpdir(),'sp-sdk-journey-'));
 const config=join(dir,'sdk.json');
 writeFileSync(config,JSON.stringify(sdkConfig(sdkSource)),{mode:0o600});
 const {stdout}=await promisify(execFile)(process.env.E2E_PYTHON??'python3',[resolve(process.cwd(),'e2e/support/sdk_job_retry.py')],{env:{...process.env,PYTHONPATH:resolve(process.cwd(),'../sdk/python/src'),SOUNDPOST_SDK_CONFIG:config,SOUNDPOST_SDK_JOB:job},timeout:60_000});
 const sdk=JSON.parse(stdout.trim().split('\n').pop()??'{}') as {run:string;failed_attempt:string;retry_attempt:string;error:string;events:number};
 for(;;){
  const r=await postJson(rp,'/api/v1/jobs/view',{org:ev.org,project:ev.project,job,run:sdk.run});
  const attempts=field(field(r.json,'run'),'attempts');
  const accepted=Array.isArray(attempts)?attempts.reduce((n:number,a:unknown)=>n+(Number(field(a,'events_accepted'))||0),0):0;
  if(accepted===sdk.events)break;
  if(Date.now()>deadline+60_000)throw Error(`the job runner applied ${accepted} of ${sdk.events} events: HTTP ${r.status} ${r.text}`);
  await rp.waitForTimeout(500);
 }
 await ctx.close();
 return {ev,reader:ev.analyst,trace:{...trace,occurrence},incident,job:{job,run:sdk.run,failedAttempt:sdk.failed_attempt,retryAttempt:sdk.retry_attempt,error:sdk.error},start:REAL_WINDOW.start,end:REAL_WINDOW.end};
}

/** The deep link of the real-journey organization (one project, the whole stored range). */
export function realLink(seed:RealJourneySeed,view:string,extra:Record<string,string>={}):string{
 return `/#${new URLSearchParams({org:seed.ev.org,projects:seed.ev.project,start:seed.start,end:seed.end,tz:'UTC',view,...extra})}`;
}
