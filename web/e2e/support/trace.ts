// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture of the critical-path e2e. Organizations, projects, users and grants go through the real admin routes, the
// span source through the real POST /api/v1/sources, and every span through the real POST /ingest/v1/batches with that source's
// credential. Nothing here fakes a server answer. The committed ingest validator refuses an end in another clock domain, an end
// before its start and an open span unless it is cancelled/incomplete, so those shapes only exist in the Go unit tests.
import type {APIRequestContext,Page} from '@playwright/test';
import {at,bitsOf,field,id,ingestBatch,postJson,spanId,SECOND,type Source} from './real';

// The committed source policy only admits operation and dependency names of a safe code alphabet (model safeCode), so a markup
// canary can never reach a span name through the real ingest route; the XSS canary on span names is unit/SSR tested instead.
export const OPS=['op.frontend','op.api','op.query','op.cache','op.gateway','op.dependency','op.job','op.skewed','op.orphan','op.cycle','op.dup','op.sampled'];
export const DEPS=['postgres','cache','upstream'];
const MS=1_000_000n;

export interface Domain{host:string;boot:string;runtime:string;base:bigint}
let domains=0;
/** A clock domain; its monotonic readings start at a base unrelated to every other domain's. */
export const domain=():Domain=>({host:id(),boot:id(),runtime:id(),base:1_000_000_000_000n+BigInt(++domains)*7_919_000_000_000n});
export interface SpanSpec{span:string;parent?:string;kind?:'internal'|'server'|'client'|'producer'|'consumer';operation:string;dependency?:string;startMs:number;endMs?:number;domain:Domain;skewMs?:number;uncertaintyMs?:number;status?:'ok'|'error'|'cancelled'|'incomplete';links?:{trace:string;span:string}[];probability?:number;decision?:'keep'|'drop'}

/** The anchor every fixture offset is measured from: at(10) of the shared test epoch, inside the window the spec opens. */
export const ANCHOR=at(10);
const resource=(s:Source):Record<string,unknown>=>({service_id:s.service,environment_id:s.environment,build_id:s.build,instance_pseudonym:s.instance,labels:[]});

/** Admit the spans of ONE trace through the real ingest route (one batch: spans of one trace share a route slot). */
export async function ingestTrace(request:APIRequestContext,s:Source,trace:string,specs:SpanSpec[]):Promise<void>{
 const records=specs.map((sp)=>{
  const stamp=(ms:number)=>({wall_ns:(ANCHOR+BigInt(ms)*MS+BigInt(Math.round((sp.skewMs??0)*1e6))).toString(),mono_ns:(sp.domain.base+BigInt(ms)*MS).toString(),domain:{host:sp.domain.host,boot:sp.domain.boot,runtime:sp.domain.runtime},uncertainty_ns:(BigInt(sp.uncertaintyMs??0)*MS).toString()});
  const end=sp.endMs===undefined?null:stamp(sp.endMs);
  const payload={trace_id:trace,span_id:sp.span,parent_id:sp.parent??null,span_kind:sp.kind??'internal',operation:sp.operation,start:stamp(sp.startMs),end,status:sp.status??'ok',dependency_alias:sp.dependency??'',links:(sp.links??[]).map((l)=>({trace_id:l.trace,span_id:l.span})),sample_probability:bitsOf(sp.probability??1),sample_decision:sp.decision??'keep'};
  return {id:id(),kind:'span' as const,observed_at_ns:(ANCHOR+BigInt(sp.startMs)*MS).toString(),resource:resource(s),payload};
 });
 await ingestBatch(request,s,records);
}

/** A structured span source whose policy lists the operations and dependency aliases of this fixture. */
export async function onboardSpanSource(page:Page,org:string,project:string):Promise<Source>{
 const source=id(),service=id(),environment=id(),build=id(),instance='opaque-instance';
 const policy={revision:'1',enabled:true,class:'structured',kinds:['span'],templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build],instance_pseudonym:[instance]},labels:{},operations:OPS,dependencies:DEPS,codes:[],retention_days:{span:7},max_bytes:'1048576',max_series:'1000',replay:false,expires_ns:'0'};
 const r=await postJson(page,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:(BigInt(Date.now())*MS+24n*3600n*SECOND).toString(),policy,reason:'Critical path e2e fixture'});
 const credential=field(r.json,'credential'),revision=field(field(r.json,'descriptor'),'policy_revision');
 if(r.status!==200||typeof credential!=='string')throw Error(`span source onboarding: HTTP ${r.status} ${r.text}`);
 return {id:source,credential,producer:id(),org,project,service,environment,build,instance,policyRevision:typeof revision==='string'?revision:'1',kinds:['span']};
}

export interface TraceSeed{
 clean:{trace:string;frontend:string;api:string;query:string;cache:string};
 gateway:{trace:string;gateway:string;dependency:string;job:{trace:string;span:string}};
 skew:{trace:string;root:string;child:string};
 broken:{trace:string;root:string;orphan:string;second:string};
 cycle:{trace:string;root:string;a:string;b:string};
 dup:{trace:string;root:string;copy:string};
 sampled:{trace:string;root:string};
 absent:string;
}

/** Build every trace through the real ingest route. Times are in ms from ANCHOR. */
export async function seedTraces(request:APIRequestContext,s:Source):Promise<TraceSeed>{
 const d1=domain(),d2=domain(),d3=domain();
 const sp=()=>spanId();
 // frontend -> API -> PostgreSQL with overlapping work: query (60 ms) and cache (30 ms) run in parallel under the API.
 const clean={trace:id(),frontend:sp(),api:sp(),query:sp(),cache:sp()};
 await ingestTrace(request,s,clean.trace,[
  {span:clean.frontend,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d1},
  {span:clean.api,parent:clean.frontend,kind:'server',operation:'op.api',startMs:5,endMs:95,domain:d2},
  {span:clean.query,parent:clean.api,kind:'client',operation:'op.query',dependency:'postgres',startMs:10,endMs:70,domain:d2},
  {span:clean.cache,parent:clean.api,kind:'client',operation:'op.cache',dependency:'cache',startMs:10,endMs:40,domain:d2},
 ]);
 // gateway -> dependency, plus an asynchronous job in its own trace that links to the gateway span.
 const gateway={trace:id(),gateway:sp(),dependency:sp(),job:{trace:id(),span:sp()}};
 await ingestTrace(request,s,gateway.trace,[
  {span:gateway.gateway,kind:'server',operation:'op.gateway',startMs:0,endMs:50,domain:d1},
  {span:gateway.dependency,parent:gateway.gateway,kind:'client',operation:'op.dependency',dependency:'upstream',startMs:5,endMs:45,domain:d1},
 ]);
 await ingestTrace(request,s,gateway.job.trace,[{span:gateway.job.span,kind:'consumer',operation:'op.job',startMs:400,endMs:500,domain:d3,links:[{trace:gateway.trace,span:gateway.gateway}]}]);
 // cross-host skew: the child's host clock is 10 ms behind with 10 ms uncertainty, so it appears to start 5 ms before its parent, which the uncertainty can explain.
 const skew={trace:id(),root:sp(),child:sp()};
 await ingestTrace(request,s,skew.trace,[
  {span:skew.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d1},
  {span:skew.child,parent:skew.root,kind:'server',operation:'op.skewed',startMs:5,endMs:60,domain:d3,skewMs:-10,uncertaintyMs:10},
 ]);
 // a missing parent, an orphan and a second root.
 const broken={trace:id(),root:sp(),orphan:sp(),second:sp()};
 await ingestTrace(request,s,broken.trace,[
  {span:broken.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d1},
  {span:broken.orphan,parent:sp(),kind:'internal',operation:'op.orphan',startMs:10,endMs:30,domain:d2},
  {span:broken.second,kind:'server',operation:'op.api',startMs:50,endMs:130,domain:d3},
 ]);
 const cycle={trace:id(),root:sp(),a:sp(),b:sp()};
 await ingestTrace(request,s,cycle.trace,[
  {span:cycle.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d1},
  {span:cycle.a,parent:cycle.b,kind:'internal',operation:'op.cycle',startMs:10,endMs:30,domain:d1},
  {span:cycle.b,parent:cycle.a,kind:'internal',operation:'op.cycle',startMs:12,endMs:28,domain:d1},
 ]);
 const dup={trace:id(),root:sp(),copy:sp()};
 await ingestTrace(request,s,dup.trace,[
  {span:dup.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d1},
  {span:dup.copy,parent:dup.root,kind:'internal',operation:'op.dup',startMs:10,endMs:30,domain:d1},
  {span:dup.copy,parent:dup.root,kind:'internal',operation:'op.dup',startMs:10,endMs:90,domain:d1},
 ]);
 const sampled={trace:id(),root:sp()};
 await ingestTrace(request,s,sampled.trace,[{span:sampled.root,kind:'server',operation:'op.sampled',startMs:0,endMs:100,domain:d1,probability:0.25,decision:'keep'}]);
 return {clean,gateway,skew,broken,cycle,dup,sampled,absent:id()};
}
