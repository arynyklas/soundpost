// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture of the replay and profile e2e. Organizations, projects, users and grants go through the real admin routes,
// the source through the real POST /api/v1/sources, and every chunk through the real POST /ingest/v1/batches with that source's
// credential. Replay chunks are built through the CLOSED format the Go validator accepts (the committed browser recorder emits
// node fields rect/pres and a wider tag enum that Go and packages/core/src/wire.ts refuse, so REAL recorder chunks cannot be
// admitted today; this fixture does not claim otherwise). Profile chunks are produced by the real nativeperf assembler over
// sanitized SYNTHETIC kernel events (no perf privileges exist on the test host); see profile-fixture.json.
import {createHash,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import type {APIRequestContext,Page} from '@playwright/test';
import {adminCommand,at,field,id,origin,postJson,SECOND,type Source} from './real';

const MS=1_000_000n;
const ZERO='0'.repeat(64);

function canon(v:unknown):string{
 if(v===null||typeof v==='boolean'||typeof v==='number')return JSON.stringify(v);
 if(typeof v==='string')return JSON.stringify(v).replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
 if(Array.isArray(v))return `[${v.map(canon).join(',')}]`;
 if(typeof v==='object')return `{${Object.keys(v).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map((k)=>`${canon(k)}:${canon((v as Record<string,unknown>)[k])}`).join(',')}}`;
 throw Error('not canonicalizable');
}
/** replays.ChunkHash: SHA-256 over the canonical JSON of the whole chunk. */
export const chunkHash=(chunk:unknown):string=>createHash('sha256').update(canon(chunk)).digest('hex');

export interface ChunkSpec{checkpoint?:boolean;loss?:number;policy?:string;raw?:string}
export class Recorder{
 readonly replay=id();readonly session=id();
 private readonly domain={host:id(),boot:id(),runtime:id()};
 private seq=0;private prev=ZERO;private cpSeq=0;private cpHash=ZERO;
 /** The next chunk of the chain. `raw` puts text into a node: the real route must refuse it. */
 next(spec:ChunkSpec={}):Record<string,unknown>{
  this.seq++;
  const wall=BigInt(Date.now())*MS;
  const checkpoint=spec.checkpoint===true;
  const chunk:Record<string,unknown>={
   replay_id:this.replay,session_id:this.session,recorder_version:'1',sequence:String(this.seq),previous_hash:this.prev,
   checkpoint_sequence:String(checkpoint?this.seq:this.cpSeq),checkpoint_hash:checkpoint?this.prev:this.cpHash,
   clock:{wall_ns:wall.toString(),mono_ns:String(this.seq*1000),domain:this.domain,uncertainty_ns:'0'},
   nodes:checkpoint?[{id:'1',parent:'0',tag:'div',class:'masked',text:spec.raw??'[masked]'},{id:'2',parent:'1',tag:'button',class:'',text:'[masked]'},{id:'3',parent:'1',tag:'input',class:'',text:'[masked]'}]:[],
   events:[{at_ns:wall.toString(),kind:'pointer',node:'1',x:this.seq,y:3}],loss:String(spec.loss??0),gap:false,capture_policy_revision:spec.policy??'1',
  };
  const hash=chunkHash(chunk);
  this.prev=hash;
  if(checkpoint){this.cpSeq=this.seq;this.cpHash=hash;}
  return chunk;
 }
}

/** A structured source for replay and profile records (replay=true in the policy). */
export async function onboardReplaySource(page:Page,org:string,project:string):Promise<Source>{
 const source=id(),service=id(),environment=id(),build=id(),instance='opaque-instance';
 const kinds=['replay_chunk','profile_chunk','capability','loss'];
 const policy={revision:'1',enabled:true,class:'structured',kinds,templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build],instance_pseudonym:[instance]},labels:{},operations:[],dependencies:[],codes:[],retention_days:{replay_chunk:14,profile_chunk:7,capability:30,loss:30},max_bytes:'1073741824',max_series:'1000',replay:true,expires_ns:'0'};
 const r=await postJson(page,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:(BigInt(Date.now())*MS+24n*3600n*SECOND).toString(),policy,reason:'Replay and profile e2e fixture'});
 const credential=field(r.json,'credential'),revision=field(field(r.json,'descriptor'),'policy_revision');
 if(r.status!==200||typeof credential!=='string')throw Error(`replay source onboarding: HTTP ${r.status} ${r.text}`);
 return {id:source,credential,producer:id(),org,project,service,environment,build,instance,policyRevision:typeof revision==='string'?revision:'1',kinds:['replay_chunk']} as unknown as Source;
}

/** model.OwnerSlot: replay and profile chunks route by their own ID; capability and loss records by source, producer and kind. */
function slotOf(s:Source,r:Record<string,unknown>):number{
 const kind=String(r.kind),payload=r.payload as Record<string,unknown>;
 const owner=kind==='replay_chunk'?String(payload.replay_id):kind==='profile_chunk'?String(payload.profile_id):s.id+s.producer+kind;
 const h=createHash('sha256');
 for(const part of [s.org,s.project,kind,owner]){const b=Buffer.from(part,'utf8'),n=Buffer.alloc(4);n.writeUInt32BE(b.length);h.update(n);h.update(b);}
 return h.digest()[7]!%64;
}
/** The HTTP status of one real batch of one record: 200 when stored, the refusal status otherwise (a refusal is an expected result here). */
async function ingestBatchRaw(request:APIRequestContext,s:Source,records:Record<string,unknown>[]):Promise<number>{
 const only=records[0];
 if(records.length!==1||only===undefined)throw Error('one record per batch');
 const batch={version:1,project:s.project,source:s.id,producer:s.producer,id:id(),policy_revision:s.policyRevision,route_slot:slotOf(s,only),records};
 const r=await request.post(new URL('/ingest/v1/batches',origin()).toString(),{headers:{Authorization:`Bearer ${s.credential}`},data:batch});
 return r.status();
}

const resource=(s:Source):Record<string,unknown>=>({service_id:s.service,environment_id:s.environment,build_id:s.build,instance_pseudonym:s.instance,labels:[]});
/** Admit one chunk through the real route and return the HTTP status (200 stored; 4xx refused before storage). */
export async function ingestChunk(request:APIRequestContext,s:Source,chunk:Record<string,unknown>):Promise<number>{
 const wall=(chunk.clock as {wall_ns:string}).wall_ns;
 return ingestBatchRaw(request,s,[{id:id(),kind:'replay_chunk',observed_at_ns:wall,resource:resource(s),payload:chunk}]);
}

export interface ReplaySeed{
 /** C1 D2 D3 [4,5 never arrive] C6 D7 D8; chunk 2 reports 3 lost events. */
 gap:{replay:string;recorder:Recorder};
 /** C1 D2 D3 [4 never arrives] D5 D6 C7 D8: the deltas after the hole must not resume playback. */
 afterGap:{replay:string};
 /** One chunk whose node text carries a canary: refused by the real route. */
 canary:{text:string;status:number};
 clean:{replay:string};
}

export async function seedReplays(request:APIRequestContext,s:Source):Promise<ReplaySeed>{
 const send=async(recorder:Recorder,spec:ChunkSpec,deliver=true):Promise<void>=>{
  const chunk=recorder.next(spec);
  if(!deliver)return;
  const status=await ingestChunk(request,s,chunk);
  if(status!==200)throw Error(`replay chunk refused: HTTP ${status}`);
 };
 const gap=new Recorder();
 await send(gap,{checkpoint:true});await send(gap,{loss:3});await send(gap,{});await send(gap,{},false);await send(gap,{},false);await send(gap,{checkpoint:true});await send(gap,{});await send(gap,{});
 const after=new Recorder();
 await send(after,{checkpoint:true});await send(after,{});await send(after,{});await send(after,{},false);await send(after,{});await send(after,{});await send(after,{checkpoint:true});await send(after,{});
 const clean=new Recorder();
 await send(clean,{checkpoint:true});await send(clean,{});await send(clean,{});
 const text='RAW-PAGE-CANARY-'+randomBytes(6).toString('hex');
 const tainted=new Recorder();
 const status=await ingestChunk(request,s,tainted.next({checkpoint:true,raw:text}));
 return {gap:{replay:gap.replay,recorder:gap},afterGap:{replay:after.replay},canary:{text,status},clean:{replay:clean.replay}};
}

/** Enable or revoke exactly these permissions for one user on one project (a real `grant` command). */
export async function setPermissions(page:Page,org:string,userId:string,project:string,enabled:boolean,permissions:readonly string[]):Promise<void>{
 await adminCommand(page,org,'grant',{user_id:userId,project_id:project,enabled,permissions:[...permissions]});
}

// ---- profiles ---------------------------------------------------------------------------------------------------
interface Fixture{chunk:Record<string,unknown>;capabilities:{id:string;value:Record<string,unknown>}[]}
const fixture=JSON.parse(readFileSync(fileURLToPath(new URL('./profile-fixture.json',import.meta.url)),'utf8')) as Fixture;
export const NATIVE_PROFILE=String(fixture.chunk.profile_id);
export const T0_NS=at(0);
/** The window every profile page of the spec opens: it contains the whole fixture. */
export const PROFILE_WINDOW={start:T0_NS-SECOND,end:T0_NS+10n*SECOND};

const BROWSER_PROFILE='5b010000000000000000000000000000',BROWSER_PROCESS='5b020000000000000000000000000000',BROWSER_CAP='5b030000000000000000000000000000';
export const UNSUPPORTED_PROFILE=BROWSER_PROFILE;

/** Admit the native profile (real assembler output) and an unsupported browser-sampling profile through the real ingest route. */
export async function seedProfiles(request:APIRequestContext,s:Source):Promise<void>{
 const observed=T0_NS.toString();
 for(const c of fixture.capabilities){
  const st=await ingestBatchRaw(request,s,[{id:c.id,kind:'capability',observed_at_ns:observed,resource:resource(s),payload:c.value}]);
  if(st!==200)throw Error(`capability refused: HTTP ${st}`);
 }
 let st=await ingestBatchRaw(request,s,[{id:id(),kind:'profile_chunk',observed_at_ns:observed,resource:resource(s),payload:fixture.chunk}]);
 if(st!==200)throw Error(`native profile chunk refused: HTTP ${st}`);
 const clock=fixture.chunk.clock;
 const unsupported={runtime:'firefox',version:'130',build:'release',os:'linux',arch:'amd64',signal:'profile_chunk',method:'browser_js_self_profile',status:'unsupported',reason:'api_unavailable',coverage:{frames:'none',threads:'none',workers:'none',tasks:'none'},clock_domain:(clock as {domain:unknown}).domain,expires_ns:(T0_NS+86_400n*SECOND).toString()};
 st=await ingestBatchRaw(request,s,[{id:BROWSER_CAP,kind:'capability',observed_at_ns:observed,resource:resource(s),payload:unsupported}]);
 if(st!==200)throw Error(`browser capability refused: HTTP ${st}`);
 const chunk={profile_id:BROWSER_PROFILE,process_id:BROWSER_PROCESS,capability_id:BROWSER_CAP,method:'runtime_cpu',units:'samples',start_ns:observed,end_ns:(T0_NS+SECOND).toString(),clock,frames:[],stacks:[],samples:[],intervals:[],loss:'0',truncated:false};
 st=await ingestBatchRaw(request,s,[{id:id(),kind:'profile_chunk',observed_at_ns:observed,resource:resource(s),payload:chunk}]);
 if(st!==200)throw Error(`browser profile chunk refused: HTTP ${st}`);
}
