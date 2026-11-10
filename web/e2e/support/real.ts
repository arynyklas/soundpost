// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server helpers for the Explore e2e specs. Nothing here fakes a route: organizations, projects, users, grants and
// source policies go through POST /api/v1/admin/commands, source credentials through POST /api/v1/sources, telemetry
// through the real POST /ingest/v1/batches with that credential, and every read through the real query/live routes.
// Nanosecond values are decimal strings or bigint, never number; floats travel as the 16-hex-digit IEEE-754 bits.
import {request as playwrightRequest,type APIRequestContext,type Page} from '@playwright/test';
import {createHash,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

export type Ns=bigint|string;
export type Kind='metric'|'log'|'span';
export interface Reply{status:number;text:string;json:unknown}
export interface Source{id:string;credential:string;producer:string;org:string;project:string;service:string;environment:string;build:string;instance:string;policyRevision:string;kinds:readonly Kind[];template?:LogTemplateWire}
export interface Reader{id:string;email:string;password:string}
export interface Owner{email:string;password:string}
export interface LogTemplateWire{id:string;revision:string;line:string;severity:string;fields:{name:string;type:string;max_bytes:number;sensitivity:string;values:unknown[]}[]}

// ---- constants -------------------------------------------------------------------------------------------------
export const SECOND=1_000_000_000n;
/** 1730000000000000000 ns: every metric sample time is a whole-millisecond multiple (the PromQL oracle rule). */
export const T0=1730000000000000000n;
export const at=(seconds:number):bigint=>{if(!Number.isInteger(seconds))throw Error('whole seconds only');return T0+BigInt(seconds)*SECOND;};
export const NAN_BITS='7ff8000000000001';
export const STALE_BITS='7ff0000000000002';
export const INF_BITS='7ff0000000000000';
export const NEG_INF_BITS='fff0000000000000';
export const NEG_ZERO_BITS='8000000000000000';
export const bitsOf=(n:number):string=>{const b=Buffer.alloc(8);b.writeDoubleBE(n);return b.toString('hex');};
export const CANARY_LINE='<img src=x onerror="window.__pwn=1"> user {name} signed in & <b>x</b>';
export const CANARY_FIELD='<script>window.__pwn=1</script>';
export const CANARY_LABEL='<img src=x onerror=window.__pwn=2>';
export const PROM_PROFILE='promql-prometheus-3.1.0';
export const LOG_PROFILE='logql-loki-3.5.2';

const ns=(v:Ns):string=>{const s=typeof v==='bigint'?v.toString():v;if(!/^(0|-?[1-9][0-9]{0,18})$/.test(s))throw Error(`not a canonical decimal nanosecond string: ${s}`);return s;};
export const id=():string=>randomBytes(16).toString('hex');
export const spanId=():string=>randomBytes(8).toString('hex');
export const origin=():string=>new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
const url=(path:string):string=>`${origin()}${path}`;
export function owner():Owner{
 const email=process.env.SOUNDPOST_SCOPE_EMAIL,password=process.env.SOUNDPOST_SCOPE_PASSWORD;
 if(!email||!password)throw Error('SOUNDPOST_SCOPE_EMAIL and SOUNDPOST_SCOPE_PASSWORD must name the provisioned instance owner');
 return {email,password};
}

// ---- profiles --------------------------------------------------------------------------------------------------
interface ProfileFile{feature_sets:{id:string;enabled:string[]}[]}
function profileFile(profile:string):ProfileFile{return JSON.parse(readFileSync(resolve(process.cwd(),'..','profiles','query',`${profile}.json`),'utf8')) as ProfileFile;}
/** The first feature set the profile lists (the default set, nothing enabled). */
export function featureSet(profile:string):string{const first=profileFile(profile).feature_sets[0];if(!first)throw Error(`no feature set in ${profile}`);return first.id;}
/** The feature set whose enabled list is exactly `features`. */
export function featureSetEnabling(profile:string,...features:string[]):string{
 const want=[...features].sort().join(',');
 const set=profileFile(profile).feature_sets.find((s)=>[...s.enabled].sort().join(',')===want);
 if(!set)throw Error(`${profile} has no feature set enabling exactly ${want}`);return set.id;
}

// ---- HTTP with a cookie session -------------------------------------------------------------------------------
function parse(text:string):unknown{try{return JSON.parse(text) as unknown;}catch{return null;}}
/** A property of a parsed JSON value, or undefined when the value is not an object that has it. */
export function field(value:unknown,key:string):unknown{return typeof value==='object'&&value!==null&&key in value?Reflect.get(value,key):undefined;}
const reply=async(r:{status():number;text():Promise<string>}):Promise<Reply>=>{const text=await r.text();return {status:r.status(),text,json:parse(text)};};
export async function csrf(page:Page):Promise<string>{
 const r=await page.request.get(url('/api/v1/session'));
 const token=field(parse(await r.text()),'csrf');
 if(r.status()!==200||typeof token!=='string')throw Error(`no session (HTTP ${r.status()}): log in first`);
 return token;
}
/** POST a JSON body as the page's cookie session with the CSRF token and Origin the real routes require. */
export async function postJson(page:Page,path:string,data:unknown):Promise<Reply>{
 return reply(await page.request.post(url(path),{headers:{'X-CSRF-Token':await csrf(page),Origin:origin()},data}));
}
/** The session cookie and CSRF token of a logged-in page, for clients that are not the browser (Node fetch SSE). */
export async function sessionCredentials(page:Page):Promise<{cookie:string;csrf:string}>{
 const cookie=(await page.context().cookies(origin())).find((c)=>c.name==='__Host-soundpost');
 if(!cookie)throw Error('no session cookie');
 return {cookie:`${cookie.name}=${cookie.value}`,csrf:await csrf(page)};
}

const logins=new WeakMap<Page,{email:string;password:string;at:number}>();
/** Real password login over POST /api/v1/login; the context keeps the HttpOnly session cookie. */
export async function login(page:Page,email:string,password:string):Promise<void>{
 const r=await reply(await page.request.post(url('/api/v1/login'),{headers:{Origin:origin()},data:{Email:email,Password:password,Code:''}}));
 if(r.status!==200)throw Error(`login ${email}: HTTP ${r.status} ${r.text}`);
 logins.set(page,{email,password,at:Date.now()});
}
// Admin commands and source onboarding demand a session authenticated within five minutes; a long spec logs in again
// (a new session cookie in the same context) before it runs out. Do not drive the browser UI from a page that also
// issues admin commands for longer than that.
async function fresh(page:Page):Promise<void>{
 const known=logins.get(page);
 if(known&&Date.now()-known.at>4*60_000)await login(page,known.email,known.password);
}

// ---- admin commands --------------------------------------------------------------------------------------------
/** One real admin command as an org admin: reads the current revision, sends the command, retries only a revision race. */
export async function adminCommand(page:Page,org:string,kind:string,payload:Record<string,unknown>):Promise<unknown>{
 await fresh(page);
 for(let attempt=0;;attempt++){
  const read=await postJson(page,'/api/v1/admin/read',{kind:'organizations'});
  const revision=field(read.json,'revision');
  if(read.status!==200||typeof revision!=='string')throw Error(`admin read: HTTP ${read.status} ${read.text}`);
  const r=await postJson(page,'/api/v1/admin/commands',{command_id:id(),expected_revision:revision,org_id:org,kind,payload:{...payload,reason:'Explore e2e fixture'}});
  if(r.status===409&&attempt<4)continue;
  if(r.status>=300)throw Error(`admin ${kind}: HTTP ${r.status} ${r.text}`);
  return r.json;
 }
}
export async function createOrg(page:Page,name='explore e2e org'):Promise<string>{const org=id();await adminCommand(page,org,'create_org',{name});return org;}
export async function createProject(page:Page,org:string,name='explore e2e project'):Promise<string>{const project=id();await adminCommand(page,org,'create_project',{id:project,name});return project;}
/** Enable or revoke telemetry.read for one user on one project (a real `grant` command). */
export async function setGrant(page:Page,org:string,userId:string,project:string,enabled:boolean):Promise<void>{
 await adminCommand(page,org,'grant',{user_id:userId,project_id:project,enabled,permissions:['telemetry.read']});
}
/** A real member with telemetry.read on each project, able to log in with the returned password. */
export async function createReader(page:Page,org:string,projects:readonly string[]):Promise<Reader>{
 const reader:Reader={id:id(),email:`reader-${id().slice(0,8)}@example.test`,password:`explore reader password ${id().slice(0,8)}`};
 await adminCommand(page,org,'create_user',{id:reader.id,email:reader.email,password:reader.password});
 await adminCommand(page,org,'membership',{user_id:reader.id,enabled:true});
 for(const project of projects)await setGrant(page,org,reader.id,project,true);
 return reader;
}

// ---- canonical JSON and route slots (internal/model/telemetry.go CanonicalJSON, OwnerKey, OwnerSlot) ---------------
function canon(v:unknown):string{
 if(v===null||typeof v==='boolean'||typeof v==='number')return JSON.stringify(v);
 if(typeof v==='string')return JSON.stringify(v).replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
 if(Array.isArray(v))return `[${v.map(canon).join(',')}]`;
 if(typeof v==='object')return `{${Object.keys(v).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map((k)=>`${canon(k)}:${canon((v as Record<string,unknown>)[k])}`).join(',')}}`;
 throw Error('not canonicalizable');
}
interface RecordWire{id:string;kind:Kind;observed_at_ns:string;resource:Record<string,unknown>;payload:Record<string,unknown>}
function ownerKey(r:RecordWire):string{
 switch(r.kind){
 case 'metric':return canon({name:r.payload.name,labels:r.payload.labels});
 case 'log':return canon(r.payload.stream_labels);
 case 'span':return String(r.payload.trace_id);
 }
}
function routeSlot(org:string,project:string,r:RecordWire):number{
 const h=createHash('sha256');
 for(const part of [org,project,r.kind,ownerKey(r)]){const b=Buffer.from(part,'utf8'),n=Buffer.alloc(4);n.writeUInt32BE(b.length);h.update(n);h.update(b);}
 return h.digest()[7]!%64; // uint16(first 8 bytes big-endian) % 64: 64 divides 2^64, so only the last byte matters
}
const labelsWire=(labels:Record<string,string>|undefined):{name:string;value:string}[]=>Object.keys(labels??{}).sort((a,b)=>Buffer.compare(Buffer.from(a),Buffer.from(b))).map((name)=>({name,value:(labels as Record<string,string>)[name] as string}));

// ---- source onboarding -----------------------------------------------------------------------------------------
interface SourcePolicyInput{kinds:Kind[];templates:LogTemplateWire[];labels:Record<string,string[]>;operations:string[]}
const INSTANCE='opaque-instance';
async function onboard(page:Page,org:string,project:string,p:SourcePolicyInput):Promise<Source>{
 await fresh(page);
 const source=id(),service=id(),environment=id(),build=id();
 const retention:Record<string,number>={};for(const k of p.kinds)retention[k]=7;
 const policy={revision:'1',enabled:true,class:'structured',kinds:p.kinds,templates:p.templates,resources:{service_id:[service],environment_id:[environment],build_id:[build],instance_pseudonym:[INSTANCE]},labels:p.labels,operations:p.operations,dependencies:[],codes:[],retention_days:retention,max_bytes:'1048576',max_series:'1000',replay:false,expires_ns:'0'};
 const r=await postJson(page,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:ns(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND),policy,reason:'Explore e2e fixture'});
 const credential=field(r.json,'credential'),policyRevision=field(field(r.json,'descriptor'),'policy_revision');
 if(r.status!==200||typeof credential!=='string')throw Error(`source onboarding: HTTP ${r.status} ${r.text}`);
 return {id:source,credential,producer:id(),org,project,service,environment,build,instance:INSTANCE,policyRevision:typeof policyRevision==='string'?policyRevision:'1',kinds:p.kinds,...(p.templates[0]?{template:p.templates[0]}:{})};
}
export interface MetricSourceOptions{labels?:Record<string,string[]>;operations?:string[]}
/** A structured source for metrics and spans; `labels` is the allow-list name -> permitted values. */
export function onboardMetricSource(page:Page,org:string,project:string,opts:MetricSourceOptions={}):Promise<Source>{
 return onboard(page,org,project,{kinds:['metric','span'],templates:[],labels:opts.labels??{job:['api'],kind:['float','hist']},operations:opts.operations??['op.request']});
}
export interface LogSourceOptions{labels?:Record<string,string[]>;names?:string[];line?:string}
/** A structured source with one log template `signin` (`{name}` placeholder) whose line is the HTML/XSS canary text. */
export function onboardLogSource(page:Page,org:string,project:string,opts:LogSourceOptions={}):Promise<Source>{
 const names=opts.names??['alice','bob','carol','dave',CANARY_FIELD];
 const template:LogTemplateWire={id:'signin',revision:'1',line:opts.line??CANARY_LINE,severity:'info',fields:[{name:'name',type:'string',max_bytes:128,sensitivity:'metadata',values:names}]};
 return onboard(page,org,project,{kinds:['log'],templates:[template],labels:opts.labels??{app:['web'],canary:[CANARY_LABEL]},operations:[]});
}

// ---- ingest ----------------------------------------------------------------------------------------------------
function resourceWire(s:Source):Record<string,unknown>{return {service_id:s.service,environment_id:s.environment,build_id:s.build,instance_pseudonym:s.instance,labels:[]};}
/** POST one real batch holding `records` (one route slot per batch) with the source credential; throws unless HTTP 200. */
export async function ingestBatch(request:APIRequestContext,s:Source,records:RecordWire[]):Promise<unknown>{
 const slots=new Set(records.map((r)=>routeSlot(s.org,s.project,r)));
 if(slots.size!==1)throw Error('records of one batch must share a route slot');
 const batch={version:1,project:s.project,source:s.id,producer:s.producer,id:id(),policy_revision:s.policyRevision,route_slot:[...slots][0],records};
 const r=await reply(await request.post(url('/ingest/v1/batches'),{headers:{Authorization:`Bearer ${s.credential}`},data:batch}));
 if(r.status!==200)throw Error(`ingest: HTTP ${r.status} ${r.text}`);
 return r.json;
}
export interface IntegerHistogramWire{flavor:'counter'|'gauge';schema:number;zero_threshold:string;sum:string;count:string;zero_count:string;positive_spans:{offset:number;length:number}[];negative_spans:{offset:number;length:number}[];positive_buckets:string[];negative_buckets:string[];reset_hint:'unknown'|'reset'|'not_reset'|'gauge'}
export type HistogramWire={integer:IntegerHistogramWire}|{float:Record<string,unknown>};
/** A valid integer native histogram: schema 0, one zero-bucket observation, positive buckets 2 and 1 (delta-encoded 2,-1), sum 5.5, count 4. */
export const integerHistogram=():HistogramWire=>({integer:{flavor:'counter',schema:0,zero_threshold:bitsOf(0),sum:bitsOf(5.5),count:'4',zero_count:'1',positive_spans:[{offset:0,length:2}],negative_spans:[],positive_buckets:['2','-1'],negative_buckets:[],reset_hint:'unknown'}});
export interface MetricInput{name:string;labels?:Record<string,string>;at:Ns;bits?:string;value?:number;stale?:true;histogram?:HistogramWire;exemplar?:{trace:string;span?:string};unit?:string;type?:'counter'|'gauge'|'histogram'|'unknown'}
/** One metric point as its own real batch. Exactly one of bits | value | stale | histogram. */
export function ingestMetric(request:APIRequestContext,s:Source,m:MetricInput):Promise<unknown>{
 const given=[m.bits!==undefined,m.value!==undefined,m.stale===true,m.histogram!==undefined].filter(Boolean).length;
 if(given!==1)throw Error('exactly one of bits, value, stale, histogram');
 const payload:Record<string,unknown>={name:m.name,labels:labelsWire(m.labels),unit:m.unit??'1',type:m.type??(m.histogram?'histogram':'gauge')};
 if(m.histogram){payload.sample_kind='integer' in m.histogram?'integer_histogram':'float_histogram';payload.histogram=m.histogram;}
 else{payload.sample_kind=m.stale?'stale':'float';payload.value=m.stale?STALE_BITS:m.bits??bitsOf(m.value as number);}
 if(m.exemplar){payload.exemplar_trace=m.exemplar.trace;if(m.exemplar.span)payload.exemplar_span=m.exemplar.span;}
 return ingestBatch(request,s,[{id:id(),kind:'metric',observed_at_ns:ns(m.at),resource:resourceWire(s),payload}]);
}
export interface LogInput{at:Ns;name:string;labels?:Record<string,string>}
/** One structured log line (template `signin`, field `name`) as its own real batch; returns the rendered line. */
export async function ingestLog(request:APIRequestContext,s:Source,l:LogInput):Promise<string>{
 const template=s.template;if(!template)throw Error('not a log source');
 const payload={timestamp_ns:ns(l.at),template_id:template.id,template_revision:template.revision,fields:{name:l.name},stream_labels:labelsWire(l.labels??{app:'web'}),structured_metadata:{}};
 await ingestBatch(request,s,[{id:id(),kind:'log',observed_at_ns:ns(l.at),resource:resourceWire(s),payload}]);
 return template.line.replace('{name}',l.name);
}
export interface SpanInput{trace:string;span?:string;at:Ns;operation?:string}
/** One finished server span of `trace` as its own real batch (makes the trace resolvable by the real link resolver). */
export async function ingestSpan(request:APIRequestContext,s:Source,sp:SpanInput):Promise<string>{
 const span=sp.span??spanId(),domain={host:id(),boot:id(),runtime:id()};
 const clock=(wall:bigint,mono:string)=>({wall_ns:ns(wall),mono_ns:mono,domain,uncertainty_ns:'0'});
 const start=BigInt(sp.at);
 const payload={trace_id:sp.trace,span_id:span,parent_id:null,span_kind:'server',operation:sp.operation??'op.request',start:clock(start,'1000000000'),end:clock(start+SECOND/100n,'1010000000'),status:'ok',dependency_alias:'',links:[],sample_probability:bitsOf(1),sample_decision:'keep'};
 await ingestBatch(request,s,[{id:id(),kind:'span',observed_at_ns:ns(sp.at),resource:resourceWire(s),payload}]);
 return span;
}

// ---- queries ---------------------------------------------------------------------------------------------------
export interface QueryInput{org:string;projects:readonly string[];expression:string;language?:'promql'|'logql';featureSet?:string;instant?:Ns;start?:Ns;end?:Ns;step?:Ns;maxReturned?:string;logLimit?:string;logOrder?:'forward'|'backward';allowPartial?:boolean}
/** The exact wire body of POST /api/v1/query (scope fields flattened next to the typed request). */
export function queryBody(q:QueryInput):Record<string,unknown>{
 const language=q.language??'promql',profile=language==='promql'?PROM_PROFILE:LOG_PROFILE;
 const instant=q.instant!==undefined;
 return {org:q.org,language,profile,feature_set:q.featureSet??featureSet(profile),expression:q.expression,
  evaluation:{instant,time:instant?ns(q.instant as Ns):'0',start:instant?'0':ns(q.start??'0'),end:instant?'0':ns(q.end??'0'),step:instant?'0':ns(q.step??'0')},
  projects:[...q.projects],budget:{timeout_ns:'0',memory_bytes:'0',max_returned:q.maxReturned??'0'},allow_partial:q.allowPartial??false,
  ...(q.logLimit!==undefined?{log_limit:q.logLimit}:{}),...(q.logOrder!==undefined?{log_order:q.logOrder}:{})};
}
export const runQuery=(page:Page,q:QueryInput):Promise<Reply>=>postJson(page,'/api/v1/query',queryBody(q));

// ---- live (real SSE route) -------------------------------------------------------------------------------------
export interface LiveInput{org:string;projects:readonly string[];expression:string;featureSet?:string}
/** POST /api/v1/live-tickets: scope fields + {projects,profile,feature_set,expression,budget}. */
export const liveTicket=(page:Page,l:LiveInput):Promise<Reply>=>postJson(page,'/api/v1/live-tickets',{org:l.org,projects:[...l.projects],profile:LOG_PROFILE,feature_set:l.featureSet??featureSet(LOG_PROFILE),expression:l.expression,budget:{timeout_ns:'0',memory_bytes:'0',max_returned:'0'}});
export interface Frame{event:string;id?:string;data:unknown}
/** GET /api/v1/live?ticket=<id> through Node fetch as the page's session; yields parsed SSE frames until the server ends the stream. */
export async function* liveFrames(page:Page,ticket:string,signal?:AbortSignal):AsyncGenerator<Frame>{
 const {cookie,csrf:token}=await sessionCredentials(page);
 const response=await fetch(url(`/api/v1/live?ticket=${ticket}`),{headers:{Cookie:cookie,'X-CSRF-Token':token,Origin:origin(),Accept:'text/event-stream'},...(signal?{signal}:{})});
 if(response.status!==200||!response.body)throw Error(`live: HTTP ${response.status} ${await response.text()}`);
 const decoder=new TextDecoder();let buffer='';
 for await(const chunk of response.body as unknown as AsyncIterable<Uint8Array>){
  buffer+=decoder.decode(chunk,{stream:true});
  for(let end=buffer.indexOf('\n\n');end>=0;end=buffer.indexOf('\n\n')){
   const raw=buffer.slice(0,end);buffer=buffer.slice(end+2);
   let event='message',frameId:string|undefined;const data:string[]=[];
   for(const line of raw.split('\n')){
    if(line.startsWith(':'))continue;
    if(line.startsWith('event: '))event=line.slice(7);
    else if(line.startsWith('id: '))frameId=line.slice(4);
    else if(line.startsWith('data: '))data.push(line.slice(6));
   }
   if(data.length===0&&event==='message')continue;
   yield {event,...(frameId!==undefined?{id:frameId}:{}),data:parse(data.join('\n'))};
  }
 }
}

// ---- the Explore fixture ---------------------------------------------------------------------------------------
export interface ExploreSeed{
 org:string;p1:string;p2:string;reader:Reader;owner:Owner;
 metricP1:Source;metricP2:Source;logP1:Source;
 /** Trace with a real ingested span (link available) and a trace whose span was never ingested (link not found). */
 trace:{ingested:string;span:string;missing:string};
 t0:string;
 logs:{first:string;second:string;duplicate:string;canaryField:string;canaryLabel:string;lines:{at:string;name:string;line:string;labels:Record<string,string>}[]};
}
/**
 * Build the whole dataset through real routes as the owner page: one org, projects P1/P2, reader R (telemetry.read on
 * both), the metric, histogram, stale, exemplar, shared-series and log fixtures, then prove it by querying as R.
 */
export async function seedExplore(page:Page,request:APIRequestContext):Promise<ExploreSeed>{
 const who=owner();
 const org=await createOrg(page,'explore e2e org'),p1=await createProject(page,org,'explore P1'),p2=await createProject(page,org,'explore P2');
 const reader=await createReader(page,org,[p1,p2]);
 const metricP1=await onboardMetricSource(page,org,p1),metricP2=await onboardMetricSource(page,org,p2),logP1=await onboardLogSource(page,org,p1);
 const api={job:'api'};
 const m=(s:Source,input:MetricInput)=>ingestMetric(request,s,input);
 for(let i=0;i<=6;i++)await m(metricP1,{name:'explore_gauge',labels:api,at:at(i*10),value:42+i});
 await m(metricP1,{name:'explore_nan',labels:api,at:at(0),value:1});
 await m(metricP1,{name:'explore_nan',labels:api,at:at(10),bits:NAN_BITS});
 await m(metricP1,{name:'explore_inf',labels:api,at:at(10),bits:INF_BITS});
 await m(metricP1,{name:'explore_neginf',labels:api,at:at(10),bits:NEG_INF_BITS});
 await m(metricP1,{name:'explore_negzero',labels:api,at:at(10),bits:NEG_ZERO_BITS});
 for(const i of [0,1,2])await m(metricP1,{name:'explore_stale',labels:api,at:at(i*10),value:10+i});
 await m(metricP1,{name:'explore_stale',labels:api,at:at(30),stale:true});
 await m(metricP1,{name:'explore_stale',labels:api,at:at(60),value:20});
 await m(metricP1,{name:'explore_hist',labels:api,at:at(10),histogram:integerHistogram(),type:'histogram'});
 await m(metricP1,{name:'explore_mixed',labels:{kind:'float'},at:at(10),value:3});
 await m(metricP1,{name:'explore_mixed',labels:{kind:'hist'},at:at(10),histogram:integerHistogram(),type:'histogram'});
 const trace={ingested:id(),span:spanId(),missing:id()};
 await ingestSpan(request,metricP1,{trace:trace.ingested,span:trace.span,at:at(10)});
 await m(metricP1,{name:'explore_requests',labels:api,at:at(10),value:5,type:'counter',exemplar:{trace:trace.ingested,span:trace.span}});
 await m(metricP1,{name:'explore_requests',labels:api,at:at(20),value:6,type:'counter',exemplar:{trace:trace.missing,span:spanId()}});
 await m(metricP1,{name:'explore_shared',labels:api,at:at(60),value:1});
 await m(metricP2,{name:'explore_shared',labels:api,at:at(60),value:2});
 const web={app:'web'},canary={app:'web',canary:CANARY_LABEL};
 const plan:{at:bigint;name:string;labels:Record<string,string>}[]=[
  {at:T0+1n,name:'alice',labels:web},{at:T0+2n,name:'bob',labels:web},{at:T0+3n,name:'carol',labels:web},{at:T0+3n,name:'dave',labels:web},
  {at:T0+4n,name:CANARY_FIELD,labels:web},{at:T0+5n,name:'alice',labels:canary}];
 const lines:ExploreSeed['logs']['lines']=[];
 for(const l of plan)lines.push({at:l.at.toString(),name:l.name,labels:l.labels,line:await ingestLog(request,logP1,{at:l.at,name:l.name,labels:l.labels})});
 const seed:ExploreSeed={org,p1,p2,reader,owner:who,metricP1,metricP2,logP1,trace,t0:T0.toString(),logs:{first:`${T0+1n}`,second:`${T0+2n}`,duplicate:`${T0+3n}`,canaryField:CANARY_FIELD,canaryLabel:CANARY_LABEL,lines}};
 await verifyExplore(seed);
 return seed;
}

const sleep=(ms:number):Promise<void>=>{const {promise,resolve}=Promise.withResolvers<void>();setTimeout(resolve,ms);return promise;};
const list=(v:unknown):unknown[]=>Array.isArray(v)?v:[];
/** Samples (vector elements) plus log entries over every project result of a /api/v1/query response. */
export function countReturned(json:unknown):number{
 let n=0;
 for(const project of list(field(json,'projects'))){
  const value=field(project,'value');
  n+=list(field(value,'vector')).length;
  for(const stream of list(field(value,'streams')))n+=list(field(stream,'entries')).length;
 }
 return n;
}
/** Prove the fixture with real queries as reader R in a fresh, cookie-only API context; throws on any mismatch. */
export async function verifyExplore(seed:ExploreSeed):Promise<void>{
 const api=await playwrightRequest.newContext();
 try{
  const session=await api.post(url('/api/v1/login'),{headers:{Origin:origin()},data:{Email:seed.reader.email,Password:seed.reader.password,Code:''}});
  const token=field(parse(await session.text()),'csrf');
  if(session.status()!==200||typeof token!=='string')throw Error(`reader login: HTTP ${session.status()}`);
  const expect=async(what:string,q:QueryInput,want:number):Promise<void>=>{
   for(let i=0;i<50;i++){
    const r=await reply(await api.post(url('/api/v1/query'),{headers:{'X-CSRF-Token':token,Origin:origin()},data:queryBody(q)}));
    if(r.status!==200)throw Error(`verify ${what}: HTTP ${r.status} ${r.text}`);
    if(countReturned(r.json)===want)return;
    await sleep(200);
   }
   throw Error(`seed not visible: ${what}`);
  };
  await expect('explore_gauge',{org:seed.org,projects:[seed.p1],expression:'explore_gauge',instant:at(60)},1);
  await expect('explore_shared in two projects',{org:seed.org,projects:[seed.p1,seed.p2],expression:'explore_shared',instant:at(60)},2);
  await expect('log lines',{org:seed.org,projects:[seed.p1],language:'logql',expression:'{app="web"}',start:T0,end:T0+SECOND,step:SECOND,logOrder:'forward'},seed.logs.lines.length);
 }finally{await api.dispose();}
}
