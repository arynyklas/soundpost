// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Optional, explicitly started runtime supplement (C09 `startProfile`). One in-process callback inspector session over V8's own
// sampling profiler: no debugging listener, no Runtime/Debugger/Heap command, no function arguments or source text. The result
// is `runtime_engine_samples` (engine samples plus engine time deltas); it is NOT OS time and never carries an OS CPU unit.
import {Session,url as inspectorUrl} from "node:inspector";
import {monitorEventLoopDelay} from "node:perf_hooks";
import {isMainThread,threadId} from "node:worker_threads";

export type ProfileStatus="supported"|"denied"|"unsupported"|"error";
export type ProfileReason="ok"|"profiler_owned"|"isolate_scope_mismatch"|"invalid_options"|"client_unavailable"|"inspector_unavailable"|"inspector_timeout"|"inspector_error"|"profiler_state_lost";
export type CoverageValue="complete"|"partial"|"none"|"unknown";
export type StoppedBy="caller"|"duration"|"client_close"|"timeout_cleanup"|"not_started";
export interface LeaseOwner {ownHookLease(lease:{close():void}):void;releaseHookLease(lease:{close():void}):void}
export interface ProfileOptions {
 /** Required wall-clock bound, 1..60000 ms. The profile always stops by itself at this bound. */
 readonly durationMs:number;
 /** Requested engine sampling interval in microseconds, 100..1_000_000 (default 1000). The engine's achieved interval is reported separately. */
 readonly intervalUs?:number;
 /** Declared isolate scope. A mismatch with the isolate the call runs in is refused, never silently reinterpreted. */
 readonly isolate?:"main"|"worker";
 /** Absolute project root. Only code under it is named; every other frame is an anonymous external placeholder. */
 readonly projectRoot?:string;
 /** Sample cap, 1..8192 (default 8192, the C04 ProfileChunk bound). */
 readonly maxSamples?:number;
 /** Also measure event-loop delay as a separate non-profile signal. */
 readonly eventLoopDelay?:boolean;
 /** Optional Soundpost client; `client.close()` then stops this profile (bounded, explicit lease). */
 readonly client?:LeaseOwner;
}
export interface ProfileCoverage {readonly frames:CoverageValue;readonly threads:CoverageValue;readonly workers:CoverageValue;readonly tasks:CoverageValue}
export interface ClockDomain {readonly host:string;readonly boot:string;readonly runtime:string}
export interface ProfileCapability {
 readonly id:string;readonly runtime:string;readonly version:string;readonly build:string;readonly os:string;readonly arch:string;
 readonly signal:"profile_chunk";readonly method:"runtime_engine_samples";readonly status:ProfileStatus;readonly reason:ProfileReason;
 readonly coverage:ProfileCoverage;readonly clock_domain:ClockDomain;readonly expires_ns:string;
}
export interface ProfileFrame {readonly module_id:string;readonly function:string;readonly artifact_id:string;readonly line:number|null;readonly column:number|null;readonly offset:"0";readonly reason:""|"not_captured"}
export interface ProfileSample {readonly at_us:string;readonly stack:number;readonly count:"1";readonly thread:string}
export interface ProfileLoss {readonly reason:"truncated"|"sample_gap"|"foreign_state"|"timeout_cleanup";readonly count:string}
export interface NonProfileMeasurement {
 readonly method:"event_loop_delay";readonly profile:false;readonly signal:"metric";readonly unit:"nanoseconds";readonly resolution_ms:number;
 readonly count:number;readonly min:number|null;readonly max:number|null;readonly mean:number|null;readonly p50:number|null;readonly p99:number|null;readonly exceeds:number;
}
export interface ProfileAck {readonly status:"not_available";readonly reason:"no_profile_admission_path"}
export interface ProfileReport {
 readonly version:1;readonly method:"runtime_engine_samples";readonly profile:true;readonly units:"samples";readonly time_delta_unit:"engine_microseconds";
 readonly capability:ProfileCapability;
 readonly interval:{readonly requested_us:number;readonly achieved_us:number|null};
 readonly clock:{readonly domain:ClockDomain;readonly uncertainty_ns:string;readonly source:"v8_profiler_engine_clock";readonly wall_start_ns:string;readonly wall_end_ns:string};
 readonly scope:{readonly isolate:"main"|"worker";readonly thread_id:number;readonly runtime:{readonly name:string;readonly version:string};readonly debugger_listener_present:boolean};
 readonly coverage:ProfileCoverage;
 readonly requested:{readonly duration_ms:number;readonly interval_us:number;readonly max_samples:number};
 readonly stack_order:"leaf_first";readonly frames:readonly ProfileFrame[];readonly stacks:readonly {readonly frames:readonly number[]}[];readonly samples:readonly ProfileSample[];
 readonly sample_count:number;readonly truncated:boolean;readonly losses:readonly ProfileLoss[];readonly non_profile:readonly NonProfileMeasurement[];
 readonly ack:ProfileAck;readonly stopped_by:StoppedBy;
}
export interface ProfileHandle {readonly active:boolean;readonly capability:ProfileCapability;stop():Promise<ProfileReport>}

/** Structural inspector seam. Production passes `node:inspector`'s in-process Session; tests pass an allowlisting fake. */
export interface InspectorSession {connect():void;post(method:string,params:object|undefined,callback:(error:Error|null,result?:unknown)=>void):void;disconnect():void}
export interface EventLoopHistogram {enable():boolean;disable():boolean;readonly count:number;readonly min:number;readonly max:number;readonly mean:number;readonly exceeds:number;percentile(percentile:number):number}
export interface ProfilerDeps {
 readonly runtime:string;readonly version:string;readonly build:string;readonly os:string;readonly arch:string;
 readonly isMainThread:boolean;readonly threadId:number;
 readonly createSession:()=>InspectorSession;readonly inspectorUrl:()=>string|undefined;
 readonly wallNs:()=>bigint;readonly setTimer:(callback:()=>void,ms:number,unref:boolean)=>{cancel():void};
 readonly commandTimeoutMs:number;readonly registry:{owner:unknown};
 readonly monitorEventLoopDelay?:(resolutionMs:number)=>EventLoopHistogram;
}

const MAX_DURATION_MS=60_000,MAX_SAMPLES=8192,MAX_FRAMES=4096,MAX_STACK_DEPTH=128,DEFAULT_INTERVAL_US=1000,DEFAULT_COMMAND_TIMEOUT_MS=2000;
const MAX_UNCERTAINTY="18446744073709551615",CAPABILITY_TTL_NS=3_600_000_000_000n,EVENT_LOOP_RESOLUTION_MS=10;
const SAFE_SYMBOL=/^(?:[A-Za-z_$][A-Za-z0-9_$.]{0,127}|<anonymous>|<module>)$/,SAFE_PATH=/^[A-Za-z0-9_./-]{1,256}$/;
const ENGINE_PSEUDO:Readonly<Record<string,string>>={"(idle)":"engine:idle","(program)":"engine:program","(garbage collector)":"engine:gc"};
const NO_COVERAGE:ProfileCoverage={frames:"none",threads:"none",workers:"none",tasks:"none"};
// Frames are JS-only; native frames, other isolates and suspended-Promise ancestry are not observed.
const ENGINE_COVERAGE:ProfileCoverage={frames:"partial",threads:"partial",workers:"none",tasks:"none"};
const EXTERNAL:ProfileFrame={module_id:"external",function:"",artifact_id:"",line:null,column:null,offset:"0",reason:"not_captured"};

class Fault extends Error {constructor(readonly reason:ProfileReason,readonly status:ProfileStatus){super(reason);}}
function randomHex(bytes:number):string{return Array.from(crypto.getRandomValues(new Uint8Array(bytes)),b=>b.toString(16).padStart(2,"0")).join("");}
function safeToken(value:unknown,max:number):string{const text=typeof value==="string"?value.replace(/[^A-Za-z0-9_.:/<>+ $-]/g,"_").slice(0,max):"";return text===""?"unknown":text;}

interface Resolved {readonly durationMs:number;readonly intervalUs:number;readonly isolate:"main"|"worker"|undefined;readonly root:string|undefined;readonly maxSamples:number;readonly eventLoopDelay:boolean;readonly client:LeaseOwner|undefined}
/** Reads each option once, defensively: a hostile accessor can only make the options invalid. */
function resolveOptions(options:unknown):Resolved|undefined{
 try{
  if(typeof options!=="object"||options===null)return undefined;
  const o=options as Record<string,unknown>,durationMs=o.durationMs,intervalUs=o.intervalUs??DEFAULT_INTERVAL_US,maxSamples=o.maxSamples??MAX_SAMPLES,isolate=o.isolate,projectRoot=o.projectRoot,eventLoopDelay=o.eventLoopDelay,client=o.client;
  if(typeof durationMs!=="number"||!Number.isInteger(durationMs)||durationMs<1||durationMs>MAX_DURATION_MS)return undefined;
  if(typeof intervalUs!=="number"||!Number.isInteger(intervalUs)||intervalUs<100||intervalUs>1_000_000)return undefined;
  if(typeof maxSamples!=="number"||!Number.isInteger(maxSamples)||maxSamples<1||maxSamples>MAX_SAMPLES)return undefined;
  if(isolate!==undefined&&isolate!=="main"&&isolate!=="worker")return undefined;
  if(eventLoopDelay!==undefined&&typeof eventLoopDelay!=="boolean")return undefined;
  let root:string|undefined;
  if(projectRoot!==undefined){if(typeof projectRoot!=="string"||projectRoot.includes("\0")||!/^(?:[A-Za-z]:[\\/]|[\\/])/.test(projectRoot))return undefined;root=normalizeRoot(projectRoot);}
  if(client!==undefined&&(typeof client!=="object"||client===null||typeof (client as LeaseOwner).ownHookLease!=="function"||typeof (client as LeaseOwner).releaseHookLease!=="function"))return undefined;
  return {durationMs,intervalUs,isolate,root,maxSamples,eventLoopDelay:eventLoopDelay===true,client:client as LeaseOwner|undefined};
 }catch{return undefined;}
}
function normalizeRoot(root:string):string{const slashed=root.replace(/\\/g,"/"),body=slashed.replace(/\/+/g,"/"),trimmed=body.length>1?body.replace(/\/$/,""):body;return slashed.startsWith("//")?"/"+trimmed:trimmed;}

/** Maps a V8 callFrame to a code identity. Anything outside the project root (or any unsafe symbol) is withheld, not guessed. */
function frameOf(call:unknown,root:string|undefined):ProfileFrame|null{
 const c=(typeof call==="object"&&call!==null?call:{}) as Record<string,unknown>,name=typeof c.functionName==="string"?c.functionName:"",url=typeof c.url==="string"?c.url:"";
 if(url===""){
  if(name==="(root)")return null;
  const pseudo=ENGINE_PSEUDO[name];return pseudo?{module_id:"engine",function:pseudo,artifact_id:"",line:null,column:null,offset:"0",reason:""}:EXTERNAL;
 }
 const relative=root===undefined?undefined:projectRelative(url,root);
 if(relative===undefined)return EXTERNAL;
 const symbol=name===""?"<anonymous>":name==="(module)"?"<module>":name,safe=SAFE_SYMBOL.test(symbol);
 const line=typeof c.lineNumber==="number"&&Number.isInteger(c.lineNumber)&&c.lineNumber>=0?c.lineNumber+1:null,column=typeof c.columnNumber==="number"&&Number.isInteger(c.columnNumber)&&c.columnNumber>=0?c.columnNumber+1:null;
 return {module_id:relative,function:safe?symbol:"",artifact_id:relative,line,column,offset:"0",reason:safe?"":"not_captured"};
}
function projectRelative(url:string,root:string):string|undefined{
 let parsed:URL;try{parsed=new URL(url);}catch{return undefined;}
 if(parsed.protocol!=="file:"||parsed.search!==""||parsed.hash!=="")return undefined;
 let path:string;try{path=decodeURIComponent(parsed.pathname);}catch{return undefined;}
 // `file://host/share/x` is the UNC path `//host/share/x`; a drive path is `/C:/x`; anything else is a POSIX path.
 if(parsed.host!=="")path="//"+parsed.host+path;else if(/^\/[A-Za-z]:\//.test(path))path=path.slice(1);
 const folded=/^[A-Za-z]:/.test(root)||root.startsWith("//"),a=folded?path.toLowerCase():path,b=folded?root.toLowerCase():root,prefix=b.endsWith("/")?b:b+"/";
 if(!a.startsWith(prefix))return undefined;
 const relative=path.slice(prefix.length);
 if(!SAFE_PATH.test(relative)||relative.split("/").some(part=>part===""||part==="."||part===".."||part==="node_modules"))return undefined;
 return relative;
}

interface RawProfile {readonly nodes:readonly unknown[];readonly samples:readonly unknown[];readonly timeDeltas:readonly unknown[]}
function rawProfile(value:unknown):RawProfile|undefined{
 const p=(typeof value==="object"&&value!==null?(value as Record<string,unknown>).profile:undefined) as Record<string,unknown>|undefined;
 return p&&Array.isArray(p.nodes)&&Array.isArray(p.samples)&&Array.isArray(p.timeDeltas)&&p.samples.length===p.timeDeltas.length?{nodes:p.nodes,samples:p.samples,timeDeltas:p.timeDeltas}:undefined;
}
interface Mapped {frames:ProfileFrame[];stacks:{frames:number[]}[];samples:ProfileSample[];sampleCount:number;truncated:boolean;losses:ProfileLoss[];achievedUs:number|null}
function mapProfile(raw:RawProfile,root:string|undefined,intervalUs:number,maxSamples:number,thread:number):Mapped{
 const parent=new Map<number,number>(),calls=new Map<number,unknown>();
 for(const node of raw.nodes){const n=(typeof node==="object"&&node!==null?node:{}) as Record<string,unknown>;if(typeof n.id!=="number")continue;calls.set(n.id,n.callFrame);if(Array.isArray(n.children))for(const child of n.children)if(typeof child==="number")parent.set(child,n.id);}
 const frames:ProfileFrame[]=[],frameIndex=new Map<string,number>(),stacks:{frames:number[]}[]=[],stackIndex=new Map<number,number>(),samples:ProfileSample[]=[],losses:ProfileLoss[]=[];
 const frameFor=(frame:ProfileFrame):number|undefined=>{const key=JSON.stringify(frame);let index=frameIndex.get(key);if(index===undefined){if(frames.length>=MAX_FRAMES)return undefined;index=frames.length;frames.push(frame);frameIndex.set(key,index);}return index;};
 const stackFor=(nodeId:number):number|undefined=>{
  const known=stackIndex.get(nodeId);if(known!==undefined)return known;
  const ids:number[]=[];let current:number|undefined=nodeId,previous:ProfileFrame|undefined;
  for(let depth=0;current!==undefined&&depth<MAX_STACK_DEPTH*4&&ids.length<MAX_STACK_DEPTH;depth++,current=parent.get(current)){
   const frame=frameOf(calls.get(current),root);if(frame===null||frame===previous)continue;previous=frame;
   const index=frameFor(frame);if(index===undefined)return undefined;ids.push(index);
  }
  const index=stacks.length;stacks.push({frames:ids});stackIndex.set(nodeId,index);return index;
 };
 let at=0,missed=0n,dropped=0,deltaSum=0,deltaCount=0,first=true;
 for(let i=0;i<raw.samples.length;i++){
  const delta=raw.timeDeltas[i],id=raw.samples[i];
  if(typeof delta!=="number"||!Number.isFinite(delta)||delta<0||typeof id!=="number"){dropped++;continue;}
  at+=Math.round(delta);
  if(samples.length>=maxSamples){dropped++;continue;}
  const stack=stackFor(id);if(stack===undefined){dropped++;continue;}
  samples.push({at_us:String(at),stack,count:"1",thread:String(thread)});
  if(!first){deltaSum+=delta;deltaCount++;if(delta>2*intervalUs)missed+=BigInt(Math.floor(delta/intervalUs)-1);}
  first=false;
 }
 if(dropped>0)losses.push({reason:"truncated",count:String(dropped)});
 if(missed>0n)losses.push({reason:"sample_gap",count:missed.toString()});
 return {frames,stacks,samples,sampleCount:samples.length,truncated:dropped>0,losses,achievedUs:deltaCount>0?Math.round(deltaSum/deltaCount):null};
}

function classify(error:unknown,during:"start"|"stop"):Fault{
 if(error instanceof Fault)return error;
 const e=(typeof error==="object"&&error!==null?error:{}) as {code?:unknown;message?:unknown},code=typeof e.code==="string"?e.code:"",message=typeof e.message==="string"?e.message:"";
 if(code==="ERR_INSPECTOR_NOT_AVAILABLE"||code==="ERR_INSPECTOR_NOT_CONNECTED"&&during==="start")return new Fault("inspector_unavailable","unsupported");
 if(during==="stop"&&(/not started|No recording profiles/i.test(message)))return new Fault("profiler_state_lost","error");
 return new Fault("inspector_error","error");
}

export function createProfiler(deps:ProfilerDeps):{startProfile(options:ProfileOptions):Promise<ProfileHandle>}{
 const timeoutMs=deps.commandTimeoutMs>0?deps.commandTimeoutMs:DEFAULT_COMMAND_TIMEOUT_MS;
 const capabilityOf=(status:ProfileStatus,reason:ProfileReason,coverage:ProfileCoverage,domain:ClockDomain,wallNs:bigint):ProfileCapability=>({
  id:randomHex(16),runtime:safeToken(deps.runtime,128),version:safeToken(deps.version,128),build:safeToken(deps.build,256),os:safeToken(deps.os,64),arch:safeToken(deps.arch,64),
  signal:"profile_chunk",method:"runtime_engine_samples",status,reason,coverage,clock_domain:domain,expires_ns:(wallNs+CAPABILITY_TTL_NS).toString(),
 });
 const freshDomain=():ClockDomain=>({host:randomHex(16),boot:randomHex(16),runtime:randomHex(16)});
 const scopeOf=(debuggerListener:boolean)=>({isolate:(deps.isMainThread?"main":"worker") as "main"|"worker",thread_id:deps.threadId,runtime:{name:safeToken(deps.runtime,128),version:safeToken(deps.version,128)},debugger_listener_present:debuggerListener});
 const refusal=(status:ProfileStatus,reason:ProfileReason,requested:Resolved|undefined):ProfileHandle=>{
  const wall=deps.wallNs(),domain=freshDomain(),capability=capabilityOf(status,reason,NO_COVERAGE,domain,wall),stamp=wall.toString();
  const report:ProfileReport={version:1,method:"runtime_engine_samples",profile:true,units:"samples",time_delta_unit:"engine_microseconds",capability,
   interval:{requested_us:requested?.intervalUs??DEFAULT_INTERVAL_US,achieved_us:null},clock:{domain,uncertainty_ns:MAX_UNCERTAINTY,source:"v8_profiler_engine_clock",wall_start_ns:stamp,wall_end_ns:stamp},
   scope:scopeOf(false),coverage:NO_COVERAGE,requested:{duration_ms:requested?.durationMs??0,interval_us:requested?.intervalUs??DEFAULT_INTERVAL_US,max_samples:requested?.maxSamples??MAX_SAMPLES},
   stack_order:"leaf_first",frames:[],stacks:[],samples:[],sample_count:0,truncated:false,losses:[],non_profile:[],ack:{status:"not_available",reason:"no_profile_admission_path"},stopped_by:"not_started"};
  return {active:false,capability,stop:()=>Promise.resolve(report)};
 };
 /** One bounded inspector command. Settles exactly once; a callback arriving after the bound is ignored. */
 const command=(session:InspectorSession,method:string,params:object|undefined,during:"start"|"stop"):Promise<unknown>=>{
  const {promise,resolve,reject}=Promise.withResolvers<unknown>();let settled=false;
  const timer=deps.setTimer(()=>{if(!settled){settled=true;reject(new Fault("inspector_timeout","error"));}},timeoutMs,false);
  const done=(action:()=>void)=>{if(!settled){settled=true;timer.cancel();action();}};
  try{session.post(method,params,(error,result)=>done(()=>error?reject(classify(error,during)):resolve(result)));}
  catch(error){done(()=>reject(classify(error,during)));}
  return promise;
 };
 const quietly=async(action:()=>Promise<unknown>|void):Promise<void>=>{try{await action();}catch{/* best-effort cleanup never reaches the application */}};
 const delayOf=(h:EventLoopHistogram):NonProfileMeasurement=>{
  const has=Number.isFinite(h.count)&&h.count>0,pick=(v:number):number|null=>has&&Number.isFinite(v)?v:null;
  return {method:"event_loop_delay",profile:false,signal:"metric",unit:"nanoseconds",resolution_ms:EVENT_LOOP_RESOLUTION_MS,count:has?h.count:0,min:pick(h.min),max:pick(h.max),mean:pick(h.mean),p50:has?pick(h.percentile(50)):null,p99:has?pick(h.percentile(99)):null,exceeds:Number.isFinite(h.exceeds)?h.exceeds:0};
 };

 async function startProfile(options:ProfileOptions):Promise<ProfileHandle>{
  const resolved=resolveOptions(options);
  if(resolved===undefined)return refusal("denied","invalid_options",undefined);
  if(resolved.isolate!==undefined&&resolved.isolate!==(deps.isMainThread?"main":"worker"))return refusal("denied","isolate_scope_mismatch",resolved);
  if(deps.registry.owner!==undefined)return refusal("denied","profiler_owned",resolved);
  const token={};deps.registry.owner=token;
  let leaseTaken=true,session:InspectorSession|undefined,clientLease:{close():void}|undefined,histogram:EventLoopHistogram|undefined,timer:{cancel():void}|undefined,poisoned=false,closeRequested=false,stopFn:((by:StoppedBy)=>Promise<ProfileReport>)|undefined;
  const release=()=>{if(leaseTaken){leaseTaken=false;if(deps.registry.owner===token)deps.registry.owner=undefined;if(clientLease&&resolved.client){try{resolved.client.releaseHookLease(clientLease);}catch{/* closed client */}}clientLease=undefined;}};
  const teardown=async():Promise<void>=>{
   timer?.cancel();timer=undefined;
   if(histogram){const h=histogram;histogram=undefined;try{h.disable();}catch{/* best effort */}}
   const s=session;session=undefined;
   if(s){if(!poisoned)await quietly(()=>command(s,"Profiler.disable",undefined,"stop"));await quietly(()=>s.disconnect());}
   release();
  };
  if(resolved.client){
   const lease={close:()=>{if(stopFn)void stopFn("client_close");else closeRequested=true;}};
   try{resolved.client.ownHookLease(lease);clientLease=lease;}
   catch{release();return refusal("denied","client_unavailable",resolved);}
  }
  const wallStart=deps.wallNs(),domain=freshDomain();
  try{
   if(typeof deps.createSession!=="function")throw new Fault("inspector_unavailable","unsupported");
   try{session=deps.createSession();session.connect();}catch(error){session=undefined;throw classify(error,"start");}
   await command(session,"Profiler.enable",undefined,"start");
   await command(session,"Profiler.setSamplingInterval",{interval:resolved.intervalUs},"start");
   await command(session,"Profiler.start",undefined,"start");
  }catch(error){
   const fault=classify(error,"start");poisoned=fault.reason==="inspector_timeout";
   await teardown();
   return refusal(fault.status,fault.reason,resolved);
  }
  const debuggerListener=(()=>{try{return deps.inspectorUrl()!==undefined;}catch{return false;}})();
  if(resolved.eventLoopDelay&&deps.monitorEventLoopDelay){try{histogram=deps.monitorEventLoopDelay(EVENT_LOOP_RESOLUTION_MS);histogram.enable();}catch{histogram=undefined;}}
  const capability=capabilityOf("supported","ok",ENGINE_COVERAGE,domain,wallStart);
  const build=(final:ProfileCapability,mapped:Mapped,wallEnd:string,by:StoppedBy,delay:NonProfileMeasurement|undefined):ProfileReport=>({
   version:1,method:"runtime_engine_samples",profile:true,units:"samples",time_delta_unit:"engine_microseconds",capability:final,
   interval:{requested_us:resolved.intervalUs,achieved_us:mapped.achievedUs},
   clock:{domain,uncertainty_ns:MAX_UNCERTAINTY,source:"v8_profiler_engine_clock",wall_start_ns:wallStart.toString(),wall_end_ns:wallEnd},
   scope:scopeOf(debuggerListener),coverage:final.coverage,requested:{duration_ms:resolved.durationMs,interval_us:resolved.intervalUs,max_samples:resolved.maxSamples},
   stack_order:"leaf_first",frames:mapped.frames,stacks:mapped.stacks,samples:mapped.samples,sample_count:mapped.sampleCount,truncated:mapped.truncated,losses:mapped.losses,
   non_profile:delay?[delay]:[],ack:{status:"not_available",reason:"no_profile_admission_path"},stopped_by:by,
  });
  let stopping:Promise<ProfileReport>|undefined;
  const stop=(by:StoppedBy):Promise<ProfileReport>=>{
   if(stopping)return stopping;
   timer?.cancel();timer=undefined;
   stopping=(async():Promise<ProfileReport>=>{
    const eld=histogram;histogram=undefined;let delay:NonProfileMeasurement|undefined;
    if(eld){try{eld.disable();delay=delayOf(eld);}catch{delay=undefined;}}
    let fault:Fault|undefined,raw:RawProfile|undefined,mapped:Mapped|undefined;const s=session;
    try{
     if(!s)throw new Fault("inspector_error","error");
     raw=rawProfile(await command(s,"Profiler.stop",undefined,"stop"));if(!raw)throw new Fault("inspector_error","error");
     // Mapping runs on engine-supplied data inside the guard: a malformed profile is an error capability, never a rejected stop().
     mapped=mapProfile(raw,resolved.root,resolved.intervalUs,resolved.maxSamples,deps.threadId);
    }catch(error){fault=classify(error,"stop");poisoned=fault.reason==="inspector_timeout";}
    await teardown();
    const wallEnd=deps.wallNs().toString();
    if(fault||!mapped){
     const failure=fault??new Fault("inspector_error","error"),final=capabilityOf(failure.status,failure.reason,NO_COVERAGE,domain,wallStart);
     const losses:ProfileLoss[]=failure.reason==="profiler_state_lost"?[{reason:"foreign_state",count:"1"}]:failure.reason==="inspector_timeout"?[{reason:"timeout_cleanup",count:"1"}]:[];
     return build(final,{frames:[],stacks:[],samples:[],sampleCount:0,truncated:false,losses,achievedUs:null},wallEnd,failure.reason==="inspector_timeout"?"timeout_cleanup":by,delay);
    }
    return build(capability,mapped,wallEnd,by,delay);
   })();
   return stopping;
  };
  timer=deps.setTimer(()=>{void stop("duration");},resolved.durationMs,true);
  stopFn=stop;if(closeRequested)void stop("client_close");
  return {get active(){return stopping===undefined;},capability,stop:()=>stop("caller")};
 }
 return {startProfile};
}

const sharedRegistry:{owner:unknown}=(()=>{
 const key=Symbol.for("soundpost.profile.owner.runtime_engine_samples"),holder=globalThis as unknown as Record<symbol,{owner:unknown}|undefined>;
 return holder[key]??(holder[key]={owner:undefined});
})();
/** C09. Profiling is off unless this is called. Never rejects for expected failures: inspect `handle.capability` / `report.capability`. */
export function startProfile(options:ProfileOptions):Promise<ProfileHandle>{
 return createProfiler({
  runtime:"node",version:process.version,build:process.versions.v8,os:process.platform,arch:process.arch,isMainThread,threadId,
  createSession:()=>new Session(),inspectorUrl,wallNs:()=>BigInt(Date.now())*1_000_000n,
  setTimer:(callback,ms,unref)=>{const handle=setTimeout(callback,ms);if(unref)handle.unref();return {cancel:()=>clearTimeout(handle)};},
  commandTimeoutMs:DEFAULT_COMMAND_TIMEOUT_MS,registry:sharedRegistry,monitorEventLoopDelay:resolution=>monitorEventLoopDelay({resolution}),
 }).startProfile(options);
}
