// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {canonical,canonicalId,decimal,unixNano,utf8Compare,utf8Size} from './policy.ts';
export function object(value:unknown):Record<string,unknown>{if(!value||typeof value!=='object'||Array.isArray(value))throw Error('native object required');return value as Record<string,unknown>;}
export function text(value:unknown):string{if(typeof value!=='string')throw Error('native string required');return value;}
export function array(value:unknown):unknown[]{if(!Array.isArray(value))throw Error('native array required');return value;}
type FieldSpec={readonly names:readonly string[];readonly extras:readonly string[];readonly allowed:ReadonlySet<string>};
const specs=new Map<string,Map<string,FieldSpec>>();
/** The closed field list parsed once per literal (required, optional) pair; the call sites pass constants. */
function spec(required:string,optional:string):FieldSpec{
 let byOptional=specs.get(required);if(!byOptional){byOptional=new Map();specs.set(required,byOptional);}
 let found=byOptional.get(optional);
 if(!found){const names=required.split(' ').filter(Boolean),extras=optional.split(' ').filter(Boolean);found={names,extras,allowed:new Set([...names,...extras])};byOptional.set(optional,found);}
 return found;
}
function fields(value:unknown,required:string,optional=''):Record<string,unknown>{const o=object(value),{names,extras,allowed}=spec(required,optional);if(names.some(k=>!Object.hasOwn(o,k))||Object.keys(o).some(k=>!allowed.has(k)))throw Error('closed native fields required');for(const k of extras){const v=o[k];if(v===null||Array.isArray(v)&&v.length===0)delete o[k];}return o;}
export interface NativeRecord {id:string;kind:string;observed_at_ns:string;policy_revision:string;payload:Record<string,unknown>}
const payloadFields:Readonly<Record<string,readonly [string,string]>>={
 metric:['name labels sample_kind unit type','value histogram start_timestamp_ns exemplar_trace exemplar_span'],
 log:['severity template_id template_revision fields line stream_labels structured_metadata source_class','timestamp_ns trace_id span_id run_id'],
 error:['occurrence_id exception_class mechanism frames code build_id handled fatal','exception_graph template_id release_id trace_id span_id replay_id profile_id run_id'],
 span:['trace_id span_id parent_id span_kind operation start end status dependency_alias links sample_probability sample_decision','job_id replay_id profile_id'],
 job_attempt:['job_id run_id attempt_id schedule_occurrence ordinal producer_epoch sequence state observed_ns terminal_ns','cause_trace cause_error'],
 replay_chunk:['replay_id session_id recorder_version sequence previous_hash checkpoint_sequence checkpoint_hash clock nodes events loss gap capture_policy_revision',''],
 profile_chunk:['profile_id process_id capability_id method units start_ns end_ns clock frames stacks samples intervals loss truncated','native_domain native_capabilities native_loss policy_revision sequence complete'],
 capability:['runtime version build os arch signal method status reason coverage clock_domain expires_ns',''],
 loss:['source producer producer_epoch start_ns end_ns signal reason count last_ack queue_bytes queue_records',''],
 condition:['condition_id epoch sequence event_ns status severity labels links','']
};
function integer(value:unknown,min=0,max=4294967295):number{if(typeof value!=='number'||!Number.isSafeInteger(value)||value<min||value>max)throw Error('invalid native integer');return value;}
function bits(value:unknown,length=16):void{if(typeof value!=='string'||value.length!==length||/[^0-9a-f]/.test(value))throw Error('invalid native bits');}
function domain(value:unknown):void{const d=fields(value,'host boot runtime');for(const v of Object.values(d))canonicalId(v);}
function clock(value:unknown):void{const c=fields(value,'wall_ns mono_ns domain uncertainty_ns');unixNano(c.wall_ns);decimal(c.mono_ns);decimal(c.uncertainty_ns);domain(c.domain);}
function labels(value:unknown):void{let previous:string|undefined;for(const item of array(value)){const l=fields(item,'name value'),name=text(l.name);if(!utf8Size(name)||previous!==undefined&&utf8Compare(previous,name)>=0)throw Error('invalid native labels');utf8Size(text(l.value));previous=name;}}
const nativeFrameReasons:Readonly<Record<string,true>>={frame_unresolved:true,missing_frame_pointer_or_callchain:true,callchain_truncated:true,build_not_approved:true,deleted_executable:true,generation_changed:true,jit_or_anonymous_map_unavailable:true,jit_map_expired:true,artifact_unavailable:true,artifact_denied:true,invalid_elf_artifact:true};
const nativeProfileReasons:Readonly<Record<string,true>>={platform_unsupported:true,permission_denied:true,tracefs_unavailable:true,event_unavailable:true,coverage_unmeasured:true,acquisition_pending:true,callchain_truncated:true,records_lost:true,generation_changed:true,clock_uncertain:true,frame_unresolved:true,missing_switch_callchain:true,missing_callchain:true,throttled:true,unthrottled:true,samples_lost:true};
function nativeTask(value:unknown,boot:string):number{
 const task=fields(value,'boot_id pid_namespace tgid tid process_start_ns generation');if(task.boot_id!==boot)throw Error('native task boot mismatch');integer(task.tgid,1);const tid=integer(task.tid,1);for(const k of ['pid_namespace','process_start_ns','generation'])if(decimal(task[k])==='0')throw Error('invalid native task');return tid;
}
function nativeProfile(p:Record<string,unknown>,revision:string):void{
 for(const key of ['policy_revision','sequence'])if(p[key]!==undefined&&decimal(p[key])==='0')delete p[key];if(p.complete!==undefined&&typeof p.complete!=='boolean')throw Error('invalid native completeness');if(p.complete===false)delete p.complete;
 for(const item of array(p.intervals)){const interval=object(item);for(const k of ['unit','reason'])if(interval[k]==='')delete interval[k];if(interval.correction===false)delete interval.correction;if(interval.correction!==undefined)throw Error('native corrections cannot persist');}
 if(p.native_domain===undefined){
  if(p.policy_revision!==undefined||p.sequence!==undefined||p.complete!==undefined||p.native_capabilities!==undefined||p.native_loss!==undefined||array(p.samples).some(s=>object(s).native!==undefined)||array(p.intervals).some(i=>{const v=object(i);return v.native_task!==undefined||v.unit!==undefined||v.reason!==undefined;}))throw Error('native metadata requires native domain');return;
 }
 const d=fields(p.native_domain,'host_id boot_id'),boot=text(d.boot_id);for(const v of Object.values(d)){const value=text(v);if(!value.length||value.length>128||/[^a-zA-Z0-9-]/.test(value))throw Error('invalid native domain');}
 if(decimal(p.policy_revision)==='0'||p.policy_revision!==revision||decimal(p.sequence)==='0'||!['native_cpu','native_offcpu'].includes(text(p.method))||p.units!==(p.method==='native_cpu'?'samples':'nanoseconds')||p.method==='native_offcpu'&&array(p.samples).length!==0)throw Error('invalid native profile');
 const capabilities=array(p.native_capabilities).map(canonicalId);if(capabilities.length!==3||new Set(capabilities).size!==3||!capabilities.includes(text(p.capability_id)))throw Error('invalid native capability references');
 let genuineLoss=0n;const losses=p.native_loss===undefined?[]:array(p.native_loss);if(losses.length>256)throw Error('native loss bounds exceeded');
 for(const value of losses){
  const loss=fields(value,'at_ns cpu count reason','throttle_event_id throttle_stream_id');decimal(loss.at_ns);integer(loss.cpu);const count=BigInt(decimal(loss.count));for(const k of ['throttle_event_id','throttle_stream_id'])if(loss[k]!==undefined&&decimal(loss[k])==='0')delete loss[k];
  if(loss.reason==='records_lost'||loss.reason==='samples_lost'){if(count===0n||loss.throttle_event_id!==undefined||loss.throttle_stream_id!==undefined)throw Error('invalid native loss');}
  else if(loss.reason==='throttled'||loss.reason==='unthrottled'){if(count!==0n||decimal(loss.throttle_event_id)==='0'||decimal(loss.throttle_stream_id)==='0')throw Error('invalid native throttle transition');}
  else throw Error('invalid native loss reason');genuineLoss+=count;if(genuineLoss>18446744073709551615n)throw Error('native loss overflow');
 }
 for(const value of array(p.frames)){
  const f=object(value),module=text(f.module_id),reason=text(f.reason);
  if(module===''){if(f.offset!=='0'||f.function!==''||f.artifact_id!==''||!Object.hasOwn(nativeFrameReasons,reason))throw Error('unsafe unresolved native frame');}
  else{
   bits(module,64);const symbol=text(f.function);if(symbol!==''&&(symbol.length>256||/[^a-zA-Z0-9_.$@:]/.test(symbol)))throw Error('invalid native symbol');
   const artifact=text(f.artifact_id);if(artifact!=='')canonicalId(artifact);
   if(reason!==''&&!Object.hasOwn(nativeFrameReasons,reason))throw Error('invalid native frame reason');
  }
 }
 for(const value of array(p.samples)){
  const sample=object(value),n=fields(sample.native,'task method unit requested_hz period','truncation coverage throttle_reason throttle_event_id throttle_stream_id'),tid=nativeTask(n.task,boot);
  for(const key of ['truncation','coverage','throttle_reason'])if(n[key]==='')delete n[key];for(const key of ['throttle_event_id','throttle_stream_id'])if(n[key]!==undefined&&decimal(n[key])==='0')delete n[key];
  if(sample.count!=='1'||sample.thread!==String(tid)||n.requested_hz!==99||decimal(n.period)==='0'||!['software_cpu_clock','hardware_cycles'].includes(text(n.method))||n.unit!==(n.method==='software_cpu_clock'?'cpu_clock_nanoseconds':'hardware_cycles'))throw Error('invalid native CPU sample');
  if(n.truncation!==undefined&&!['callchain_truncated','frame_unresolved','missing_callchain'].includes(text(n.truncation))||n.coverage!==undefined&&!Object.hasOwn(nativeFrameReasons,text(n.coverage)))throw Error('invalid native sample coverage');
  if(n.throttle_reason===undefined){if(n.throttle_event_id!==undefined||n.throttle_stream_id!==undefined)throw Error('invalid native throttle identity');}else if(!['throttled','unthrottled'].includes(text(n.throttle_reason))||decimal(n.throttle_event_id)==='0'||decimal(n.throttle_stream_id)==='0')throw Error('invalid native throttle');
 }
 for(const value of array(p.intervals)){const i=object(value),tid=nativeTask(i.native_task,boot);if(i.thread!==String(tid)||i.unit!=='nanoseconds'||i.reason!==undefined&&!Object.hasOwn(nativeProfileReasons,text(i.reason))||i.kind==='unknown_offcpu'&&i.reason===undefined||i.censored===true&&i.reason===undefined)throw Error('invalid native interval');}
}
const structureStrings:Readonly<Record<string,readonly string[]>>={metric:'name sample_kind unit type'.split(' '),log:'severity template_id line source_class'.split(' '),span:'span_kind operation status dependency_alias sample_decision'.split(' '),error:'exception_class mechanism'.split(' '),job_attempt:'schedule_occurrence state'.split(' '),replay_chunk:['recorder_version'],profile_chunk:'method units'.split(' '),capability:'runtime version build os arch signal method status reason'.split(' '),loss:'signal reason'.split(' '),condition:'status severity'.split(' ')};
const structureIds:Readonly<Record<string,readonly string[]>>={metric:['exemplar_trace'],log:'trace_id run_id'.split(' '),span:'trace_id job_id replay_id profile_id'.split(' '),error:'occurrence_id build_id release_id trace_id replay_id profile_id run_id'.split(' '),job_attempt:'job_id run_id attempt_id producer_epoch cause_trace cause_error'.split(' '),replay_chunk:'replay_id session_id'.split(' '),profile_chunk:'profile_id process_id capability_id'.split(' '),loss:'source producer producer_epoch'.split(' '),condition:'condition_id epoch'.split(' ')};
function structures(kind:string,p:Record<string,unknown>,revision:string):void{
 for(const key of structureStrings[kind]??[])text(p[key]);if(kind==='error'){if(p.code!==null)text(p.code);if(p.template_id!==undefined)text(p.template_id);}if(kind==='log'&&p.timestamp_ns!==undefined)unixNano(p.timestamp_ns);
 for(const key of structureIds[kind]??[])if(p[key]!==undefined)canonicalId(p[key]);
 for(const key of ['span_id','exemplar_span'])if(p[key]!==undefined){bits(p[key]);if(text(p[key])==='0'.repeat(16))throw Error('invalid span ID');}
 if(kind==='metric'){
  labels(p.labels);if(p.value!==undefined)bits(p.value);
  if(p.start_timestamp_ns!==undefined)unixNano(p.start_timestamp_ns);
  if(p.histogram!==undefined){const h=fields(p.histogram,'','integer float');
   for(const tagged of ['integer','float'])if(h[tagged]!==undefined){
    const v=fields(h[tagged],'flavor schema zero_threshold sum count zero_count positive_spans negative_spans positive_buckets negative_buckets reset_hint',tagged==='integer'?'positive_counts negative_counts custom_bounds':'custom_bounds');
    const schema=integer(v.schema,-2147483648,2147483647);if(schema!==-53&&(schema< -4||schema>8))throw Error('invalid histogram schema');bits(v.zero_threshold);bits(v.sum);
    if(tagged==='float'){bits(v.count);bits(v.zero_count);}
    for(const key of ['positive_spans','negative_spans'])for(const item of array(v[key])){const span=fields(item,'offset length');integer(span.offset,-2147483648,2147483647);integer(span.length);}
    for(const key of ['positive_buckets','negative_buckets'])if(tagged==='float')array(v[key]).forEach(v=>bits(v));
    if(v.custom_bounds!==undefined)array(v.custom_bounds).forEach(v=>bits(v));
   }
  }
 }
 if(kind==='log')labels(p.stream_labels);
 if(kind==='span'){
  bits(p.span_id);if(p.parent_id!==null)bits(p.parent_id);clock(p.start);if(p.end!==null)clock(p.end);bits(p.sample_probability);
  for(const item of array(p.links)){const link=fields(item,'trace_id span_id');canonicalId(link.trace_id);bits(link.span_id);}
 }
 if(kind==='job_attempt'){decimal(p.ordinal);decimal(p.sequence);unixNano(p.observed_ns);if(p.terminal_ns!==null)unixNano(p.terminal_ns);}
 if(kind==='replay_chunk'){
  clock(p.clock);for(const key of ['sequence','checkpoint_sequence','loss','capture_policy_revision'])decimal(p[key]);bits(p.previous_hash,64);bits(p.checkpoint_hash,64);if(typeof p.gap!=='boolean')throw Error('invalid replay gap');
  if(array(p.nodes).length>4096||array(p.events).length>4096)throw Error('invalid replay bounds');
  for(const item of array(p.nodes)){const n=fields(item,'id parent tag class text');decimal(n.id);decimal(n.parent);if(!['div','span','p','button','input','section','canvas','masked'].includes(text(n.tag))||!['','masked'].includes(text(n.class))||!['','[masked]'].includes(text(n.text)))throw Error('unmasked replay node');}
  for(const item of array(p.events)){const e=fields(item,'at_ns kind node x y');decimal(e.at_ns);decimal(e.node);integer(e.x,-2147483648,2147483647);integer(e.y,-2147483648,2147483647);if(!['pointer','scroll','resize','mutation','checkpoint','gap'].includes(text(e.kind)))throw Error('invalid replay event');}
 }
 if(kind==='profile_chunk'){
  clock(p.clock);unixNano(p.start_ns);unixNano(p.end_ns);decimal(p.loss);if(typeof p.truncated!=='boolean')throw Error('invalid profile');if(array(p.frames).length>4096||array(p.stacks).length>4096||array(p.samples).length>8192||array(p.intervals).length>8192)throw Error('invalid profile bounds');
  for(const item of array(p.frames)){const f=fields(item,'module_id function artifact_id offset reason');for(const key of ['module_id','function','artifact_id','reason'])text(f[key]);decimal(f.offset);}
  for(const item of array(p.stacks)){const s=fields(item,'frames');if(array(s.frames).length>128)throw Error('invalid profile stack');for(const frame of array(s.frames))integer(frame,0,array(p.frames).length-1);}
  for(const item of array(p.samples)){const s=fields(item,'at_ns stack count thread','native');decimal(s.at_ns);decimal(s.count);decimal(s.thread);integer(s.stack,0,array(p.stacks).length-1);}
  for(const item of array(p.intervals)){const i=fields(item,'start_ns end_ns stack kind thread censored','native_task unit reason correction');decimal(i.start_ns);decimal(i.end_ns);decimal(i.thread);integer(i.stack,0,array(p.stacks).length-1);if(typeof i.censored!=='boolean'||!['blocked','runnable','unknown_offcpu'].includes(text(i.kind)))throw Error('invalid profile interval');}
  nativeProfile(p,revision);
 }
 if(kind==='capability'){domain(p.clock_domain);unixNano(p.expires_ns);const c=fields(p.coverage,'frames threads workers tasks');for(const value of Object.values(c))if(!['complete','partial','none','unknown'].includes(text(value)))throw Error('invalid coverage');}
 if(kind==='loss'){for(const key of ['count','queue_bytes','queue_records'])decimal(p[key]);unixNano(p.start_ns);unixNano(p.end_ns);if(p.last_ack!==null){const c=fields(p.last_ack,'group index');canonicalId(c.group);decimal(c.index);}}
 if(kind==='condition'){decimal(p.sequence);unixNano(p.event_ns);labels(p.labels);array(p.links).forEach(canonicalId);}
}
export function parseSafeRecord(serialized:string):NativeRecord{
 const r=fields(JSON.parse(serialized),'id kind observed_at_ns policy_revision payload');canonicalId(r.id);unixNano(r.observed_at_ns);decimal(r.policy_revision);const kind=text(r.kind),schema=payloadFields[kind];if(!schema)throw Error('invalid signal');const p=fields(r.payload,schema[0],schema[1]);
 structures(kind,p,decimal(r.policy_revision));
 // Closed current capture graph: no raw object, message, stack or unknown field can enter native bytes.
 if(kind==='error'){
  canonicalId(p.occurrence_id);canonicalId(p.build_id);if(p.occurrence_id!==r.id||typeof p.handled!=='boolean'||typeof p.fatal!=='boolean'||!['manual','uncaught_exception','unhandled_rejection','thread_exception','asyncio_exception'].includes(text(p.mechanism)))throw Error('invalid error');
  const frame=(value:unknown):void=>{const f=fields(value,'module_id function artifact_id line column in_app async');for(const k of ['module_id','function','artifact_id'])text(f[k]);if(!Number.isInteger(f.line)||typeof f.line!=='number'||f.line<1||f.line>4294967295||f.column!==null&&(!Number.isInteger(f.column)||typeof f.column!=='number'||f.column<0)||typeof f.in_app!=='boolean'||typeof f.async!=='boolean')throw Error('invalid frame');};
  array(p.frames).forEach(frame);
  if(p.exception_graph!==undefined){
   const g=fields(p.exception_graph,'nodes edges reasons'),nodes=array(g.nodes),edges=array(g.edges),reasons=array(g.reasons);if(!nodes.length||nodes.length>16||edges.length>272||reasons.length>16)throw Error('invalid graph');let total=0;
   for(const [index,n] of nodes.entries()){const node=fields(n,'id exception_class frames context_suppressed');if(node.id!==index||typeof node.context_suppressed!=='boolean')throw Error('invalid graph');text(node.exception_class);total+=array(node.frames).length;array(node.frames).forEach(frame);}
   const root=object(nodes[0]);if(total>128||root.exception_class!==p.exception_class||canonical(root.frames)!==canonical(p.frames))throw Error('invalid graph root');
   for(const e of edges){const edge=fields(e,'from to kind','ordinal');integer(edge.from,0,nodes.length-1);integer(edge.to,0,nodes.length-1);if(!['cause','context','group'].includes(text(edge.kind)))throw Error('invalid edge');if(edge.kind==='group')integer(edge.ordinal,0,15);else if(edge.ordinal!==undefined)throw Error('invalid edge ordinal');}
   for(const reason of reasons)if(!['cycle','node_limit','frame_limit','group_limit','unknown_throw','project_root_unconfigured','frame_not_project_safe','foreign_or_custom_error_class','safe_original_stack_unavailable','native_brand_unavailable','cause_accessor','group_accessor','safe_group_boundary_unavailable','unsafe_group_container'].includes(text(reason)))throw Error('invalid graph reason');
  }
 }
 if(kind==='log'){decimal(p.template_revision);for(const k of ['template_id','line','severity','source_class'])text(p[k]);for(const map of [object(p.fields),object(p.structured_metadata)])for(const v of Object.values(map))if(!(v===null||typeof v==='string'||typeof v==='boolean'||typeof v==='number'&&Number.isSafeInteger(v)))throw Error('invalid log scalar');}
 if(kind==='metric'&&p.histogram!==undefined){const h=fields(p.histogram,'','integer float');if((h.integer===undefined)===(h.float===undefined))throw Error('invalid histogram');if(h.integer!==undefined){const v=fields(h.integer,'flavor schema zero_threshold sum count zero_count positive_spans negative_spans positive_buckets negative_buckets reset_hint','positive_counts negative_counts custom_bounds');decimal(v.count);decimal(v.zero_count);for(const key of ['positive_counts','negative_counts'])if(v[key]!==undefined)array(v[key]).forEach(decimal);for(const key of ['positive_buckets','negative_buckets'])array(v[key]).forEach(unixNano);}}
 return {id:text(r.id),kind,observed_at_ns:text(r.observed_at_ns),policy_revision:text(r.policy_revision),payload:p};
}
