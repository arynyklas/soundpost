// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Demo data set for the console screenshots and the owner's review (h.sh demo). NOT a test of the product and not part of `playwright test`;
// like provision.spec.ts it runs through playwright.provision.config.ts against a fresh real server. Nothing is injected: the organization, projects,
// users and their display names, grants, source policies, releases, deploy markers and incident/issue actions go through the real admin and action
// routes; errors, spans, metrics, job attempts, replay chunks and profile chunks go through POST /ingest/v1/batches with real source credentials;
// the source map is a real esbuild bundle uploaded through the real artifact route; incidents and issues are made by the server's own producers.
// In the spirit of the mockup (ui-mockup-v3/mock.js): org "Example Co", projects storefront-web / api / jobs, seven incidents in different states.
// Environment: the h.sh variables plus DEMO_OUT (file that receives demo.json, mode 0600).
import {test,expect,request as pwRequest,type APIRequestContext,type Page} from '@playwright/test';
import {createHash,randomBytes} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {adminCommand,at,bitsOf,createOrg,createProject,field,id,ingestBatch,ingestError,ingestJobAttempt,ingestMetric,login,onboardJobSource,onboardSdkJobSource,origin,owner,postJson,saveJobDefinition,SECOND,spanId,csrf,type Source} from '../e2e/support/real';
import {buildRealBundle,ingestStoredFailure,registerRelease} from '../e2e/support/evidence';
import {domain,type Domain} from '../e2e/support/trace';
import {NATIVE_PROFILE,onboardReplaySource,seedProfiles,seedReplays} from '../e2e/support/replay';

const MS=1_000_000n;
const NOW=BigInt(Date.now())*MS;
const minAgo=(m:number):bigint=>NOW-BigInt(Math.round(m*60))*SECOND;
const sleep=(ms:number):Promise<void>=>{const {promise,resolve}=Promise.withResolvers<void>();setTimeout(resolve,ms);return promise;};
const ALL=['telemetry.read','incidents.write','issues.write','artifacts.read','artifacts.write','replay.read','profiles.read','policy.write'];
const MEMBER=['telemetry.read','incidents.write','issues.write'];

interface Person{id:string;email:string;password:string;name:string}
async function person(owners:Page,org:string,name:string,projects:string[],permissions:string[],orgAdmin:boolean):Promise<Person>{
 const p:Person={id:id(),email:`${name.toLowerCase().replace(/[^a-z]+/g,'.')}@example.test`,password:`demo ${name} ${randomBytes(6).toString('hex')}`,name};
 await adminCommand(owners,org,'create_user',{id:p.id,email:p.email,password:p.password});
 await adminCommand(owners,org,'membership',{user_id:p.id,enabled:true});
 for(const project of projects)await adminCommand(owners,org,'grant',{user_id:p.id,project_id:project,enabled:true,permissions});
 if(orgAdmin)await adminCommand(owners,org,'org_admin',{user_id:p.id,enabled:true});
 const named=await postJson(owners,'/api/v1/directory/names',{org,command_id:id(),user:p.id,display_name:name});
 if(named.status!==200)throw Error(`display name of ${name}: HTTP ${named.status} ${named.text}`);
 return p;
}

const SERVICE_OPS=['op.checkout','op.payment','op.inventory','op.search','op.render','op.request'];
const DEPENDENCIES=['postgres','cache','upstream'];
/** A structured source of a project for errors, spans and metrics; its policy lists the demo builds and both environments. */
async function onboard(owners:Page,org:string,project:string,readers:string[],builds:string[],environments:string[],service:string):Promise<Source>{
 const source=id();
 await adminCommand(owners,org,'source_policy',{id:source,config:{project_id:project,origins:[],restricted:false,readers,enabled:true}});
 const kinds=['metric','error','span'];
 const policy={revision:'1',enabled:true,class:'structured',kinds,templates:[],resources:{service_id:[service],environment_id:environments,build_id:builds,instance_pseudonym:['opaque-instance']},labels:{job:['api'],kind:['float','hist']},operations:SERVICE_OPS,dependencies:DEPENDENCIES,codes:['E_CHECKOUT'],retention_days:{metric:30,error:30,span:30},max_bytes:'1048576',max_series:'1000',replay:false,expires_ns:'0'};
 const r=await postJson(owners,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:String(NOW+24n*3600n*SECOND),policy,reason:'Demo data set'});
 const credential=field(r.json,'credential'),revision=field(field(r.json,'descriptor'),'policy_revision');
 if(r.status!==200||typeof credential!=='string')throw Error(`source onboarding: HTTP ${r.status} ${r.text}`);
 return {id:source,credential,producer:id(),org,project,service,environment:environments[0] as string,build:builds[0] as string,instance:'opaque-instance',policyRevision:typeof revision==='string'?revision:'1',kinds:['metric','error','span']};
}

interface SpanIn{span:string;parent?:string;kind:'server'|'client'|'internal';operation:string;dependency?:string;startMs:number;endMs:number;status?:'ok'|'error'}
/** One trace as one real batch; startMs/endMs are offsets from `base` (wall ns). */
async function ingestTrace(api:APIRequestContext,s:Source,trace:string,base:bigint,d:Domain,specs:SpanIn[]):Promise<void>{
 const stamp=(ms:number)=>({wall_ns:(base+BigInt(ms)*MS).toString(),mono_ns:(d.base+BigInt(ms)*MS).toString(),domain:{host:d.host,boot:d.boot,runtime:d.runtime},uncertainty_ns:'0'});
 const records=specs.map((sp)=>({id:id(),kind:'span' as const,observed_at_ns:(base+BigInt(sp.endMs)*MS).toString(),resource:{service_id:s.service,environment_id:s.environment,build_id:s.build,instance_pseudonym:s.instance,labels:[]},
  payload:{trace_id:trace,span_id:sp.span,parent_id:sp.parent??null,span_kind:sp.kind,operation:sp.operation,start:stamp(sp.startMs),end:stamp(sp.endMs),status:sp.status??'ok',dependency_alias:sp.dependency??'',links:[],sample_probability:bitsOf(1),sample_decision:'keep'}}));
 await ingestBatch(api,s,records);
}
async function pool<T>(items:T[],width:number,run:(item:T)=>Promise<void>):Promise<void>{
 let next=0;
 await Promise.all(Array.from({length:width},async()=>{for(;;){const i=next++;if(i>=items.length)return;await run(items[i] as T);}}));
}

test('provision the demo data set',async({page,browser})=>{
 test.setTimeout(1_500_000);
 const out=process.env.DEMO_OUT;
 if(!out)throw Error('DEMO_OUT is required');
 const o=owner();
 await login(page,o.email,o.password);
 const org=await createOrg(page,'Example Co');
 const storefront=await createProject(page,org,'storefront-web');
 const apiProject=await createProject(page,org,'api');
 const jobsProject=await createProject(page,org,'jobs');
 const projects=[storefront,apiProject,jobsProject];

 // People: the signed-in administrator and three members, each with a display name.
 const aigerim=await person(page,org,'Aigerim Sadykova',projects,ALL,true);
 const dana=await person(page,org,'Dana Omarova',projects,MEMBER,false);
 const timur=await person(page,org,'Timur Bekov',projects,MEMBER,false);
 await person(page,org,'Madi Nurlanov',[storefront,apiProject],['telemetry.read'],false);

 // The administrator's own session reads telemetry and takes the incident and issue actions.
 const ctx=await browser.newContext({baseURL:origin()});
 const me=await ctx.newPage();
 await login(me,aigerim.email,aigerim.password);
 // The build uploads source maps as a member with artifacts.write who is the source's reader (the grant the artifact route is specified for).
 const ci=await person(page,org,'Release Pipeline',[storefront],['artifacts.write','artifacts.read','raw.read'],false);
 const uctx=await browser.newContext({baseURL:origin()});
 const uploader=await uctx.newPage();
 await login(uploader,ci.email,ci.password);
 const ingest=await pwRequest.newContext();

 // Sources, one service and two environments per project.
 const build=id(),environments=[id(),id()];
 const storefrontService=id(),apiService=id();
const storefrontSource=await onboard(page,org,storefront,[ci.id],[build],environments,storefrontService);
 const apiSource=await onboard(page,org,apiProject,[aigerim.id],[build],environments,apiService);
 const jobsErrorSource=await onboardSdkJobSource(page,org,jobsProject);

 // The real source map, admitted through the real upload route as the administrator (artifacts.write).
 const bundle=await buildRealBundle();
 const sha=(b:Buffer):string=>createHash('sha256').update(b).digest('hex');
 const debugId=`debug-${id().slice(0,12)}`;
 const manifest=`{"version":1,"org":"${org}","project":"${storefront}","source":"${storefrontSource.id}","build":"${build}","debug_id":"${debugId}","generated_sha256":"${sha(bundle.generated)}","map_sha256":"${sha(bundle.map)}","path":"dist/app.js","source_content":true,"size":"${bundle.map.length}","retain_until_ns":"4102444800000000000"}`;
 const upload=await uploader.request.post(`${origin()}/api/v1/artifacts`,{headers:{'X-CSRF-Token':await csrf(uploader),Origin:origin()},multipart:{manifest:{name:'manifest',mimeType:'application/json',buffer:Buffer.from(manifest)},file:{name:'app.js.map',mimeType:'application/json',buffer:bundle.map}}});
 const uploaded=await upload.text();
 const artifact=field(JSON.parse(uploaded) as unknown,'id');
 if(upload.status()!==200||typeof artifact!=='string')throw Error(`artifact upload: HTTP ${upload.status()} ${uploaded}`);

 // Releases with ancestry, labels and deploy times per environment.
 const rel={a:id(),b:id(),c:id()};
 const release=(rid:string,label:string,parents:string[],builtMinutesAgo:number)=>({id:rid,org,project:storefront,build_id:build,parents,build_time_ns:String(minAgo(builtMinutesAgo)),debug_artifacts:[{artifact_id:artifact,debug_id:debugId,sha256:sha(bundle.map)}],display_label:label,revision:'0'});
 await registerRelease(page,org,storefront,release(rel.a,'v2.40.1',[],600));
 await registerRelease(page,org,storefront,release(rel.b,'v2.40.2',[rel.a],300));
 await registerRelease(page,org,storefront,release(rel.c,'v2.41.0',[rel.b],70));
 const deploy=async(release:string,environment:string,minutes:number):Promise<void>=>{
  const r=await postJson(page,'/api/v1/releases/deploys',{op:'record',org,project:storefront,release,environment,deployed_at:String(minAgo(minutes)),command_id:id()});
  if(r.status!==200)throw Error(`deploy marker: HTTP ${r.status} ${r.text}`);
 };
 await deploy(rel.a,environments[0] as string,590);
 await deploy(rel.b,environments[0] as string,280);
 await deploy(rel.c,environments[1] as string,55);
 await deploy(rel.c,environments[0] as string,22);

 // Reads as the administrator.
 const listIssues=async(project:string):Promise<{issue_id:string;title:string|null;revision:string}[]>=>{
  const r=await postJson(me,'/api/v1/issues/list',{org,projects:[project],limit:100});
  const items=field(r.json,'items');
  return Array.isArray(items)?items as {issue_id:string;title:string|null;revision:string}[]:[];
 };
 const issueOf=async(project:string,cls:string,occurrences=1):Promise<string>=>{
  const deadline=Date.now()+90_000;
  for(;;){
   const hit=(await listIssues(project)).find((i)=>i.title===cls);
   if(hit){
    const e=await postJson(me,'/api/v1/evidence/issue',{org,project,issue:hit.issue_id});
    const occ=field(e.json,'occurrences');
    if(e.status===200&&Array.isArray(occ)&&occ.length>=occurrences)return hit.issue_id;
   }
   if(Date.now()>deadline)throw Error(`the issue producer never grouped ${occurrences} occurrence(s) of ${cls}`);
   await sleep(500);
  }
 };
 const queue=async():Promise<{project_id:string;incident_id:string}[]>=>{
  const r=await postJson(me,'/api/v1/queue',{org,projects,limit:100});
  const entries=field(r.json,'entries');
  return Array.isArray(entries)?entries as {project_id:string;incident_id:string}[]:[];
 };
 const known:{project:string;id:string}[]=[];
 const nextIncident=async():Promise<{project:string;id:string}> =>{
  const deadline=Date.now()+120_000;
  for(;;){
   const fresh=(await queue()).find((e)=>!known.some((k)=>k.id===e.incident_id));
   if(fresh){const item={project:fresh.project_id,id:fresh.incident_id};known.push(item);return item;}
   if(Date.now()>deadline)throw Error('the incident producer opened no further incident');
   await sleep(750);
  }
 };
 const act=async(entity:'incident'|'issue',project:string,target:string,kind:string,payload:Record<string,unknown>):Promise<void>=>{
  for(let attempt=0;attempt<5;attempt++){
   const v=entity==='incident'
    ?await postJson(me,'/api/v1/incidents/get',{org,project_id:project,target_id:target})
    :await postJson(me,'/api/v1/evidence/issue',{org,project,issue:target});
   const version=entity==='incident'?field(v.json,'version'):field(field(v.json,'grouping'),'revision');
   const r=await postJson(me,'/api/v1/actions',{org,command_id:id(),expected_version:String(version),project_id:project,target_id:target,entity_kind:entity,kind,payload});
   if(r.status===200)return;
   if(r.status!==409||attempt===4)throw Error(`${entity} ${kind}: HTTP ${r.status} ${r.text}`);
  }
 };
 const T=(m:number):bigint=>minAgo(m);

 // 1. The failure of the real bundle (frames mapped through the uploaded source map), a fatal error: critical incident.
 const trace=id(),span=spanId();
 const traceBase=minAgo(12);
 const d0=domain();
 await ingestTrace(ingest,storefrontSource,trace,traceBase,d0,[
  {span,kind:'server',operation:'op.checkout',startMs:0,endMs:910,status:'error'},
  {span:spanId(),parent:span,kind:'internal',operation:'op.payment',startMs:40,endMs:880,status:'error'},
  {span:spanId(),parent:span,kind:'client',operation:'op.inventory',dependency:'postgres',startMs:60,endMs:700},
  {span:spanId(),parent:span,kind:'client',operation:'op.request',dependency:'cache',startMs:70,endMs:120},
 ]);
 await ingestStoredFailure(ingest,storefrontSource,{at:T(11),class:'CheckoutFailure',mechanism:'uncaught_exception',handled:false,fatal:true,code:'E_CHECKOUT',release:rel.c,trace,span,artifact,frames:bundle.frames});
 const checkoutIssue=await issueOf(storefront,'CheckoutFailure');
 const inc=[await nextIncident()];

 // 2. A regression: seen in v2.40.2, resolved with that release as the fix, back in v2.41.0.
 await ingestError(ingest,storefrontSource,{at:T(80),class:'PaymentGatewayTimeout',handled:false,fatal:false,release:rel.b});
 const paymentIssue=await issueOf(storefront,'PaymentGatewayTimeout');
 inc.push(await nextIncident());
 await act('issue',storefront,paymentIssue,'resolve',{reason:'Fixed by the retry budget in v2.40.2',fixed_frontier:[rel.b],resolution_boundary:String(T(60))});
 await sleep(2000);
 await ingestError(ingest,storefrontSource,{at:T(9),class:'PaymentGatewayTimeout',handled:false,fatal:false,release:rel.c});
 await issueOf(storefront,'PaymentGatewayTimeout',2);
 inc.push(await nextIncident());

 // 3-6. Four more error issues, each its own incident.
 const classes:[Source,string,string,boolean,string,number][]=[
  [jobsErrorSource,jobsProject,'InventorySyncStalled',false,'',30],
  [storefrontSource,storefront,'CartTotalMismatch',false,rel.c,25],
  [apiSource,apiProject,'SearchIndexLag',false,'',18],
  [jobsErrorSource,jobsProject,'EmailRenderError',false,'',6],
 ];
 for(const [src,project,cls,fatal,release,ago] of classes){
  await ingestError(ingest,src,{at:T(ago),class:cls,handled:false,fatal,...(release?{release}:{})});
  await issueOf(project,cls);
  inc.push(await nextIncident());
 }
 expect(inc.length).toBe(7);
 // A second occurrence of the checkout failure on another day-part (the issue page lists more than one).
 await ingestStoredFailure(ingest,storefrontSource,{at:T(5),class:'CheckoutFailure',mechanism:'uncaught_exception',handled:false,fatal:true,code:'E_CHECKOUT',release:rel.c,trace,span,artifact,frames:bundle.frames});

 // The error issue has an owner; the incidents sit in different states with titles, owners, links and timeline notes.
 await act('issue',storefront,checkoutIssue,'assign',{owner:dana.id,reason:'Owns the checkout flow'});
 const [i0,i1,i2,i3,i4,i5,i6]=inc as [typeof inc[0],typeof inc[0],typeof inc[0],typeof inc[0],typeof inc[0],typeof inc[0],typeof inc[0]];
 // 0: critical, acknowledged, owned, noted, linked to its issue, release and service.
 await act('incident',i0.project,i0.id,'title',{title:'Checkout fails with a 500 for card payments'});
 await act('incident',i0.project,i0.id,'ack',{reason:'Looking now'});
 await act('incident',i0.project,i0.id,'assign',{owner:dana.id});
 await act('incident',i0.project,i0.id,'note',{note:'Started right after the v2.41.0 deploy to production. Rolling back is the fallback.'});
 await act('incident',i0.project,i0.id,'note',{note:'Stack points at riskyCheckout in src/app.ts (mapped frames on the issue page).'});
 await act('incident',i0.project,i0.id,'link',{link:{kind:'issue',id:checkoutIssue}});
 await act('incident',i0.project,i0.id,'link',{link:{kind:'release',id:rel.c}});
 await act('incident',i0.project,i0.id,'link',{link:{kind:'service',id:storefrontService}});
 // 1: the old payment-timeout episode, resolved with a post-incident note.
 await act('incident',i1.project,i1.id,'title',{title:'Payment gateway timeouts (v2.40.1)'});
 await act('incident',i1.project,i1.id,'resolve',{reason:'Retry budget shipped in v2.40.2'});
 await act('incident',i1.project,i1.id,'note',{note:'Post-incident: the gateway SLA was 4 s, our client timeout was 3 s.'});
 // 2: the regression, still unacknowledged.
 await act('incident',i2.project,i2.id,'title',{title:'Payment gateway timeouts are back in v2.41.0'});
 await act('incident',i2.project,i2.id,'link',{link:{kind:'release',id:rel.c}});
 await act('incident',i2.project,i2.id,'link',{link:{kind:'service',id:apiService}});
 // 3: acknowledged and snoozed.
 await act('incident',i3.project,i3.id,'title',{title:'Inventory sync is stalled'});
 await act('incident',i3.project,i3.id,'ack',{reason:'Known upstream maintenance'});
 await act('incident',i3.project,i3.id,'snooze',{until:String(NOW+2n*3600n*SECOND),reason:'Supplier feed is down until the evening'});
 // 4: resolved.
 await act('incident',i4.project,i4.id,'title',{title:'Cart total differs from the order total'});
 await act('incident',i4.project,i4.id,'ack',{reason:'Taking it'});
 await act('incident',i4.project,i4.id,'resolve',{reason:'Rounding fixed in the cart service'});
 // 5: owned by Timur, not yet acknowledged.
 await act('incident',i5.project,i5.id,'title',{title:'Search results are minutes behind the catalog'});
 await act('incident',i5.project,i5.id,'assign',{owner:timur.id});
 // 6: acknowledged by the administrator with a note.
 await act('incident',i6.project,i6.id,'title',{title:'Order e-mails fail to render'});
 await act('incident',i6.project,i6.id,'ack',{reason:'On it'});
 await act('incident',i6.project,i6.id,'note',{note:'Template change in the last release; reverting the partial.'});

 // Spans of the storefront service across the hour, with a real gap (no entry span between minutes 27 and 38), and the featured trace above.
 const traceMinutes:number[]=[];
 for(let m=57;m>1;m-=0.55)if(!(m<38&&m>27))traceMinutes.push(m);
 await pool(traceMinutes,6,async(m)=>{
  const base=minAgo(m),sp=spanId(),d=domain();
  const dur=120+Math.round(Math.abs(Math.sin(m*3.1))*700);
  const bad=Math.round(m*10)%13===0;
  await ingestTrace(ingest,storefrontSource,id(),base,d,[
   {span:sp,kind:'server',operation:'op.checkout',startMs:0,endMs:dur,status:bad?'error':'ok'},
   {span:spanId(),parent:sp,kind:'client',operation:'op.inventory',dependency:'postgres',startMs:10,endMs:Math.max(20,Math.round(dur*0.6))},
  ]);
 });

 // Metric series of the api project: one point every 30 s over the hour with a real gap (minutes 25 to 35 never reported).
 const series:number[]=[];
 for(let m=58;m>0.5;m-=0.5)if(!(m<35&&m>25))series.push(m);
 await pool(series,8,async(m)=>{
  await ingestMetric(ingest,apiSource,{name:'request_latency_ms',labels:{job:'api',kind:'float'},at:minAgo(m),value:180+Math.round(Math.abs(Math.sin(m/4))*90)+(m<14?160:0)});
 });

 // Jobs: one with failed attempts and a recovery, one with a failing run, one steady. Events go in (attempt start, record id) order.
 const jobsSource=await onboardJobSource(page,org,jobsProject);
 const J={recovers:id(),failing:id(),steady:id()};
 await saveJobDefinition(page,org,jobsProject,J.recovers,{revision:'1',effective_from_ns:String(minAgo(500)),schedule:{cron:'*/20 * * * *',timezone:'UTC'},grace_ns:String(5n*60n*SECOND)});
 const epoch=id();
 interface Ev{job:string;run:string;attempt:string;occurrence:string;ordinal:number;seq:number;state:'started'|'succeeded'|'failed';start:number;end?:number;cause?:boolean}
 const events:Ev[]=[];
 const run=(job:string,occ:string,attempts:{state:'succeeded'|'failed';start:number;end:number}[])=>{
  const runId=id();
  attempts.forEach((a,i)=>{const attempt=id();
   events.push({job,run:runId,attempt,occurrence:occ,ordinal:i+1,seq:1,state:'started',start:a.start});
   events.push({job,run:runId,attempt,occurrence:occ,ordinal:i+1,seq:2,state:a.state,start:a.start,end:a.end,...(a.state==='failed'?{cause:true}:{})});
  });
 };
 const m=(minutes:number):number=>Number(minAgo(minutes)/MS);
 run(J.recovers,'manual.run1',[{state:'failed',start:m(50),end:m(49.5)},{state:'succeeded',start:m(48),end:m(47)}]);
 run(J.steady,'manual.run1',[{state:'succeeded',start:m(46),end:m(45.5)}]);
 run(J.recovers,'manual.run2',[{state:'succeeded',start:m(30),end:m(29)}]);
 run(J.steady,'manual.run2',[{state:'succeeded',start:m(26),end:m(25.5)}]);
 run(J.failing,'manual.run1',[{state:'failed',start:m(20),end:m(19)},{state:'failed',start:m(18),end:m(17)},{state:'failed',start:m(15),end:m(14)}]);
 run(J.recovers,'manual.run3',[{state:'succeeded',start:m(10),end:m(9)}]);
 events.sort((a,b)=>a.start-b.start||a.seq-b.seq);
 for(const e of events){
  await ingestJobAttempt(ingest,jobsSource,{job:e.job,run:e.run,attempt:e.attempt,occurrence:e.occurrence,ordinal:e.ordinal,epoch,sequence:e.seq,state:e.state,observed:String(BigInt(e.start)*MS),...(e.end!==undefined?{terminal:String(BigInt(e.end)*MS)}:{})});
 }

 // Replays (a clean one, one with a gap) and the native profile, through the replay source of the storefront project.
 const replaySource=await onboardReplaySource(page,org,storefront);
 const replays=await seedReplays(ingest,replaySource);
 await seedProfiles(ingest,replaySource);

 const data={org,projects:{storefront,api:apiProject,jobs:jobsProject},admin:{email:aigerim.email,password:aigerim.password,id:aigerim.id,name:aigerim.name},
  incidents:inc,issues:{checkout:checkoutIssue,payment:paymentIssue},releases:rel,services:{storefront:storefrontService,api:apiService},environments,
  trace:{id:trace,project:storefront},job:{id:J.recovers,failing:J.failing,project:jobsProject},replay:{id:replays.clean.replay,gap:replays.gap.replay,project:storefront},
  profile:{project:storefront,id:NATIVE_PROFILE,t0_ns:String(at(0))}};
 writeFileSync(out,JSON.stringify(data,null,1),{mode:0o600});
 await ctx.close();
});
