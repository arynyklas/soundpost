// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture of the error/release/artifact e2e. Everything goes through committed product routes: organizations,
// projects, users, grants, the source policy and the source through the admin and source-onboarding routes; the source map
// through the multipart POST /api/v1/artifacts upload as a user holding artifacts.write; releases through the organization
// administrator's POST /api/v1/releases/register; spans and error occurrences through POST /ingest/v1/batches, followed by the
// runner's issue producer. No seed route, no state injection.
//
// The artifact is REAL: the application source below is bundled and minified by esbuild (the bundler the web console build itself
// ships with), the generated bundle is executed, the Error it throws is caught, and the frames recorded in the stored error
// occurrence are the ones of that real stack (V8 reports 1-based columns; the occurrence model stores 0-based generated columns).
// The uploaded map is the one esbuild wrote for that bundle, so what the browser later shows as mapped is what the map says about
// the very position that threw.
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import vm from 'node:vm';
import {request as playwrightRequest} from '@playwright/test';
import type {Browser,Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,ingestBatch,ingestError,ingestSpan,login,origin,postJson,csrf,SECOND,type Source} from './real';

export interface Member{id:string;email:string;password:string}
export const MAP_SECRET='PRIVATE-SOURCE-CANARY privateSource = 1;';
export const CANARY_LABEL='<img src=x onerror="window.__pwn=1"> release & <b>label</b>';
export const CANARY_FN='<script>window.__pwn=2</script> boom';
export const ERROR_CLASS='E2eEvidenceFailure';
export const ACTION_CLASS='E2eActionTarget';
export const REAL_CLASS='CheckoutFailure';
export const REAL_CODE='E_CHECKOUT';

export interface RealStackFrame{function:string;line:number;column:number}
export interface RealBundle{generated:Buffer;map:Buffer;sourceFile:string;throwLine:number;callLine:number;frames:RealStackFrame[]}
export interface EvidenceSeed{
 org:string;project:string;otherOrg:string;otherProject:string;source:string;build:string;otherBuild:string;
 artifact:string;mapHash:string;mapBytes:string;
 admin:Member;analyst:Member;srcOwner:Member;mapOnly:Member;telemetry:Member;outsider:Member;
 releases:{root:string;child:string;sibling:string;orphan:string;missingParent:string;unregistered:string};
 issue:{id:string;fingerprint:string;knownOccurrence:string;unknownOccurrence:string};
 /** One issue made from a failure of the REAL bundle: the stored record carries the real stack, the chain, the code, a trace and a release. */
 real:{issue:string;fingerprint:string;occurrence:string;trace:string;span:string;release:string;bundle:RealBundle;sha256Generated:string};
 /** An issue nothing else reads: the issue-action flows change its workflow state. */
 actions:{issue:string;fingerprint:string;occurrence:string};
 debugId:string;
 /** Rename the display label of the child release (entity revision = the current one) through the real registration route. */
 renameChild:(label:string,revision:string)=>Promise<void>;
 /** Make one more real occurrence of an issue's class (frameless, manual) in a registered release, and wait until the producer has recorded it. */
 occurrenceOf:(errorClass:string,release?:string)=>Promise<string>;
}

export async function member(page:Page,org:string,project:string,label:string,permissions:string[],orgAdmin=false):Promise<Member>{
 const m:Member={id:id(),email:`${label}-${id().slice(0,8)}@example.test`,password:`evidence ${label} password ${id().slice(0,8)}`};
 await adminCommand(page,org,'create_user',{id:m.id,email:m.email,password:m.password});
 await adminCommand(page,org,'membership',{user_id:m.id,enabled:true});
 if(permissions.length>0)await adminCommand(page,org,'grant',{user_id:m.id,project_id:project,enabled:true,permissions});
 if(orgAdmin)await adminCommand(page,org,'org_admin',{user_id:m.id,enabled:true});
 return m;
}
export const revoke=(page:Page,org:string,project:string,userId:string,permissions:string[]):Promise<unknown>=>adminCommand(page,org,'grant',{user_id:userId,project_id:project,enabled:false,permissions});

async function post(page:Page,path:string,data:unknown):Promise<unknown>{
 const r=await postJson(page,path,data);
 if(r.status>=300)throw Error(`${path}: HTTP ${r.status} ${r.text}`);
 return r.json;
}

// The identities below are the grouping contract the issue producer applies (internal/issues/group.go Fingerprint, version 1;
// internal/issues/service.go issueID). They are recomputed here from the organization, the project and what the error carries
// because no route lists issues by what they group; the page then shows the SAME hash, which is what the spec asserts.
const GROUPING_VERSION=1;
const part=(value:string):Buffer=>{const bytes=Buffer.from(value);const n=Buffer.alloc(4);n.writeUInt32BE(bytes.length);return Buffer.concat([n,bytes]);};
const version=():Buffer=>{const v=Buffer.alloc(2);v.writeUInt16BE(GROUPING_VERSION);return v;};
/** A frameless error with no code: grouped by class and mechanism. */
export function groupingFingerprint(org:string,project:string,errorClass:string,mechanism:string):string{
 return createHash('sha256').update(Buffer.concat([part('soundpost.error-grouping'),Buffer.from(org,'hex'),Buffer.from(project,'hex'),version(),part(errorClass),Buffer.from([0]),part(mechanism),Buffer.from([0]),Buffer.from([0])])).digest('hex');
}
/** An error with application frames and a code: grouped by class, the first (at most eight) in-app frames' module, artifact and function, and the code. */
export function groupingFingerprintOfFrames(org:string,project:string,errorClass:string,frames:{module:string;artifact:string;function:string}[],code:string):string{
 const count=Math.min(frames.length,8);
 const parts=frames.slice(0,count).map((f)=>Buffer.concat([part(f.module),part(f.artifact),part(f.function)]));
 return createHash('sha256').update(Buffer.concat([part('soundpost.error-grouping'),Buffer.from(org,'hex'),Buffer.from(project,'hex'),version(),part(errorClass),Buffer.from([count]),...parts,Buffer.from([1]),part(code)])).digest('hex');
}
export function issueId(org:string,project:string,fingerprint:string):string{
 return createHash('sha256').update(Buffer.concat([Buffer.from('soundpost.issue.v1'),Buffer.from(org,'hex'),Buffer.from(project,'hex'),version(),Buffer.from(fingerprint,'hex')])).digest('hex').slice(0,32);
}

/** Register (or rename, with the entity revision) one release as an organization administrator; retries only a control-revision race. */
export async function registerRelease(page:Page,org:string,project:string,release:Record<string,unknown>):Promise<void>{
 for(let attempt=0;;attempt++){
  const read=await postJson(page,'/api/v1/admin/read',{kind:'organizations'});
  const revision=field(read.json,'revision');
  if(read.status!==200||typeof revision!=='string')throw Error(`admin read: HTTP ${read.status} ${read.text}`);
  const r=await postJson(page,'/api/v1/releases/register',{org,project,command_id:id(),expected_revision:revision,release});
  if(r.status===409&&attempt<4)continue;
  if(r.status>=300)throw Error(`release register: HTTP ${r.status} ${r.text}`);
  return;
 }
}

/** The application the real bundle is built from. The first line is the private-source canary: it lives only in the map's sourcesContent. */
export const APP_SOURCE=[
 `// ${MAP_SECRET}`,
 'export function riskyCheckout(total: number): number {',
 '  const label = `order-${total}`;',
 '  if (total > 100) {',
 '    throw new Error(label);',
 '  }',
 '  return total;',
 '}',
 'export function run(): number {',
 '  return riskyCheckout(250);',
 '}',
 '',
].join('\n');

interface Esbuild{build(options:Record<string,unknown>):Promise<{outputFiles:{path:string;text:string}[]}>}
/**
 * Bundle and minify the application with esbuild, run the generated bundle for real and read the frames of the Error it throws.
 * Resolved through the web workspace's own vite dependency: no new package is introduced.
 */
export async function buildRealBundle():Promise<RealBundle>{
 const web=createRequire(resolve(process.cwd(),'package.json'));
 const esbuild=createRequire(web.resolve('vite/package.json'))('esbuild') as Esbuild;
 const built=await esbuild.build({stdin:{contents:APP_SOURCE,sourcefile:'src/app.ts',loader:'ts',resolveDir:process.cwd()},bundle:true,minify:true,sourcemap:'external',outfile:resolve(process.cwd(),'app.js'),absWorkingDir:process.cwd(),write:false,format:'cjs',platform:'node',legalComments:'none',logLevel:'silent'});
 const js=built.outputFiles.find((f)=>f.path.endsWith('.js')),map=built.outputFiles.find((f)=>f.path.endsWith('.map'));
 if(!js||!map)throw Error('esbuild produced no bundle or no map');
 const exported:{run?:()=>number}={};
 const sandbox={module:{exports:exported},exports:exported};
 new vm.Script(js.text,{filename:'app.js'}).runInNewContext(sandbox);
 let stack='';
 try{if(!sandbox.module.exports.run)throw Error('the bundle exports no run');sandbox.module.exports.run();throw Error('the real bundle did not throw');}
 catch(error){stack=typeof error==='object'&&error!==null&&'stack' in error?String(error.stack):'';if(!/^Error: order-250/.test(stack))throw error;}
 const frames:RealStackFrame[]=[];
 for(const m of stack.matchAll(/^\s+at (?:Object\.)?([A-Za-z_$][\w$]*) \(app\.js:(\d+):(\d+)\)$/gm))frames.push({function:m[1]??'',line:Number(m[2]),column:Number(m[3])-1});
 if(frames.length<2)throw Error(`the thrown stack has fewer than two bundle frames: ${stack}`);
 const lines=APP_SOURCE.split('\n');
 const lineOf=(needle:string):number=>{const i=lines.findIndex((l)=>l.includes(needle));if(i<0)throw Error(`no source line has ${needle}`);return i+1;};
 return {generated:Buffer.from(js.text),map:Buffer.from(map.text),sourceFile:'src/app.ts',throwLine:lineOf('throw new Error'),callLine:lineOf('return riskyCheckout(250)'),frames:frames.slice(0,2)};
}

type Records=Parameters<typeof ingestBatch>[2];
const resourceOf=(s:Source):Record<string,unknown>=>({service_id:s.service,environment_id:s.environment,build_id:s.build,instance_pseudonym:s.instance,labels:[]});
export interface StoredFailureInput{at:bigint;class:string;mechanism:string;handled:boolean;fatal:boolean;code:string;release:string;trace:string;span:string;artifact:string;frames:RealStackFrame[]}
/** One error occurrence with the real stack, a cause chain, a code, a release, a trace and a span, as its own real batch; returns its occurrence ID. */
export async function ingestStoredFailure(request:Parameters<typeof ingestBatch>[0],s:Source,e:StoredFailureInput):Promise<string>{
 const occurrence=id();
 const frames=e.frames.map((f)=>({module_id:'app',function:f.function,artifact_id:e.artifact,line:f.line,column:f.column,in_app:true,async:false}));
 const payload={occurrence_id:occurrence,exception_class:e.class,mechanism:e.mechanism,frames,
  exception_graph:{nodes:[{id:0,exception_class:e.class,frames,context_suppressed:false},{id:1,exception_class:'CheckoutCause',frames:[],context_suppressed:true}],edges:[{from:0,to:1,kind:'cause'}],reasons:['cause_accessor']},
  code:e.code,build_id:s.build,release_id:e.release,handled:e.handled,fatal:e.fatal,trace_id:e.trace,span_id:e.span};
 const records:Records=[{id:id(),kind:'error',observed_at_ns:e.at.toString(),resource:resourceOf(s),payload}];
 await ingestBatch(request,s,records);
 return occurrence;
}

/** Everything the three pages and the frame lookup read, through real routes only. */
export async function seedEvidence(owner:Page,browser:Browser):Promise<EvidenceSeed>{
 const org=await createOrg(owner,'evidence e2e org'),project=await createProject(owner,org,'evidence project');
 const otherOrg=await createOrg(owner,'evidence other org'),otherProject=await createProject(owner,otherOrg,'other project');
 // An administrator with no telemetry grant, one with it, the artifact writer and source reader, a map-only reader, a telemetry-only reader and a stranger.
 const admin=await member(owner,org,project,'admin',['artifacts.read'],true);
 const analyst=await member(owner,org,project,'analyst',['artifacts.read','telemetry.read'],true);
 const srcOwner=await member(owner,org,project,'srcowner',['artifacts.write','artifacts.read','raw.read']);
 const mapOnly=await member(owner,org,project,'maponly',['artifacts.read']);
 const telemetry=await member(owner,org,project,'telemetry',['telemetry.read']);
 const outsider=await member(owner,otherOrg,otherProject,'outsider',['artifacts.read','raw.read','telemetry.read']);

 // The source whose policy admits this build (metrics, errors and spans) and names the one source reader.
 const source=id(),build=id(),otherBuild=id(),service=id(),environment=id();
 await adminCommand(owner,org,'source_policy',{id:source,config:{project_id:project,origins:[],restricted:false,readers:[srcOwner.id],enabled:true}});
 const policy={revision:'1',enabled:true,class:'structured',kinds:['metric','error','span'],templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build,otherBuild],instance_pseudonym:['opaque-instance']},labels:{},operations:['op.request'],dependencies:[],codes:[REAL_CODE],retention_days:{metric:30,error:30,span:30},max_bytes:'1048576',max_series:'1000',replay:false,expires_ns:'0'};
 const onboarded=await post(owner,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:String(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND),policy,reason:'evidence e2e fixture'});
 const credential=field(onboarded,'credential'),policyRevision=field(field(onboarded,'descriptor'),'policy_revision');
 if(typeof credential!=='string')throw Error('source onboarding returned no credential');
 const errorSource:Source={id:source,credential,producer:id(),org,project,service,environment,build,instance:'opaque-instance',policyRevision:typeof policyRevision==='string'?policyRevision:'1',kinds:['error']};

 // The real artifact: the generated bundle of the application above and the map its bundler wrote, admitted through the real upload route.
 const bundle=await buildRealBundle();
 const generated=bundle.generated,map=bundle.map;
 const sha=(b:Buffer):string=>createHash('sha256').update(b).digest('hex');
 const debugId=`debug-${id().slice(0,12)}`;
 const manifest=`{"version":1,"org":"${org}","project":"${project}","source":"${source}","build":"${build}","debug_id":"${debugId}","generated_sha256":"${sha(generated)}","map_sha256":"${sha(map)}","path":"dist/app.js","source_content":true,"size":"${map.length}","retain_until_ns":"4102444800000000000"}`;
 const writer=await browser.newContext({baseURL:origin()});
 const w=await writer.newPage();
 await login(w,srcOwner.email,srcOwner.password);
 const token=await csrf(w);
 const upload=await w.request.post(`${origin()}/api/v1/artifacts`,{headers:{'X-CSRF-Token':token,Origin:origin()},multipart:{manifest:{name:'manifest',mimeType:'application/json',buffer:Buffer.from(manifest)},file:{name:'app.js.map',mimeType:'application/json',buffer:map}}});
 const text=await upload.text();
 await writer.close();
 const artifact=field(JSON.parse(text) as unknown,'id');
 if(upload.status()!==200||typeof artifact!=='string')throw Error(`artifact upload: HTTP ${upload.status()} ${text}`);

 // Releases through the real registration route, as the organization owner acting as administrator of this organization.
 const releases={root:id(),child:id(),sibling:id(),orphan:id(),missingParent:id(),unregistered:id()};
 const release=(rid:string,label:string,parents:string[],artifactBound:boolean,revision='0')=>({id:rid,org,project,build_id:build,parents,build_time_ns:'5',debug_artifacts:artifactBound?[{artifact_id:artifact,debug_id:debugId,sha256:sha(map)}]:[],display_label:label,revision});
 await registerRelease(owner,org,project,release(releases.root,'v1.0',[],true));
 await registerRelease(owner,org,project,release(releases.child,'v1.1',[releases.root],true));
 await registerRelease(owner,org,project,release(releases.sibling,CANARY_LABEL,[releases.root],false));
 await registerRelease(owner,org,project,release(releases.orphan,'v-orphan',[releases.missingParent],false));
 await registerRelease(owner,org,project,release(releases.child,'v1.1-renamed',[releases.root],true,'1'));

 // Issues made by the product from real ingested occurrences; the runner's issue producer groups them. Wait until the real issue read shows each.
 const api=await playwrightRequest.newContext();
 const t=BigInt(Date.now())*1_000_000n;
 const knownOccurrence=await ingestError(api,errorSource,{at:t,class:ERROR_CLASS,handled:false,fatal:false,release:releases.child});
 const unknownOccurrence=await ingestError(api,errorSource,{at:t+SECOND,class:ERROR_CLASS,handled:false,fatal:false});
 const actionsOccurrence=await ingestError(api,errorSource,{at:t+2n*SECOND,class:ACTION_CLASS,handled:false,fatal:false,release:releases.child});
 // The failure of the real bundle: its real stack, a cause chain, a code, the release it ran in and a real span of the trace it happened under.
 const trace=id(),span=id().slice(0,16);
 await ingestSpan(api,errorSource,{trace,span,at:t+3n*SECOND});
 const realOccurrence=await ingestStoredFailure(api,errorSource,{at:t+4n*SECOND,class:REAL_CLASS,mechanism:'uncaught_exception',handled:false,fatal:true,code:REAL_CODE,release:releases.child,trace,span,artifact,frames:bundle.frames});
 const fingerprint=groupingFingerprint(org,project,ERROR_CLASS,'manual'),issue=issueId(org,project,fingerprint);
 const actionsFingerprint=groupingFingerprint(org,project,ACTION_CLASS,'manual'),actionsIssue=issueId(org,project,actionsFingerprint);
 const realFingerprint=groupingFingerprintOfFrames(org,project,REAL_CLASS,bundle.frames.map((f)=>({module:'app',artifact,function:f.function})),REAL_CODE),realIssue=issueId(org,project,realFingerprint);
 const reader=await browser.newContext({baseURL:origin()});
 const rp=await reader.newPage();
 await login(rp,admin.email,admin.password);
 const waitFor=async(issueIdentity:string,want:number):Promise<void>=>{
  const deadline=Date.now()+60_000;
  for(;;){
   const r=await postJson(rp,'/api/v1/evidence/issue',{org,project,issue:issueIdentity});
   const occurrences=field(r.json,'occurrences');
   if(r.status===200&&Array.isArray(occurrences)&&occurrences.length>=want)return;
   if(Date.now()>deadline)throw Error(`the issue producer never grouped ${want} occurrence(s) of ${issueIdentity}: HTTP ${r.status} ${r.text}`);
   await rp.waitForTimeout(500);
  }
 };
 await waitFor(issue,2);
 await waitFor(actionsIssue,1);
 await waitFor(realIssue,1);
 // More occurrences of a class after the fact (regression flows): ingested through the same real route, then awaited.
 let extra=0;
 const occurrenceOf=async(errorClass:string,releaseId?:string):Promise<string>=>{
  extra++;
  const occurrence=await ingestError(api,errorSource,{at:BigInt(Date.now())*1_000_000n+BigInt(extra)*SECOND,class:errorClass,handled:false,fatal:false,...(releaseId?{release:releaseId}:{})});
  const identity=issueId(org,project,groupingFingerprint(org,project,errorClass,'manual'));
  const deadline=Date.now()+60_000;
  for(;;){
   const r=await postJson(rp,'/api/v1/evidence/issue',{org,project,issue:identity});
   const list=[...(Array.isArray(field(r.json,'occurrences'))?field(r.json,'occurrences') as unknown[]:[]),...(Array.isArray(field(r.json,'late_history'))?field(r.json,'late_history') as unknown[]:[])];
   if(r.status===200&&list.some((o)=>field(o,'occurrence_id')===occurrence))return occurrence;
   if(Date.now()>deadline)throw Error(`the producer never recorded occurrence ${occurrence}: HTTP ${r.status} ${r.text}`);
   await rp.waitForTimeout(500);
  }
 };

 return {org,project,otherOrg,otherProject,source,build,otherBuild,artifact,mapHash:sha(map),mapBytes:map.toString(),admin,analyst,srcOwner,mapOnly,telemetry,outsider,releases,
  issue:{id:issue,fingerprint,knownOccurrence,unknownOccurrence},
  real:{issue:realIssue,fingerprint:realFingerprint,occurrence:realOccurrence,trace,span,release:releases.child,bundle,sha256Generated:sha(generated)},
  actions:{issue:actionsIssue,fingerprint:actionsFingerprint,occurrence:actionsOccurrence},
  debugId,
  renameChild:(label,revision)=>registerRelease(owner,org,project,release(releases.child,label,[releases.root],true,revision)),
  occurrenceOf};
}
