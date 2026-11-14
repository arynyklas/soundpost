// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture of the error/release/artifact e2e. Everything goes through committed product routes: organizations,
// projects, users, grants, the source policy and the source through the admin and source-onboarding routes; the source map
// through the multipart POST /api/v1/artifacts upload as a user holding artifacts.write; releases through the organization
// administrator's POST /api/v1/releases/register; and the grouping issue through POST /ingest/v1/batches (two error
// occurrences) followed by the runner's issue producer. No seed route, no state injection.
import {createHash} from 'node:crypto';
import {request as playwrightRequest} from '@playwright/test';
import type {Browser,Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,ingestError,login,origin,postJson,csrf,SECOND,type Source} from './real';

export interface Member{id:string;email:string;password:string}
export const MAP_SECRET='PRIVATE-SOURCE-CANARY privateSource = 1;';
export const CANARY_LABEL='<img src=x onerror="window.__pwn=1"> release & <b>label</b>';
export const CANARY_FN='<script>window.__pwn=2</script> boom';
export const ERROR_CLASS='E2eEvidenceFailure';

export interface EvidenceSeed{
 org:string;project:string;otherOrg:string;otherProject:string;source:string;build:string;otherBuild:string;
 artifact:string;mapHash:string;mapBytes:string;
 admin:Member;srcOwner:Member;mapOnly:Member;telemetry:Member;outsider:Member;
 releases:{root:string;child:string;sibling:string;orphan:string;missingParent:string;unregistered:string};
 issue:{id:string;fingerprint:string;knownOccurrence:string;unknownOccurrence:string};
 debugId:string;
}

async function member(page:Page,org:string,project:string,label:string,permissions:string[],orgAdmin=false):Promise<Member>{
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

// The two identities below are the grouping contract the issue producer applies (internal/issues/group.go Fingerprint, version 1, no frames,
// no template, no code; internal/issues/service.go issueID). They are recomputed here from the organization, the project and the error class
// because no route lists issues by what they group; the page then shows the SAME hash, which is what the spec asserts.
const GROUPING_VERSION=1;
const part=(value:string):Buffer=>{const bytes=Buffer.from(value);const n=Buffer.alloc(4);n.writeUInt32BE(bytes.length);return Buffer.concat([n,bytes]);};
const version=():Buffer=>{const v=Buffer.alloc(2);v.writeUInt16BE(GROUPING_VERSION);return v;};
export function groupingFingerprint(org:string,project:string,errorClass:string,mechanism:string):string{
 return createHash('sha256').update(Buffer.concat([part('soundpost.error-grouping'),Buffer.from(org,'hex'),Buffer.from(project,'hex'),version(),part(errorClass),Buffer.from([0]),part(mechanism),Buffer.from([0]),Buffer.from([0])])).digest('hex');
}
export function issueId(org:string,project:string,fingerprint:string):string{
 return createHash('sha256').update(Buffer.concat([Buffer.from('soundpost.issue.v1'),Buffer.from(org,'hex'),Buffer.from(project,'hex'),version(),Buffer.from(fingerprint,'hex')])).digest('hex').slice(0,32);
}

/** Register (or rename, with the entity revision) one release as an organization administrator; retries only a control-revision race. */
async function registerRelease(page:Page,org:string,project:string,release:Record<string,unknown>):Promise<void>{
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

/** Everything the three pages and the frame lookup read, through real routes only. */
export async function seedEvidence(owner:Page,browser:Browser):Promise<EvidenceSeed>{
 const org=await createOrg(owner,'evidence e2e org'),project=await createProject(owner,org,'evidence project');
 const otherOrg=await createOrg(owner,'evidence other org'),otherProject=await createProject(owner,otherOrg,'other project');
 const admin=await member(owner,org,project,'admin',['artifacts.read'],true);
 const srcOwner=await member(owner,org,project,'srcowner',['artifacts.write','artifacts.read','raw.read']);
 const mapOnly=await member(owner,org,project,'maponly',['artifacts.read']);
 const telemetry=await member(owner,org,project,'telemetry',['telemetry.read']);
 const outsider=await member(owner,otherOrg,otherProject,'outsider',['artifacts.read','raw.read','telemetry.read']);

 // The source whose policy admits this build (metrics and errors) and names the one source reader.
 const source=id(),build=id(),otherBuild=id(),service=id(),environment=id();
 await adminCommand(owner,org,'source_policy',{id:source,config:{project_id:project,origins:[],restricted:false,readers:[srcOwner.id],enabled:true}});
 const policy={revision:'1',enabled:true,class:'structured',kinds:['metric','error'],templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build,otherBuild],instance_pseudonym:['opaque-instance']},labels:{},operations:[],dependencies:[],codes:[],retention_days:{metric:30,error:30},max_bytes:'1048576',max_series:'1000',replay:false,expires_ns:'0'};
 const onboarded=await post(owner,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:String(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND),policy,reason:'evidence e2e fixture'});
 const credential=field(onboarded,'credential'),policyRevision=field(field(onboarded,'descriptor'),'policy_revision');
 if(typeof credential!=='string')throw Error('source onboarding returned no credential');
 const errorSource:Source={id:source,credential,producer:id(),org,project,service,environment,build,instance:'opaque-instance',policyRevision:typeof policyRevision==='string'?policyRevision:'1',kinds:['error']};

 // The real artifact: a generated bundle and its source map (with private source content) admitted through the real upload route.
 const generated=Buffer.from('function boom(){throw new Error("boom")}\n//# sourceMappingURL=app.js.map\n');
 const map=Buffer.from(JSON.stringify({version:3,file:'app.js',sources:['src/app.ts'],names:['boom'],mappings:'AAAA',sourcesContent:[MAP_SECRET]}));
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

 // One grouping issue made by the product: two real error occurrences of one class, one carrying a registered release (known ancestry) and one
 // carrying none (unknown), admitted through the ingest route; the runner's issue producer groups them. Wait until the real issue read shows both.
 const api=await playwrightRequest.newContext();
 const t=BigInt(Date.now())*1_000_000n;
 const knownOccurrence=await ingestError(api,errorSource,{at:t,class:ERROR_CLASS,handled:false,fatal:false,release:releases.child});
 const unknownOccurrence=await ingestError(api,errorSource,{at:t+SECOND,class:ERROR_CLASS,handled:false,fatal:false});
 await api.dispose();
 const fingerprint=groupingFingerprint(org,project,ERROR_CLASS,'manual'),issue=issueId(org,project,fingerprint);
 const reader=await browser.newContext({baseURL:origin()});
 const rp=await reader.newPage();
 await login(rp,admin.email,admin.password);
 const deadline=Date.now()+60_000;
 for(;;){
  const r=await postJson(rp,'/api/v1/evidence/issue',{org,project,issue});
  const occurrences=field(r.json,'occurrences');
  if(r.status===200&&Array.isArray(occurrences)&&occurrences.length===2)break;
  if(Date.now()>deadline)throw Error(`the issue producer never grouped the two occurrences: HTTP ${r.status} ${r.text}`);
  await rp.waitForTimeout(500);
 }
 await reader.close();

 return {org,project,otherOrg,otherProject,source,build,otherBuild,artifact,mapHash:sha(map),mapBytes:map.toString(),admin,srcOwner,mapOnly,telemetry,outsider,releases,issue:{id:issue,fingerprint,knownOccurrence,unknownOccurrence},debugId};
}
