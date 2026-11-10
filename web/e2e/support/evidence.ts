// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real-server fixture of the error/release/artifact e2e. Organizations, projects, users, grants, the source policy and the
// source are made through the real admin and source-onboarding routes; the source map goes through the REAL multipart
// POST /api/v1/artifacts upload as a user holding artifacts.write. Two parts have no committed route and are seeded by
// the temporary harness routes the run wires in (see the report): release registration (real releases.Service under the
// caller's own admin scope) and one persisted grouping issue (a direct control-state injection).
import {createHash} from 'node:crypto';
import type {Browser,Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,login,origin,postJson,csrf,SECOND} from './real';

export interface Member{id:string;email:string;password:string}
export const MAP_SECRET='PRIVATE-SOURCE-CANARY privateSource = 1;';
export const CANARY_LABEL='<img src=x onerror="window.__pwn=1"> release & <b>label</b>';
export const CANARY_FN='<script>window.__pwn=2</script> boom';

export interface EvidenceSeed{
 org:string;project:string;otherOrg:string;otherProject:string;source:string;build:string;otherBuild:string;
 artifact:string;mapHash:string;mapBytes:string;
 admin:Member;srcOwner:Member;mapOnly:Member;telemetry:Member;outsider:Member;
 releases:{root:string;child:string;sibling:string;orphan:string;missingParent:string;unregistered:string};
 issue:{id:string;fingerprint:string;lateOccurrence:string;knownOccurrence:string;unknownOccurrence:string};
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

/** Everything the three pages and the frame lookup read, through real routes (and the two temporary seed routes). */
export async function seedEvidence(owner:Page,browser:Browser):Promise<EvidenceSeed>{
 const org=await createOrg(owner,'evidence e2e org'),project=await createProject(owner,org,'evidence project');
 const otherOrg=await createOrg(owner,'evidence other org'),otherProject=await createProject(owner,otherOrg,'other project');
 const admin=await member(owner,org,project,'admin',['artifacts.read'],true);
 const srcOwner=await member(owner,org,project,'srcowner',['artifacts.write','artifacts.read','raw.read']);
 const mapOnly=await member(owner,org,project,'maponly',['artifacts.read']);
 const telemetry=await member(owner,org,project,'telemetry',['telemetry.read']);
 const outsider=await member(owner,otherOrg,otherProject,'outsider',['artifacts.read','raw.read','telemetry.read']);

 // The source whose policy admits this build and names the one source reader.
 const source=id(),build=id(),otherBuild=id(),service=id(),environment=id();
 await adminCommand(owner,org,'source_policy',{id:source,config:{project_id:project,origins:[],restricted:false,readers:[srcOwner.id],enabled:true}});
 const policy={revision:'1',enabled:true,class:'structured',kinds:['metric'],templates:[],resources:{service_id:[service],environment_id:[environment],build_id:[build,otherBuild],instance_pseudonym:['opaque-instance']},labels:{},operations:[],dependencies:[],codes:[],retention_days:{metric:30},max_bytes:'1048576',max_series:'1000',replay:false,expires_ns:'0'};
 await post(owner,'/api/v1/sources',{command_id:id(),org,project,source,browser:false,origins:[],expires_ns:String(BigInt(Date.now())*1_000_000n+24n*3600n*SECOND),policy,reason:'evidence e2e fixture'});

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

 // Releases through the temporary seed route (the real releases.Service, under the owner's own admin scope).
 const releases={root:id(),child:id(),sibling:id(),orphan:id(),missingParent:id(),unregistered:id()};
 const release=(rid:string,label:string,parents:string[],artifactBound:boolean,revision='0')=>({org,project,release:{id:rid,org,project,build_id:build,parents,build_time_ns:'5',debug_artifacts:artifactBound?[{artifact_id:artifact,debug_id:debugId,sha256:sha(map)}]:[],display_label:label,revision}});
 await post(owner,'/api/v1/e2e-seed/release',release(releases.root,'v1.0',[],true));
 await post(owner,'/api/v1/e2e-seed/release',release(releases.child,'v1.1',[releases.root],true));
 await post(owner,'/api/v1/e2e-seed/release',release(releases.sibling,CANARY_LABEL,[releases.root],false));
 await post(owner,'/api/v1/e2e-seed/release',release(releases.orphan,'v-orphan',[releases.missingParent],false));
 await post(owner,'/api/v1/e2e-seed/release',release(releases.child,'v1.1-renamed',[releases.root],true,'1'));

 // One persisted issue with a late history, injected into control state (no committed writer exists).
 const issueId=id(),fingerprint=sha(Buffer.from('fingerprint')),known=id(),unknown=id(),late=id();
 const evidence=(occurrence:string,version:number,ancestry:string,release:string|undefined,event:number,arrival:number)=>({occurrence_id:occurrence,record_id:id(),origin:{group:id(),index:'1'},grouping_version:version,fingerprint,event_time_ns:String(event),arrival_time_ns:String(arrival),...(release?{release_id:release}:{}),ancestry,ordinal:'1',freshness:'fresh'});
 await post(owner,'/api/v1/e2e-seed/issue',{org,project,issue:{id:issueId,org,project,grouping_version:3,fingerprint,workflow:'resolved',revision:'4',occurrences:[evidence(known,3,'known',releases.child,90,200),evidence(unknown,3,'unknown',undefined,95,201)],late_history:[evidence(late,2,'unknown',undefined,80,300)],resolution_time_ns:'100',resolution_frontier:[releases.root],observed_releases:[releases.child],fixed_descendants:[],migration_links:[]}});

 return {org,project,otherOrg,otherProject,source,build,otherBuild,artifact,mapHash:sha(map),mapBytes:map.toString(),admin,srcOwner,mapOnly,telemetry,outsider,releases,issue:{id:issueId,fingerprint,lateOccurrence:late,knownOccurrence:known,unknownOccurrence:unknown},debugId};
}
