// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,ingestError,login,onboardErrorSource,owner,postJson,setGrant} from './support/real';
// D9 in a real browser against the real server: no service registry. The service exists because an active source policy admits its ID;
// its environments are the policy's environments (the filter is applied by the server); its health is read only from stored evidence:
// failing with an open incident linked to it, degraded with only active conditions naming it, healthy with neither. The incident here
// is the REAL one the leader-only runner opens for an error ingested through a real source; the person links it to the service with the
// real action route and later resolves it. Nothing is seeded into a route and nothing is injected in the browser.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const hash=(org:string,project:string,extra:Record<string,string>):string=>`/#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',...extra})}`;
interface IncidentView{version:string;status:string;links:{kind:string;id:string}[]}
async function incident(page:Page,org:string,project:string,target:string):Promise<IncidentView>{
 const r=await postJson(page,'/api/v1/incidents/get',{org,project_id:project,target_id:target});
 expect(r.status).toBe(200);
 return r.json as IncidentView;
}
async function act(page:Page,org:string,project:string,target:string,expected:string,kind:string,payload:Record<string,unknown>):Promise<void>{
 const r=await postJson(page,'/api/v1/actions',{org,command_id:id(),expected_version:expected,project_id:project,target_id:target,entity_kind:'incident',kind,payload});
 expect(r.status,r.text).toBe(200);
}

test('a service is derived from source policies and its health from stored incidents; the environment filter is the server\'s',async({page,browser,playwright})=>{
 test.setTimeout(480_000);
 const o=owner();
 await login(page,o.email,o.password);
 const org=await createOrg(page,'service health org'),project=await createProject(page,org,'service health project');
 const ops={id:id(),email:`ops-${id().slice(0,8)}@example.test`,password:`service ops password ${id().slice(0,8)}`};
 await adminCommand(page,org,'create_user',{id:ops.id,email:ops.email,password:ops.password});
 await adminCommand(page,org,'membership',{user_id:ops.id,enabled:true});
 await adminCommand(page,org,'org_admin',{user_id:ops.id,enabled:true});
 await setGrant(page,org,ops.id,project,true);
 const source=await onboardErrorSource(page,org,project);
 const api=await playwright.request.newContext();
 await ingestError(api,source,{at:nsOf(Date.now()),class:'ServiceHealthFailure',fatal:false,handled:false});
 let target='';
 await expect.poll(async()=>{
  const r=await postJson(page,'/api/v1/queue',{org,projects:[project],limit:50});
  const entries=field(r.json,'entries');
  const first=Array.isArray(entries)?field(entries[0],'incident_id'):undefined;
  target=typeof first==='string'?first:'';
  return target;
 // The runner visits every project of the installation on each pass: late in the full suite its latency is several times what it is alone (job-history
 // waits of 42 s against 8 s, l3w15-fine), and an incident needs the issue and the incident stage in turn.
 },{message:'the runner opens an incident for the ingested error',timeout:240_000,intervals:[250,500,1000]}).not.toBe('');

 const ctx=await browser.newContext();
 const ops_=await ctx.newPage();
 await login(ops_,ops.email,ops.password);

 // The list: exactly the service the source policy admits, with the environment the policy lists. Its health is the stored evidence read per service; with no incident or condition it is healthy.
 await ops_.goto(hash(org,project,{view:'services'}));
 const row=ops_.getByTestId('service-row');
 await expect(row).toHaveCount(1);
 await expect(row).toHaveAttribute('data-service',source.service);
 await expect(row).toContainText(source.environment);
 await expect(row).toHaveAttribute('data-health','healthy');

 // The page of the service: no incident names it yet, so it is healthy by the stored evidence, and says why.
 await row.getByRole('link',{name:`Open service ${source.service}`}).click();
 await expect(ops_.locator(`h1[data-service="${source.service}"]`)).toBeVisible();
 await expect(ops_.getByTestId('service-health')).toHaveAttribute('data-status','healthy');
 // The service metrics are real figures where the installation serves them, else the honest not-available state (never zero).
 await expect(ops_.getByTestId('red-unavailable').or(ops_.getByTestId('red'))).toBeVisible();
 await expect(ops_.locator('[data-section="identity"]')).toContainText('Ready');
 await expect(ops_.locator('[data-section="health"]')).toContainText('Ready');
 await expect(ops_.locator('[data-section="telemetry"]')).toContainText('Not available');
 await expect(ops_.getByText(source.build)).toBeVisible();

 // A person links the real, open incident to the service: the service is failing and the page links the incident.
 const before=await incident(ops_,org,project,target);
 expect(before.status).toBe('open');
 await act(ops_,org,project,target,before.version,'link',{link:{kind:'service',id:source.service}});
 await ops_.reload();
 await expect(ops_.getByTestId('service-health')).toHaveAttribute('data-status','failing');
 const link=ops_.getByTestId('health-incident').getByRole('link');
 await expect(link).toHaveAttribute('href',new RegExp(`view=incidents.*incident=${project}%3A${target}`));
 await link.click();
 await expect(ops_.getByTestId('revision')).toBeVisible();

 // Resolving the incident ends failing; the stored evidence alone decides.
 const linked=await incident(ops_,org,project,target);
 expect(linked.links).toContainEqual({kind:'service',id:source.service});
 await act(ops_,org,project,target,linked.version,'resolve',{reason:'service health acceptance'});
 await ops_.goto(hash(org,project,{view:'services',service:source.service}));
 await expect(ops_.getByTestId('service-health')).toHaveAttribute('data-status','healthy');

 // A service no policy admits is one not-found; it never reads as a healthy service.
 await ops_.goto(hash(org,project,{view:'services',service:id()}));
 await expect(ops_.locator('.status[data-state="unauthorized"]')).toContainText('not found');
 await expect(ops_.getByTestId('service-health')).toHaveCount(0);

 // The environment filter is applied by the server: the policy's environment lists the service, any other lists none, and the bar says which.
 await ops_.goto(hash(org,project,{view:'services',env:source.environment}));
 await expect(ops_.getByTestId('visible-environment')).toContainText(source.environment);
 await expect(ops_.getByTestId('service-row')).toHaveCount(1);
 await ops_.goto(hash(org,project,{view:'services',env:id()}));
 await expect(ops_.getByTestId('service-list-empty')).toBeVisible();
 await expect(ops_.getByTestId('service-row')).toHaveCount(0);
 await ops_.goto(hash(org,project,{view:'services',service:source.service,env:id()}));
 await expect(ops_.locator('.status[data-state="unauthorized"]')).toContainText('not found');
});
