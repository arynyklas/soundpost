// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type Page} from '@playwright/test';
import {at,createOrg,createProject,createReader,field,id,ingestMetric,login,onboardMetricSource,owner,postJson,queryBody,reopen} from './support/real';

// 05.05#19 and 05.09#6 (D60, D61): the console reads under the audited elevation, and the `rate_limited` and `stale` load states
// are produced by the REAL server on real routes. Nothing here routes, rewrites or fulfils a request.
//  - Elevation: an instance administrator without a project grant is refused by the real query route; after the audited elevation the same
//    console query carries the handle (the one the real elevation route returned) and is answered, with the elevated read said in words.
//  - rate_limited: the server throttles an elevation that found nothing, per credential (30 misses in five minutes). The misses are real
//    reads of the real route with handles the server never issued; the console's next elevated query meets the server's own 429 body.
//  - stale: the query engine answers stale when a read has not reached a minimum cursor the caller names. The console's minimum-data-position
//    field sends one no group can have reached (the largest index the field accepts) for a group of the previous answer: the shared server's groups
//    keep moving while a person types, so a position "just beyond" the one read is reached by any other writer of that group.
const admin=process.env.SOUNDPOST_ELEVATION_EMAIL;
const password=process.env.SOUNDPOST_ELEVATION_PASSWORD;
const selected=process.env.SOUNDPOST_TEST_ORG;
if(!admin||!password||!selected)throw new Error('A real separate MFA-free instance-admin fixture and administered organization are required for the console elevation acceptance');

const linkFor=(org:string,project:string):string=>`/#${new URLSearchParams({org,projects:project,start:String(at(0)),end:String(at(70)),tz:'UTC',view:'explore'})}`;
const UINT64_MAX='18446744073709551615';
async function run(page:Page,expression:string):Promise<void>{
 await page.getByLabel('Query expression').fill(expression);
 await page.getByRole('button',{name:'Run query',exact:true}).click();
}
/** Opens the elevation form for `org`, fills it, submits; resolves with the elevation id the real route returned. */
async function elevate(page:Page,org:string,reason:string,secret:string):Promise<string>{
 await page.getByRole('button',{name:'Request scoped elevation'}).click();await page.getByRole('checkbox',{name:org,exact:true}).check();await page.getByLabel('Reason',{exact:true}).fill(reason);await page.getByLabel('Current password',{exact:true}).fill(secret);
 const [response]=await Promise.all([page.waitForResponse((r)=>r.url().endsWith('/api/v1/elevation')&&r.request().method()==='POST'),page.getByRole('button',{name:'Reauthenticate and elevate'}).click()]);
 expect(response.status()).toBe(200);
 const handle=field(await response.json() as unknown,'id');
 if(typeof handle!=='string')throw new Error('no elevation id in the response');
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeVisible();
 return handle;
}
/** The instance administrator's own project in the administered organization, holding one real metric; the administrator holds no grant on it. */
async function adminProject(page:Page,name:string):Promise<{project:string;metric:string}>{
 const project=await createProject(page,selected as string,name);
 const source=await onboardMetricSource(page,selected as string,project);
 const metric=`elev_${id().slice(0,8)}`;
 const api=await pwRequest.newContext();
 await ingestMetric(api,source,{name:metric,at:at(10),value:7});
 return {project,metric};
}
interface Sent{elevation?:unknown;csrf:boolean}
const queryBodies=(page:Page):Sent[]=>{
 const seen:Sent[]=[];
 page.on('request',(r)=>{if(r.url().endsWith('/api/v1/query')&&r.method()==='POST'){const body=r.postDataJSON() as {elevation?:unknown};seen.push({elevation:body.elevation,csrf:Boolean(r.headers()['x-csrf-token'])});}});
 return seen;
};

test('a console query carries the audited elevation for an organization it was granted for: refused before, answered after, said in words, and not after the view is cleared',async({page})=>{
 test.setTimeout(240_000);
 await login(page,admin,password);
 const {project,metric}=await adminProject(page,'console elevation project');
 const sent=queryBodies(page);
 await reopen(page,linkFor(selected,project));
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 // Control: without elevation the real route refuses (an organization administrator holds no data grant) and the console says it is not available to this account.
 await run(page,`${metric}`);
 await expect(page.getByTestId('results').locator('.status[data-state="unauthorized"]')).toBeVisible();
 await expect(page.getByTestId('elevated-read')).toHaveCount(0);
 expect(sent.map((b)=>[b.elevation,b.csrf])).toEqual([[undefined,true]]);

 const handle=await elevate(page,selected,'Console elevated read acceptance',password);
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 const [answer]=await Promise.all([page.waitForResponse((r)=>r.url().endsWith('/api/v1/query')&&r.request().method()==='POST'),run(page,`${metric}`)]);
expect(answer.status(),`${answer.request().postData()} -> ${await answer.text()} headers ${JSON.stringify(answer.request().headers())}`).toBe(200);
 const results=page.getByTestId('results');
 await expect(results.locator(`[data-project="${project}"]`)).toHaveAttribute('data-state','ready');
 await expect(results.getByText('7',{exact:false}).first()).toBeVisible();
 await expect(page.getByTestId('elevated-read')).toBeVisible();
 await expect(page.getByTestId('elevated-read')).toContainText(selected);
 // The handle on the wire is exactly the one the real elevation route issued, and only on the elevated read.
 expect(sent.map((b)=>b.elevation)).toEqual([undefined,handle]);

 // Clearing the elevated view takes the handle away: the same query is refused again and nothing elevated stays on the screen.
 await page.getByRole('button',{name:'Clear elevated view'}).click();
 await expect(page.getByRole('heading',{name:'Scoped elevation active'})).toBeHidden();
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 await run(page,`${metric}`);
 await expect(page.getByTestId('results').locator('.status[data-state="unauthorized"]')).toBeVisible();
 await expect(page.getByTestId('elevated-read')).toHaveCount(0);
 expect(sent.map((b)=>b.elevation)).toEqual([undefined,handle,undefined]);
});

test('an account change detected by the periodic session check drops the elevation: the next query from the same page carries none and the elevated banner is gone',async({browser})=>{
 test.setTimeout(240_000);
 const context=await browser.newContext();
 const a=await context.newPage();const b=await context.newPage();
 await login(a,admin,password);
 const {project,metric}=await adminProject(a,'console account change project');
 const reader=await createReader(a,selected,[project]);
 const sent=queryBodies(a);
 await reopen(a,linkFor(selected,project));
 await expect(a.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 const handle=await elevate(a,selected,'Account change must not carry the elevation',password);
 await expect(a.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 await run(a,`${metric}`);
 await expect(a.getByTestId('elevated-read')).toBeVisible();
 expect(sent.map((x)=>x.elevation)).toEqual([handle]);
 // Another account signs in from a second page of the same browser context (the session cookie is shared): page A is not told, its own
 // periodic check (5 s) meets a different user and re-mounts the console.
 await login(b,reader.email,reader.password);
 await expect(a.getByRole('heading',{name:'Scoped elevation active'})).toBeHidden({timeout:30_000});
 await expect(a.getByTestId('elevated-read')).toHaveCount(0);
 await expect(a.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 await run(a,`${metric}`);
 await expect(a.getByTestId('results').locator(`[data-project="${project}"]`)).toHaveAttribute('data-state','ready');
 expect(sent.map((x)=>x.elevation)).toEqual([handle,undefined]);
 await expect(a.getByTestId('elevated-read')).toHaveCount(0);
 await context.close();
});

test('the server\'s own throttle on elevation reads that found nothing is the Rate limited state in the console, with the server request id',async({page})=>{
 test.setTimeout(240_000);
 await login(page,admin,password);
 const {project,metric}=await adminProject(page,'console rate limit project');
 await reopen(page,linkFor(selected,project));
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 const handle=await elevate(page,selected,'Console rate limited acceptance',password);
 // Control: the elevated read is answered while the credential is under its limit.
 const [answer]=await Promise.all([page.waitForResponse((r)=>r.url().endsWith('/api/v1/query')&&r.request().method()==='POST'),run(page,`${metric}`)]);
 expect(answer.status(),`${answer.request().postData()} -> ${await answer.text()}`).toBe(200);
 await expect(page.getByTestId('results').locator(`[data-project="${project}"]`)).toHaveAttribute('data-state','ready');
 // Thirty real reads of the real route that name a handle the server never issued: each is a miss; the next read is over the limit, for every handle of this credential.
 const body={...queryBody({org:selected,projects:[project],expression:`${metric}`,instant:at(0)})};
 let limited:{status:number;text:string}|null=null;
 for(let i=0;i<40&&limited===null;i++){
  const reply=await postJson(page,'/api/v1/query',{...body,elevation:id()});
  if(reply.status===429)limited=reply;else expect([403,404],reply.text).toContain(reply.status);
 }
 expect(limited,'the server never throttled the misses').not.toBeNull();
 expect(field(JSON.parse((limited as {text:string}).text) as unknown,'code')).toBe('rate_limited');
 expect(handle).toMatch(/^[0-9a-f]{32}$/);
 await run(page,`${metric} + 0`);
 const status=page.locator('.status[data-state="rate_limited"]');
 await expect(status).toBeVisible();
 await expect(status).toHaveAttribute('role','alert');
 await expect(status.locator('strong').first()).toHaveText('Rate limited');
 await expect(status).toContainText('Request');
 await expect(page.locator('[data-series]')).toHaveCount(0);
 await expect(page.getByTestId('elevated-read')).toHaveCount(0);
});

test('a minimum data position the read has not reached is refused by the real query engine as Error (stale), and with partial results the project reads Partial, never Complete',async({browser})=>{
 test.setTimeout(240_000);
 const o=owner();
 const adminPage=await (await browser.newContext()).newPage();
 await login(adminPage,o.email,o.password);
 const api=await pwRequest.newContext();
 const org=await createOrg(adminPage,'console stale org'),project=await createProject(adminPage,org,'console stale project');
 const reader=await createReader(adminPage,org,[project]);
 const source=await onboardMetricSource(adminPage,org,project);
 const metric=`stale_${id().slice(0,8)}`;
 for(let i=0;i<4;i++)await ingestMetric(api,source,{name:metric,at:at(10+i),value:i+1});
 const page=await (await browser.newContext()).newPage();
 await login(page,reader.email,reader.password);
 await reopen(page,linkFor(org,project));
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 // The control: a read with no minimum is complete, and reports the cursors it read through.
 await run(page,`{__name__="${metric}"}`);
 const panel=page.getByTestId('results').locator(`[data-project="${project}"]`);
 await expect(panel).toHaveAttribute('data-state','ready');
 await panel.locator('summary').click();
 const cursor=(await panel.locator('.cursor-list code').first().innerText()).trim();
 const [group,index]=cursor.split(':');
 expect(group).toMatch(/^[0-9a-f]{32}$/);
 // The server is shared: while a person reads and types, other writers ingest into this group too (the first cursor of the answer is only the first of the
 // 64 groups, not the group this test wrote to, so the suite's other specs move it all the time). Make that happen here, deterministically: fresh series of
 // this source (each is routed to a slot by its own identity, one batch per series) are ingested until a receipt names this group; its cursor is then past
 // the one just read. A minimum of "one beyond what was read" is reached from then on and answered; the minimum named below is one no group can have reached.
 let landed=false;
 for(let n=0;n<600&&!landed;n++){
  const receipt=field(await ingestMetric(api,source,{name:`${metric}_other_${n}`,at:at(20),value:1}),'cursor');
  landed=field(receipt,'group')===group;
  if(landed)expect(BigInt(String(field(receipt,'index')))).toBeGreaterThan(BigInt(index as string));
 }
 expect(landed,`no fresh series was routed to the group ${group} within 600 batches`).toBe(true);
 const beyond=`${group}:${UINT64_MAX}`;
 // Without partial results the engine refuses the whole query: the console says Error (stale) in words and shows no value.
 await page.getByLabel(/Minimum data position/).fill(beyond);
 await run(page,`{__name__=~"${metric}"}`);
 const error=page.locator('.status[data-state="error"][data-code="stale"]');
 await expect(error).toBeVisible();
 await expect(error).toContainText('Error (stale)');
 await expect(page.locator('[data-series]')).toHaveCount(0);
 // With partial results the real fence drops the group whose minimum it could not reach: the project is Partial (missing data is not zero), never Complete.
 // (The engine's completeness `stale` cannot come out of the shipped storage, whose read fence refuses or drops first; the stale answer the real server gives is the typed error above.)
 await page.getByLabel(/Allow partial results/).check();
 await run(page,`{__name__=~"${metric}.*"}`);
 const partial=page.getByTestId('results').locator(`[data-project="${project}"]`);
 await expect(partial).toHaveAttribute('data-state','incomplete');
 await expect(partial).toHaveAttribute('data-completeness','partial');
 await expect(page.locator('.status[data-state="incomplete"]')).toBeVisible();
 await expect(page.getByTestId('project-state')).not.toContainText('Complete.');
 // A malformed position is refused in the form, before any request.
 await page.getByLabel(/Minimum data position/).fill('not a cursor');
 await page.getByRole('button',{name:'Run query',exact:true}).click();
 await expect(page.getByTestId('form-problems')).toContainText('minimum data position');
});
