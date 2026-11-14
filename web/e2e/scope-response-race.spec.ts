// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {randomBytes} from 'node:crypto';
// Real server, real browser. A real investigate response for organization A is held
// in the network layer (fetched from the real server, fulfilled late) while the
// browser navigates to organization B: A's late completion must never paint.
const email=process.env.SOUNDPOST_SCOPE_EMAIL;
const password=process.env.SOUNDPOST_SCOPE_PASSWORD;
if(!email||!password)throw new Error('A real provisioned MFA-free instance-admin account (SOUNDPOST_SCOPE_EMAIL, SOUNDPOST_SCOPE_PASSWORD) is required');
const id=():string=>randomBytes(16).toString('hex');
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
// The control revision also advances under the runner's own commits (producers), so a command read at revision N can land
// at N+1: that 409 is retried with a fresh revision, exactly as support/real.ts adminCommand does; any other status fails.
async function command(page:Page,org:string,kind:string,payload:Record<string,unknown>):Promise<void>{
 for(let attempt=0;;attempt++){
  const session=await (await page.request.get('/api/v1/session')).json() as {csrf:string};
  const read=await page.request.post('/api/v1/admin/read',{headers:{'X-CSRF-Token':session.csrf,Origin:origin},data:{kind:'organizations'}});
  expect(read.ok()).toBe(true);
  const {revision}=await read.json() as {revision:string};
  const response=await page.request.post('/api/v1/admin/commands',{headers:{'X-CSRF-Token':session.csrf,Origin:origin},data:{command_id:id(),expected_revision:revision,org_id:org,kind,payload:{...payload,reason:'Generic scope race acceptance'}}});
  if(response.status()===409&&attempt<4)continue;
  expect(response.status(),`${kind}`).toBeLessThan(300);
  return;
 }
}
const hashFor=(org:string,project:string,service:string):string=>`#${new URLSearchParams({org,projects:project,start:'1700000000000000000',end:'1700003600000000000',tz:'UTC',view:'services',service})}`;
test('a stale response for the previous scope never paints after navigation',async({page})=>{
 test.setTimeout(90_000);
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Account access',exact:true})).toBeVisible();
 const user=(await (await page.request.get('/api/v1/session')).json() as {user:string}).user;
 const orgA=id(),orgB=id(),projectA=id(),projectB=id(),service=id();
 for(const [org,project] of [[orgA,projectA],[orgB,projectB]] as const){
  await command(page,org,'create_org',{id:org,name:'scope race'});
  await command(page,org,'create_project',{id:project,name:'project'});
  await command(page,org,'membership',{user_id:user,enabled:true});
  await command(page,org,'grant',{user_id:user,project_id:project,enabled:true,permissions:['telemetry.read']});
 }
 let release=():void=>{};
 const barrier=new Promise<void>((resolve)=>{release=resolve;});
 let heldA=0,servedA=Promise.resolve();
 await page.route('**/api/v1/investigate',async(route)=>{
  const body=route.request().postDataJSON() as {org:string};
  if(body.org!==orgA||heldA>0){await route.continue();return;}
  heldA++;
  const real=await route.fetch();
  servedA=(async()=>{await barrier;await route.fulfill({response:real});})();
  await servedA;
 });
 await page.goto(`/${hashFor(orgA,projectA,service)}`);
 await expect(page.getByTestId('visible-org')).toHaveText(orgA);
 await expect(page.getByRole('status').filter({hasText:'Loading'})).toBeVisible();
 // Navigate to B while A is still held.
 await page.evaluate((hash)=>{location.hash=hash;},hashFor(orgB,projectB,service));
 await expect(page.getByTestId('visible-org')).toHaveText(orgB);
 await expect(page.locator('[data-state="empty"], [data-state="incomplete"]').first()).toBeVisible();
 await expect(page.getByText(`Project ${projectB}`)).toBeVisible();
 // Now let A's real response complete late.
 release();await servedA;await page.waitForTimeout(500);
 await expect(page.getByTestId('visible-org')).toHaveText(orgB);
 const text=await page.locator('.investigation').innerText();
 expect(text).not.toContain(orgA);
 expect(text).not.toContain(projectA);
 expect(text).toContain(projectB);
 // Back restores A's scope from the URL alone, with a fresh read of A; forward returns to B.
 await page.goBack();
 await expect(page.getByTestId('visible-org')).toHaveText(orgA);
 expect(page.url()).toContain(`org=${orgA}`);
 await expect(page.getByText(`Project ${projectA}`)).toBeVisible();
 expect(await page.locator('.investigation').innerText()).not.toContain(projectB);
 await page.goForward();
 await expect(page.getByTestId('visible-org')).toHaveText(orgB);
 await expect(page.getByText(`Project ${projectB}`)).toBeVisible();
 expect(page.url()).not.toMatch(/query|expression|token|csrf/i);
 expect(await page.evaluate(()=>({local:Object.keys(localStorage),session:Object.keys(sessionStorage)}))).toEqual({local:[],session:[]});
});
