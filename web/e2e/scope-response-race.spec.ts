// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {randomBytes} from 'node:crypto';
import {barrierProxy} from './support/barrier';
import {adminCommand,field,onboardMetricSource} from './support/real';
// Real server, real browser. A real investigate response for organization A is held
// in the network layer (fetched from the real server, fulfilled late) while the
// browser navigates to organization B: A's late completion must never paint.
const email=process.env.SOUNDPOST_SCOPE_EMAIL;
const password=process.env.SOUNDPOST_SCOPE_PASSWORD;
if(!email||!password)throw new Error('A real provisioned MFA-free instance-admin account (SOUNDPOST_SCOPE_EMAIL, SOUNDPOST_SCOPE_PASSWORD) is required');
const id=():string=>randomBytes(16).toString('hex');
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
// The control revision also advances under the runner's own commits (producers), so a command read at revision N can land
// at N+1: the shared fixture (support/real.ts adminCommand) retries that race for up to a minute; any other status fails.
async function command(page:Page,org:string,kind:string,payload:Record<string,unknown>):Promise<void>{
 await adminCommand(page,org,kind,payload,'Generic scope race acceptance');
}
// The service list of the selected scope: a service ID chosen at random is no longer "unconfirmable" but not found (D9), and a not-found
// answer is not the state this spec drives.
const hashFor=(org:string,project:string):string=>`#${new URLSearchParams({org,projects:project,start:'1700000000000000000',end:'1700003600000000000',tz:'UTC',view:'services'})}`;
test('a stale response for the previous scope never paints after navigation',async({page})=>{
 test.setTimeout(90_000);
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{level:1,name:'Home',exact:true})).toBeVisible();
 const user=(await (await page.request.get('/api/v1/session')).json() as {user:string}).user;
 const orgA=id(),orgB=id(),projectA=id(),projectB=id();
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
 await page.goto(`/${hashFor(orgA,projectA)}`);
 await expect(page.getByTestId('visible-org')).toHaveText(orgA);
 await expect(page.getByRole('status').filter({hasText:'Loading'})).toBeVisible();
 // Navigate to B while A is still held.
 await page.evaluate((hash)=>{location.hash=hash;},hashFor(orgB,projectB));
 await expect(page.getByTestId('visible-org')).toHaveText(orgB);
 await expect(page.locator('[data-state="empty"], [data-state="incomplete"]').first()).toBeVisible();
 await expect(page.getByText(`Project ${projectB}`)).toBeVisible();
 // Now let A's real response complete late.
 release();await servedA;await page.waitForTimeout(500);
 await expect(page.getByTestId('visible-org')).toHaveText(orgB);
 const text=await page.locator('main').innerText();
 expect(text).not.toContain(orgA);
 expect(text).not.toContain(projectA);
 expect(text).toContain(projectB);
 // Back restores A's scope from the URL alone, with a fresh read of A; forward returns to B.
 await page.goBack();
 await expect(page.getByTestId('visible-org')).toHaveText(orgA);
 expect(page.url()).toContain(`org=${orgA}`);
 await expect(page.getByText(`Project ${projectA}`)).toBeVisible();
 expect(await page.locator('main').innerText()).not.toContain(projectB);
 await page.goForward();
 await expect(page.getByTestId('visible-org')).toHaveText(orgB);
 await expect(page.getByText(`Project ${projectB}`)).toBeVisible();
 expect(page.url()).not.toMatch(/query|expression|token|csrf/i);
 expect(await page.evaluate(()=>({local:Object.keys(localStorage),session:Object.keys(sessionStorage)}))).toEqual({local:[],session:[]});
});

// The stale-response guard of the investigation hook (abort plus latest-only, src/app/context.ts) in a real browser, WITHOUT a remount:
// the console remounts the whole app on every address change, so navigation cannot show the guard. Refreshing the SAME scope
// changes only the hook's key (the generation), nothing remounts, and the first read is still in flight. Its late answer must neither
// paint nor replace the newer read's state; if the guard is removed the late answer parks the held state on an old key and the view
// is stuck on "Loading".
test('a late answer of a superseded read does not replace the newer read when the same scope is read again without a remount',async({page})=>{
 test.setTimeout(90_000);
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{level:1,name:'Home',exact:true})).toBeVisible();
 const user=(await (await page.request.get('/api/v1/session')).json() as {user:string}).user;
 const org=id(),project=id();
 await command(page,org,'create_org',{id:org,name:'guard without remount'});
 await command(page,org,'create_project',{id:project,name:'project'});
 await command(page,org,'membership',{user_id:user,enabled:true});
 await command(page,org,'grant',{user_id:user,project_id:project,enabled:true,permissions:['telemetry.read']});
 let release=():void=>{};
 const barrier=new Promise<void>((resolve)=>{release=resolve;});
 let held=0,served=Promise.resolve();
 const sent:number[]=[];
 await page.route('**/api/v1/investigate',async(route)=>{
  // The list's own read names no target; the health read of each listed service (a row's figures) names one and is not what is counted here.
  if((route.request().postDataJSON() as {target?:string}).target!==undefined){await route.continue();return;}
  sent.push(Date.now());
  if(held>0){await route.continue();return;}
  held++;
  const real=await route.fetch();
  served=(async()=>{await barrier;await route.fulfill({response:real}).catch(()=>undefined);})();
  await served;
 });
 await page.goto(`/${hashFor(org,project)}`);
 await expect(page.getByTestId('visible-org')).toHaveText(org);
 await expect(page.getByRole('status').filter({hasText:'Loading'})).toBeVisible();
 expect(sent).toHaveLength(1);
 // While the first read is held, the organization changes: a source is onboarded, so the newer read's answer DIFFERS from the held one
 // (it lists the source's service, the held one cannot). A late stale answer that replaced it would be visible, not merely a different spinner.
 const source=await onboardMetricSource(page,org,project);
 const row=page.locator(`[data-testid=service-row][data-service="${source.service}"]`);
 await expect(row).toHaveCount(0);
 // Refresh re-reads the same scope: same address, so no hashchange and no remount; the hook starts a second read under a new generation.
 await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(row).toHaveCount(1);
 expect(sent).toHaveLength(2);
 await expect(page.getByRole('status').filter({hasText:'Loading'})).toHaveCount(0);
 // Now the first read's real answer (computed before the source existed) arrives late.
 release();await served;await page.waitForTimeout(750);
 await expect(page.getByRole('status').filter({hasText:'Loading'})).toHaveCount(0);
 await expect(row).toHaveCount(1);
 await expect(page.getByTestId('visible-org')).toHaveText(org);
 expect(sent).toHaveLength(2);
});

// The same race with a SERVER-SIDE delay: the real server computes organization A's real answer, and a fault barrier on the network path
// (support/barrier.ts, a reverse proxy in front of the real server, not the browser's own network layer) holds that answer on the wire
// while the browser navigates to organization B. Run headed (`h.sh headed`) for the smoke; it passes headless too.
test('a real answer held on the server side of the wire never paints in a later scope, and back and forward keep the scope',async({page})=>{
 test.setTimeout(120_000);
 const pki=process.env.E2E_PKI;
 if(!pki)throw new Error('E2E_PKI (the directory of the private leaf certificate the real server uses) is required for the fault barrier');
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(email);await page.getByLabel('Password',{exact:true}).fill(password);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{level:1,name:'Home',exact:true})).toBeVisible();
 const user=(await (await page.request.get('/api/v1/session')).json() as {user:string}).user;
 const orgA=id(),orgB=id(),projectA=id(),projectB=id();
 for(const [org,project] of [[orgA,projectA],[orgB,projectB]] as const){
  await command(page,org,'create_org',{id:org,name:'server side barrier'});
  await command(page,org,'create_project',{id:project,name:'project'});
  await command(page,org,'membership',{user_id:user,enabled:true});
  await command(page,org,'grant',{user_id:user,project_id:project,enabled:true,permissions:['telemetry.read']});
 }
 let heldA=0;
 const barrier=await barrierProxy(origin,pki,(path,body)=>{
  if(path!=='/api/v1/investigate'||field(JSON.parse(body),'org')!==orgA||heldA>0)return false;
  heldA++;
  return true;
 });
 try{
  await page.goto(`${barrier.origin}/${hashFor(orgA,projectA)}`);
  await expect(page.getByTestId('visible-org')).toHaveText(orgA);
  await expect(page.getByRole('status').filter({hasText:'Loading'})).toBeVisible();
  // The real server has answered (the barrier holds that answer); the browser has nothing to show for A.
  await expect.poll(()=>barrier.held(),{message:'the real answer for A is held on the wire'}).toBe(1);
  await page.evaluate((hash)=>{location.hash=hash;},hashFor(orgB,projectB));
  await expect(page.getByTestId('visible-org')).toHaveText(orgB);
  await expect(page.locator('[data-state="empty"], [data-state="incomplete"]').first()).toBeVisible();
  await expect(page.getByText(`Project ${projectB}`)).toBeVisible();
  expect(barrier.held()).toBe(1);
  // The held answer reaches the browser late: it must not paint or change the scope.
  barrier.release();
  await expect.poll(()=>barrier.held()).toBe(0);
  await page.waitForTimeout(500);
  await expect(page.getByTestId('visible-org')).toHaveText(orgB);
  const text=await page.locator('main').innerText();
  expect(text).not.toContain(orgA);
  expect(text).not.toContain(projectA);
  expect(text).toContain(projectB);
  // Back restores A's scope from the address alone with a fresh read of A (no longer held); forward returns to B.
  await page.goBack();
  await expect(page.getByTestId('visible-org')).toHaveText(orgA);
  expect(page.url()).toContain(`org=${orgA}`);
  await expect(page.getByText(`Project ${projectA}`)).toBeVisible();
  expect(await page.locator('main').innerText()).not.toContain(projectB);
  await page.goForward();
  await expect(page.getByTestId('visible-org')).toHaveText(orgB);
  await expect(page.getByText(`Project ${projectB}`)).toBeVisible();
  expect(page.url()).not.toMatch(/query|expression|token|csrf/i);
  expect(await page.evaluate(()=>({local:Object.keys(localStorage),session:Object.keys(sessionStorage)}))).toEqual({local:[],session:[]});
 }finally{await barrier.close();}
});
