// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect} from '@playwright/test';
import {createOrg,createProject,login,owner,reopen} from './support/real';
// The session boundary revalidates on every focus / hashchange / popstate. A still valid session keeps the mounted console and its view state (a settings tab the
// user selected while the revalidation was in flight survives it); a revoked session still clears the console.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const settings=(org:string,project:string):string=>`#${new URLSearchParams({org,projects:project,start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000),tz:'UTC',view:'settings',page:'project'})}`;

test('a settings tab selected during a focus revalidation survives it, and a revoked session then clears the console',async({page})=>{
 test.setTimeout(180_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'revalidation org');
 const project=await createProject(page,org);
 await reopen(page,`/${settings(org,project)}`);
 await expect(page.locator('[data-settings-tab="project"]')).toBeVisible();

 // Hold the session read of the revalidation open, click the tab while it is in flight, then let it answer.
 const gate=Promise.withResolvers<void>();
 let held=0;
 await page.route('**/api/v1/session',async(route)=>{held++;await gate.promise;await route.continue();});
 await page.evaluate(()=>{window.dispatchEvent(new Event('blur'));window.dispatchEvent(new Event('focus'));window.dispatchEvent(new HashChangeEvent('hashchange'));});
 await expect.poll(()=>held).toBeGreaterThan(0);
 await expect(page.getByText('Revalidating access…')).toHaveCount(0);
 await page.locator('[data-settings-tab="teams"]').click();
 await expect(page.locator('[data-settings-page="teams"]')).toBeVisible();
 gate.resolve();
 await page.evaluate(()=>new Promise<void>((done)=>{window.setTimeout(done,800);}));
 await expect(page.locator('[data-settings-page="teams"]')).toBeVisible();
 await expect(page.getByText('Revalidating access…')).toHaveCount(0);
 await page.unroute('**/api/v1/session');

 // A revoked session clears the console.
 await page.route('**/api/v1/session',(route)=>route.fulfill({status:401,body:'{}',contentType:'application/json'}));
 await page.evaluate(()=>{window.dispatchEvent(new Event('focus'));});
 await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible();
 await expect(page.locator('[data-settings-page="teams"]')).toHaveCount(0);
 await expect(page.locator('.console')).toHaveCount(0);
});
