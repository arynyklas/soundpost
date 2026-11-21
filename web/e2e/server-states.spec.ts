// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest} from '@playwright/test';
import {at,createOrg,createProject,createReader,faultControl,ingestMetric,login,onboardMetricSource,owner,removeShards} from './support/real';
import {auditDom} from './support/audit';

// 05.09-W3: the `error` load state produced by the SERVER, not by a request the browser rewrote. The server under test is built with
// -tags soundpost_faults (E2E_FAULTS=1 h.sh prep) and closes the replica groups of chosen data slots on request; with every shard gone the
// real query route refuses a query that does not opt in to partial results with its own non-2xx fault, and the real page says so. Nothing in
// this spec routes, rewrites or fulfils a request. The removal is irreversible for the server, so this spec owns its server:
// `E2E_FAULTS=1 h.sh prep; h.sh run pw no e2e/server-states.spec.ts`.
// `rate_limited` and `stale` are produced from the real server in console-states.spec.ts (the elevation read throttle answers 429 rate_limited; a
// minimum data position the read has not reached is refused `stale`), which does not remove shards and shares a server.
test.skip(!faultControl(),'needs a server built with -tags soundpost_faults (E2E_FAULTS=1) and a server of its own: shards are removed for good');

test('with every shard removed the query route refuses and the page says Error in words, announced assertively, with a clean audit and no value',async({browser})=>{
 test.setTimeout(240_000);
 const o=owner();
 const admin=await (await browser.newContext()).newPage();
 await login(admin,o.email,o.password);
 const api=await pwRequest.newContext();
 const org=await createOrg(admin,'server states org'),p1=await createProject(admin,org,'server states project');
 const reader=await createReader(admin,org,[p1]);
 const source=await onboardMetricSource(admin,org,p1);
 for(let i=0;i<8;i++)await ingestMetric(api,source,{name:`state_s${i}`,at:at(10),value:i+1});
 const page=await (await browser.newContext()).newPage();
 await login(page,reader.email,reader.password);
 const link=`/#${new URLSearchParams({org,projects:p1,start:String(at(0)),end:String(at(70)),tz:'UTC',view:'explore'})}`;
 const run=async(expression:string):Promise<void>=>{
  await page.getByLabel('Query expression').fill(expression);
  await page.getByRole('button',{name:'Run query',exact:true}).click();
 };

 // The control: before the loss the same query is ready and shows the ingested values.
 await page.goto(link);
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 await run('{__name__=~"state_s.+"}');
 await expect(page.getByTestId('results').locator(`[data-project="${p1}"]`)).toHaveAttribute('data-state','ready');
 await expect(page.locator('.status[data-state="error"]')).toHaveCount(0);

 expect(await removeShards(Array.from({length:64},(_,i)=>i))).toBe(64);
 const answered=page.waitForResponse((r)=>r.url().endsWith('/api/v1/query')&&r.request().method()==='POST');
 // A new expression: a settled answer of the same one could be served from the result cache without touching a shard.
 await run('{__name__=~"state_s[0-3]"}');
 await answered;
 const status=page.locator('.status[data-state="error"]').first();
 await expect(status).toBeVisible();
 expect((await status.locator('strong').first().innerText()).trim()).toMatch(/^Error/);
 await expect(status).toHaveAttribute('role','alert');
 await expect(status).toHaveAttribute('aria-live','assertive');
 expect((await status.innerText()).trim().length).toBeGreaterThan(20);
 await expect(page.locator('[data-series]')).toHaveCount(0);
 await expect(page.locator('[data-kind]')).toHaveCount(0);
 const found=await auditDom(page);
 expect(found,JSON.stringify(found)).toEqual([]);
});
