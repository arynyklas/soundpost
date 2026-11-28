// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type APIRequestContext,type Browser,type Page,type Request,type Response} from '@playwright/test';
import {at,createOrg,createProject,createReader,csrf,login,owner,setGrant,type Reader} from './support/real';
import {onboardSpanSource,seedTraces,type TraceSeed} from './support/trace';
// Real server, real Chrome. A reader opens a trace DETAIL page (the real POST /api/v1/traces/view read), then the owner revokes the
// reader's access for real (a grant revoke, or disabling the membership which kills the session) while the page stays open. The open
// page must clear its content at the next revalidation and no further read may succeed. Nothing here fakes a server answer.
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
interface World{org:string;project:string;owners:Page;api:APIRequestContext;reader:Reader;seed:TraceSeed;browser:Browser}
const hashFor=(w:World):string=>`#${new URLSearchParams({org:w.org,projects:w.project,start:String(at(0)),end:String(at(70)),tz:'UTC',view:'traces',target:`${w.project}:${w.seed.clean.trace}`})}`;

async function world(browser:Browser):Promise<World>{
 const o=owner();
 const owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 const org=await createOrg(owners,'revocation detail e2e org'),project=await createProject(owners,org,'revocation detail project');
 const reader=await createReader(owners,org,[project]);
 const api=await pwRequest.newContext();
 const seed=await seedTraces(api,await onboardSpanSource(owners,org,project));
 return {org,project,owners,api,reader,seed,browser};
}
/** A reader with the trace detail open and fully rendered; every traces/view request and answer it makes is recorded. */
async function openDetail(w:World):Promise<{page:Page;requests:Request[];answers:Response[]}> {
 const page=await (await w.browser.newContext()).newPage();
 await login(page,w.reader.email,w.reader.password);
 const requests:Request[]=[],answers:Response[]=[];
 page.on('request',(r)=>{if(r.url().endsWith('/api/v1/traces/view'))requests.push(r);});
 page.on('response',(r)=>{if(r.url().endsWith('/api/v1/traces/view'))answers.push(r);});
 await page.goto(`/${hashFor(w)}`);
 await expect(page.getByRole('heading',{name:/^Trace /})).toBeVisible();
 await expect(page.getByTestId('critical-path')).toBeVisible();
 expect(answers.length).toBeGreaterThan(0);
 expect(answers.every((a)=>a.status()===200)).toBe(true);
 return {page,requests,answers};
}
/** The exact body of the page's own trace read, replayed as the cookie session the page holds (no new fixture, no guessed shape). */
async function replay(page:Page,request:Request):Promise<{status:number;text:string}> {
 const token=await page.request.get(`${origin}/api/v1/session`).then(async(r)=>r.status()===200?csrf(page):'');
 const r=await page.request.post(`${origin}/api/v1/traces/view`,{headers:{Origin:origin,'Content-Type':'application/json',...(token?{'X-CSRF-Token':token}:{})},data:request.postData()??''});
 return {status:r.status(),text:await r.text()};
}

test('a grant revoked while a trace detail page is open clears the page at the next revalidation and no further read succeeds',async({browser})=>{
 test.setTimeout(240_000);
 const w=await world(browser);
 const {page,requests,answers}=await openDetail(w);
 const readsBefore=requests.length;
 // The owner REVOKES the reader's telemetry.read grant for real while the detail stays open.
 await setGrant(w.owners,w.org,w.reader.id,w.project,false);
 // The next revalidation is the console's own (a window focus returning to the open page after it lost focus): it re-reads the scope and remounts the view.
 await page.evaluate(()=>{window.dispatchEvent(new Event('blur'));window.dispatchEvent(new Event('focus'));});
 await expect(page.getByTestId('critical-path')).toHaveCount(0);
 await expect(page.getByText('Not found').first()).toBeVisible();
 await expect(page.locator('main')).not.toContainText(w.seed.clean.frontend);
 await expect(page.locator('table.path-table')).toHaveCount(0);
 // The reads made after the revocation were all refused (the typed not-found), none succeeded.
 await expect.poll(()=>answers.length).toBeGreaterThan(readsBefore);
 for(const a of answers.slice(readsBefore))expect([404,403],`${a.status()} ${await a.text()}`).toContain(a.status());
 // And the same exact read replayed now is refused by the server: nothing of the trace is released.
 const again=await replay(page,requests[0]!);
 expect([404,403],again.text).toContain(again.status);
 expect(again.text).not.toContain(w.seed.clean.frontend);
 expect(again.text).not.toContain(w.seed.clean.api);
});

test('a session revoked in another tab while a trace detail page is open ends the page at the next revalidation and no further read succeeds',async({browser})=>{
 test.setTimeout(240_000);
 const w=await world(browser);
 const {page,requests,answers}=await openDetail(w);
 const readsBefore=answers.length;
 // The reader signs out in ANOTHER tab of the same browser: the server session behind the open detail page is revoked.
 const other=await page.context().newPage();
 await other.goto('/');
 await other.getByRole('button',{name:'Sign out',exact:true}).click();
 await expect(other.getByRole('heading',{name:'Access your installation'})).toBeVisible();
 // The console checks its session every five seconds: the open page ends at the sign-in form without any user action.
 await expect(page.getByRole('heading',{name:'Access your installation'})).toBeVisible({timeout:30_000});
 await expect(page.getByTestId('critical-path')).toHaveCount(0);
 await expect(page.locator('body')).not.toContainText(w.seed.clean.frontend);
 expect(answers.slice(readsBefore).every((a)=>a.status()!==200)).toBe(true);
 expect((await page.request.get(`${origin}/api/v1/session`)).status()).toBe(401);
 const again=await replay(page,requests[0]!);
 expect([401,403,404],again.text).toContain(again.status);
 expect(again.text).not.toContain(w.seed.clean.frontend);
});
