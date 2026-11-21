// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type APIRequestContext,type Browser,type Page,type Request} from '@playwright/test';
import {at,createOrg,createProject,createReader,ingestLog,login,onboardLogSource,owner,setGrant,type Reader,type Source} from './support/real';
// Real server, real Chrome, REAL data admitted through the real ingest route, a REAL revoke of the reader mid-stream.
// The live view is a fetch-based server-sent-event stream (a GET with a one-use ticket in the URL, the CSRF header and
// Last-Event-ID), opened and resumed only by explicit clicks. Nothing here fakes a server answer.
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
interface World{org:string;project:string;admin:Page;api:APIRequestContext;source:Source;browser:Browser}
const hashFor=(org:string,project:string):string=>`#${new URLSearchParams({org,projects:project,start:String(at(0)),end:String(at(70)),tz:'UTC',view:'explore'})}`;

async function world(browser:Browser):Promise<World>{
 const o=owner();
 const admin=await (await browser.newContext()).newPage();
 await login(admin,o.email,o.password);
 const org=await createOrg(admin,'live e2e org'),project=await createProject(admin,org,'live project');
 const source=await onboardLogSource(admin,org,project,{names:Array.from({length:12},(_,i)=>`user${i}`)});
 return {org,project,admin,api:await pwRequest.newContext(),source,browser};
}
async function readerPage(w:World,reader:Reader):Promise<Page>{
 const page=await (await w.browser.newContext()).newPage();
 await login(page,reader.email,reader.password);
 await page.goto(`/${hashFor(w.org,w.project)}`);
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 return page;
}
/** Selects LogQL, types the query, opens the live view and starts it: three explicit clicks, nothing automatic. */
async function startLive(page:Page,expression:string):Promise<void>{
 await page.getByRole('radio',{name:'LogQL',exact:true}).check();
 await page.getByLabel('Query expression').fill(expression);
 await page.getByRole('button',{name:'Open the live log view for this query',exact:true}).click();
 await page.getByRole('button',{name:'Start live view',exact:true}).click();
 await expect(page.getByTestId('live-status')).toContainText('Live: connected to stream');
}
const rows=(page:Page)=>page.locator('[data-row]');
async function lineAt(w:World,seconds:number,name:string):Promise<void>{await ingestLog(w.api,w.source,{at:at(seconds),name});}

test('a real revoke of the reader mid-stream ends the view and clears every buffered row',async({browser})=>{
 test.setTimeout(240_000);
 const w=await world(browser);
 const reader=await createReader(w.admin,w.org,[w.project]);
 const page=await readerPage(w,reader);
 const gets:Request[]=[],tickets:Request[]=[];
 page.on('request',(r)=>{if(r.url().includes('/api/v1/live?'))gets.push(r);if(r.url().endsWith('/api/v1/live-tickets'))tickets.push(r);});
 await startLive(page,'{app="web"}');
 await expect(page.getByTestId('live-rows')).toHaveText('0');
 await lineAt(w,1,'user0');await lineAt(w,2,'user1');await lineAt(w,3,'user2');
 await expect(rows(page)).toHaveCount(3);
 await expect(rows(page).first()).toContainText('user0');
 expect(gets).toHaveLength(1);
 expect(tickets).toHaveLength(1);
 const headers=await gets[0]!.allHeaders();
 expect(gets[0]!.url()).toBe(`${origin}/api/v1/live?ticket=${new URL(gets[0]!.url()).searchParams.get('ticket')}`);
 expect(headers['x-csrf-token']).toBeTruthy();
 // The owner REVOKES the reader's grant while the stream is open.
 await expect(page.getByTestId('live-status')).toContainText('Live: connected');
 await setGrant(w.admin,w.org,reader.id,w.project,false);
 await expect(page.locator('[data-end="revoked"]')).toBeVisible({timeout:30_000});
 await expect(page.locator('[data-end="revoked"]')).toContainText('Every buffered row was cleared');
 await expect(rows(page)).toHaveCount(0);
 await expect(page.getByTestId('live-rows')).toHaveText('0');
 await expect(page.getByTestId('live-empty')).toHaveText('Nothing is shown.');
 expect(await page.locator('.live-items').count()).toBe(0);
 // More real lines are committed after the revoke: not one of them is rendered, and the stream is not read again.
 await lineAt(w,4,'user3');await lineAt(w,5,'user4');
 await page.waitForTimeout(2500);
 await expect(rows(page)).toHaveCount(0);
 expect(await page.locator('.investigation').innerText()).not.toMatch(/user[0-4]/);
 expect(gets).toHaveLength(1);
 expect(tickets).toHaveLength(1);
 // The revoked reader cannot start again: the server answers Not found and nothing is shown.
 await page.getByRole('button',{name:'Start a new live view',exact:true}).click();
 await expect(page.locator('[data-end="refused"]')).toContainText('Not found');
 await expect(rows(page)).toHaveCount(0);
});

test('a resume inside the replay window continues exactly after Last-Event-ID; after the window an explicit replay_expired gap is shown',async({browser})=>{
 test.setTimeout(300_000);
 const w=await world(browser);
 const reader=await createReader(w.admin,w.org,[w.project]);
 const page=await readerPage(w,reader);
 const gets:Request[]=[],tickets:Request[]=[];
 page.on('request',(r)=>{if(r.url().includes('/api/v1/live?'))gets.push(r);if(r.url().endsWith('/api/v1/live-tickets'))tickets.push(r);});
 await startLive(page,'{app="web"}');
 for(const [s,n] of [[1,'user0'],[2,'user1'],[3,'user2']] as const)await lineAt(w,s,n);
 await expect(rows(page)).toHaveCount(3);
 await page.getByRole('button',{name:'Stop live view',exact:true}).click();
 await expect(page.locator('[data-end="stopped"]')).toContainText('Stopped by you');
 await expect(rows(page)).toHaveCount(3);
 // Two more real lines are committed while nothing is connected: the server retains them for the 60-second replay window.
 await lineAt(w,4,'user3');await lineAt(w,5,'user4');
 await page.getByRole('button',{name:'Resume after sequence 3',exact:true}).click();
 await expect(rows(page)).toHaveCount(5);
 expect(await rows(page).evaluateAll((els)=>els.map((e)=>e.getAttribute('data-sequence')))).toEqual(['1','2','3','4','5']);
 await expect(page.getByTestId('live-gaps')).toHaveText('0');
 await expect(page.getByTestId('live-status')).not.toContainText('retained stream had expired');
 expect(gets).toHaveLength(2);
 expect((await gets[1]!.allHeaders())['last-event-id']).toBe('3');
 expect((await gets[0]!.allHeaders())['last-event-id']).toBeUndefined();
 const first=tickets[0]!.postDataJSON() as {resume_stream_id?:string},second=tickets[1]!.postDataJSON() as {resume_stream_id?:string};
 expect(first.resume_stream_id).toBeUndefined();
 expect(second.resume_stream_id).toMatch(/^[0-9a-f]{32}$/);
 // Stop again and stay away longer than the 60-second replay window; a line committed meanwhile is never delivered.
 await page.getByRole('button',{name:'Stop live view',exact:true}).click();
 await expect(page.locator('[data-end="stopped"]')).toBeVisible();
 await lineAt(w,6,'user5');
 await page.waitForTimeout(66_000);
 await page.getByRole('button',{name:'Resume after sequence 5',exact:true}).click();
 await expect(page.getByTestId('live-status')).toContainText('The retained stream had expired');
 const gap=page.locator('[data-gap][data-reason="replay_expired"]');
 await expect(gap).toHaveCount(1);
 await expect(gap).toHaveAttribute('data-from','6');
 await expect(gap).toHaveAttribute('data-to','6');
 await expect(page.getByTestId('live-gaps')).toHaveText('1');
 await lineAt(w,7,'user6');
 await expect(rows(page)).toHaveCount(6);
 await expect(rows(page).last()).toContainText('user6');
 expect(await page.locator('.live-items').innerText()).not.toContain('user5');
 expect((await gets[2]!.allHeaders())['last-event-id']).toBe('5');
 expect(tickets).toHaveLength(3);
});
