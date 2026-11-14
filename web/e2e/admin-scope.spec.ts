// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,login,onboardMetricSource,owner,postJson,setGrant} from './support/real';
// [05.03-W4] A REAL project deletion observed through the console against the real served process: the deletion is begun through the
// real admin route (POST /api/v1/admin/deletions), and the settings page polls the C11 contract path GET /api/v1/operations/{id}
// (no poller double). The leader-only retention worker drives the fence on its own cadence, so the operation really is `fencing` for
// a while: the page must say reads are already denied, show the confirmed/pending group counts, never use a success label, and only
// when the worker has really completed it (and erased the primary stores) show Complete, exactly once. The phases the console
// received must be monotone: fencing... then complete..., never back.
// Limit (reported): a single healthy serve cannot be made to hold ONE group unavailable from a browser; that state is driven over
// the real HTTP routes by the Go test TestRealDeletionWithOneUnavailableGroupStaysFencingThenCompletesOnce (soundpost_faults build).
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const settings=(org:string,project:string):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view:'settings'})}`;
interface Seen{phase:string;physical:string}
/** Begins one real retire_project deletion at the current admin revision; returns the operation id. */
async function begin(page:Page,org:string,project:string):Promise<string>{
 const read=await postJson(page,'/api/v1/admin/read',{kind:'organizations'});
 const revision=field(read.json,'revision');
 if(typeof revision!=='string')throw Error(`admin read: ${read.text}`);
 const command=id();
 const r=await postJson(page,'/api/v1/admin/deletions',{command_id:command,expected_revision:revision,mode:'retire_project',org_id:org,project_ids:[project],reason:'admin-scope e2e erasure'});
 if(r.status!==202)throw Error(`begin deletion: HTTP ${r.status} ${r.text}`);
 expect(field(r.json,'phase')).toBe('fencing');
 return command;
}

test('a real deletion is pending while it fences, never success early, and completes once',async({page})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'admin scope deletion org');
 const project=await createProject(page,org);
 // The administrator also reads the project (telemetry.read), so the page shows the source before and "not found" after.
 const me=field(await (await page.request.get('/api/v1/session')).json() as unknown,'user');
 if(typeof me!=='string')throw Error('no session user');
 await adminCommand(page,org,'membership',{user_id:me,enabled:true});
 await setGrant(page,org,me,project,true);
 const source=await onboardMetricSource(page,org,project);
 await page.goto(`/${settings(org,project)}`);
 await expect(page.locator(`[data-project="${project}"]`)).toContainText(source.id);

 const phases:Seen[]=[];
 page.on('response',async(r)=>{
  if(!r.url().includes('/api/v1/operations/')||r.status()!==200)return;
  const body:unknown=await r.json().catch(()=>null);
  const phase=field(body,'phase'),physical=field(body,'physical');
  if(typeof phase==='string')phases.push({phase,physical:typeof physical==='string'?physical:''});
 });
 const operation=await begin(page,org,project);
 // The page the person is on: the project they were reading is now denied, the same as a project that never existed.
 await page.reload();
 await expect(page.locator('[data-state="unauthorized"]').first()).toBeVisible();
 await page.getByLabel('Operation ID',{exact:true}).fill(operation);
 await page.getByRole('button',{name:'Show progress',exact:true}).click();
 const panel=page.getByTestId('operation');
 await expect(panel).toBeVisible();
 // Whatever the worker has done by now, the words never claim success before complete + erased.
 const early=await panel.getAttribute('data-phase');
 if(early==='fencing'){
  await expect(panel).toContainText('Pending (fencing)');
  await expect(panel).toContainText('Reads of the affected data are already denied, but the fence is not complete');
  await expect(panel).toContainText('This is not success, and nothing has been erased yet');
  await expect(panel).not.toContainText('Complete.');
 }
 // The real worker completes it (fence 64/64, then the physical pass); the console shows the success label only then.
 await expect(panel.locator('strong')).toHaveText('Complete.',{timeout:180_000});
 await expect(panel).toContainText('physical erasure of the primary stores are done');
 await expect(panel).toHaveAttribute('data-phase','complete');
 // The projected phases never went backwards and ended complete: fencing* then complete*.
 const order=phases.map((p)=>p.phase);
 const firstComplete=order.indexOf('complete');
 expect(firstComplete).toBeGreaterThanOrEqual(0);
 expect(order.slice(0,firstComplete).every((p)=>p==='fencing')).toBe(true);
 expect(order.slice(firstComplete).every((p)=>p==='complete')).toBe(true);
 // A complete answer before physical erasure (physical pending) is labelled "Logically complete", never "Complete": only the last answer is both.
 expect(phases.at(-1)?.physical).toBe('done');
 // The retired project stays denied.
 await page.reload();
 await expect(page.locator('[data-state="unauthorized"]').first()).toBeVisible();
});
