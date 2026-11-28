// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type APIRequestContext,type Page,type BrowserContext} from '@playwright/test';
import {randomBytes} from 'node:crypto';
import {adminCommand,field,ingestError,onboardErrorSource,postJson} from './support/real';
import {auditDom} from './support/audit';
// Two real browsers, one real server, one REAL incident produced the product's own way: an error occurrence ingested through
// POST /ingest/v1/batches with a real source credential -> the leader-only background runner (`soundpost serve`, issue producer, then
// incident producer, acting as the in-process system principal) -> a system-origin incident, found through the real POST /api/v1/queue.
// Nothing seeds a route. A and B load revision 1; A assigns an owner; B acknowledges with the revision it saw:
// exactly one commit, B gets a conflict naming the current revision, nothing is retried or shown
// as committed, and B's typed reason survives until B explicitly reloads and submits again.
// What the real producer decides (and the spec asserts): an unhandled, non-fatal error opens the incident at severity major (a fatal one would
// open at critical, leaving nothing worse to report) with one impact observation, source
// firing with fresh data, no linked issue (the "What changed" card says so), delivery not available.
const email=process.env.SOUNDPOST_SCOPE_EMAIL;
const password=process.env.SOUNDPOST_SCOPE_PASSWORD;
if(!email||!password)throw new Error('A real provisioned MFA-free instance-admin account (SOUNDPOST_SCOPE_EMAIL, SOUNDPOST_SCOPE_PASSWORD) is required');
const id=():string=>randomBytes(16).toString('hex');
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
interface View{version:string;status:string;owner?:string;ack?:{actor:string;current:boolean};timeline:{type:string;actor:string;origin:string}[];source_firing:boolean}
async function csrf(page:Page):Promise<string>{return (await (await page.request.get('/api/v1/session')).json() as {csrf:string}).csrf;}
// The admin revision can move between the read and the command (the background runner commits control state too): the shared fixture retries only that race.
async function command(page:Page,org:string,kind:string,payload:Record<string,unknown>):Promise<void>{
 await adminCommand(page,org,kind,payload,'Generic incident action acceptance');
}
async function login(page:Page,who:string,secret:string):Promise<void>{
 await page.goto('/');await page.getByLabel('Email',{exact:true}).fill(who);await page.getByLabel('Password',{exact:true}).fill(secret);await page.getByRole('button',{name:'Sign in',exact:true}).click();await expect(page.getByRole('heading',{name:'Home',exact:true})).toBeVisible();
}
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
// The page window brackets "now" (an incident reads by id; the window only scopes the shell).
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const hash=(org:string,project:string,view:string,incident?:string):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view,...(incident?{incident:`${project}:${incident}`}:{})})}`;
/**
 * Ingest one fatal error for a new source of the project and wait (real queue route) until the runner has turned it into an incident;
 * returns the incident id taken from the queue.
 */
async function seed(page:Page,api:APIRequestContext,org:string,project:string):Promise<string>{
 const source=await onboardErrorSource(page,org,project);
 await ingestError(api,source,{at:nsOf(Date.now()),class:'IncidentE2eFailure',fatal:false,handled:false});
 let incident='';
 await expect.poll(async()=>{
  const r=await postJson(page,'/api/v1/queue',{org,projects:[project],limit:50});
  const entries=field(r.json,'entries');
  const first=Array.isArray(entries)?field(entries[0],'incident_id'):undefined;
  incident=typeof first==='string'?first:'';
  return incident;
 },{message:'the runner opens an incident for the ingested error',timeout:90_000,intervals:[250,500,1000]}).not.toBe('');
 return incident;
}
async function read(page:Page,org:string,project:string,incident:string):Promise<View>{
 const response=await page.request.post('/api/v1/incidents/get',{headers:{'X-CSRF-Token':await csrf(page),Origin:origin},data:{org,project_id:project,target_id:incident}});
 expect(response.status()).toBe(200);
 return await response.json() as View;
}
const outcome=(page:Page,kind:string)=>page.locator(`[data-outcome="${kind}"]`);
// Each action opens its own dialog from the incident's action bar (Report impact is in the More menu); the dialog holds the form and the outcome.
async function openAction(page:Page,action:string):Promise<void>{
 if(action==='Report impact'){await page.getByRole('button',{name:/^More actions/}).click();await page.getByRole('menuitem',{name:'Report impact',exact:true}).click();}
 else await page.getByRole('button',{name:({'Resolve':'Resolve incident','Snooze reminders':'Snooze'} as Record<string,string>)[action]??action,exact:true}).click();
 await expect(page.getByRole('dialog')).toBeVisible();
}
async function submit(page:Page,action:string):Promise<void>{await page.getByRole('dialog').getByRole('button',{name:action==='Resolve'?'Resolve incident':action,exact:true}).click();}

test('two browsers act on one real incident without a silent overwrite',async({page,browser,playwright})=>{
 test.setTimeout(240_000);
 await login(page,email,password);
 const org=id(),project=id();
 await command(page,org,'create_org',{id:org,name:'incident actions'});
 await command(page,org,'create_project',{id:project,name:'project'});
 const people:{email:string;password:string;id:string}[]=[];
 for(const name of ['alpha','bravo']){
  const p={email:`${name}-${id().slice(0,8)}@example.test`,password:`incident ${name} password 2026`,id:id()};
  await command(page,org,'create_user',{id:p.id,email:p.email,password:p.password});
  await command(page,org,'membership',{user_id:p.id,enabled:true});
  await command(page,org,'org_admin',{user_id:p.id,enabled:true});
  people.push(p);
 }
 const [alpha,bravo]=people as [typeof people[0],typeof people[0]];
 const api=await playwright.request.newContext();
 const incident=await seed(page,api,org,project);
 const open=(c:BrowserContext)=>c.newPage();
 const ctxA=await browser.newContext(),ctxB=await browser.newContext();
 const pageA=await open(ctxA),pageB=await open(ctxB);
 await login(pageA,alpha.email,alpha.password);await login(pageB,bravo.email,bravo.password);
 const url=`/${hash(org,project,'incidents',incident)}`;
 await pageA.goto(url);await pageB.goto(url);
 for(const p of [pageA,pageB]){
  await expect(p.getByTestId('revision')).toContainText('Revision 1');
  await expect(p.getByTestId('source-badge')).toHaveText('Source firing, fresh data');
 }
 // The three concerns are separate sections, each with its own words.
 for(const section of ['alert-condition','issue-workflow','incident-response'])await expect(pageA.locator(`[data-section="${section}"]`)).toBeVisible();
 await expect(pageA.locator('[data-section="issue-workflow"]')).toContainText('No error issue is linked');
 await expect(pageA.getByTestId('rate')).toContainText('Rate unknown');
 await expect(pageA.getByTestId('rate')).toContainText('1 impact observation');
 expect(await pageA.locator('main').innerText()).not.toMatch(/\b0\s*%/);

 // A assigns. While the request is held the page says pending and shows nothing as committed.
 const {promise:gate,resolve:release}=Promise.withResolvers<void>();
 await pageA.route('**/api/v1/actions',async(route)=>{await gate;await route.continue();});
 await openAction(pageA,'Assign owner');
 await expect(pageA.getByTestId('expected-version')).toHaveText('1');
 await pageA.getByRole('button',{name:'Use my user ID',exact:true}).click();
 await submit(pageA,'Assign owner');
 await expect(outcome(pageA,'pending')).toContainText('Nothing is committed yet');
 await expect(pageA.getByTestId('revision')).toContainText('Revision 1');
 await expect(pageA.getByTestId('response-words')).not.toContainText(alpha.id);
 release();
 await expect(outcome(pageA,'committed')).toContainText('revision 2');
 await pageA.unroute('**/api/v1/actions');
 await expect(pageA.getByTestId('revision')).toContainText('Revision 2');
 await expect(pageA.getByTestId('response-words')).toContainText(`Owner ${alpha.id}`);

 // B, still looking at revision 1, acknowledges with expected revision 1: it loses.
 const typed='<img src=x onerror="window.__pwn=1"> B is on it & looking';
 await expect(pageB.getByTestId('revision')).toContainText('Revision 1');
 await openAction(pageB,'Acknowledge');
 await pageB.getByLabel('Reason (optional)').fill(typed);
 await submit(pageB,'Acknowledge');
 await expect(outcome(pageB,'conflict')).toBeFocused();
 await expect(pageB.locator('[data-conflict="current"]')).toContainText('Conflict: not applied');
 await expect(pageB.getByTestId('current-version')).toHaveText('2');
 await expect(pageB.getByTestId('revision')).toContainText('Revision 1');
 await expect(pageB.getByTestId('ack-source-firing')).toHaveCount(0);
 await expect(pageB.getByLabel('Reason (optional)')).toHaveValue(typed);
 // Exactly one commit: the server holds A's assignment only, with no ACK and no hidden retry.
 const afterConflict=await read(pageB,org,project,incident);
 expect([afterConflict.version,afterConflict.owner,afterConflict.ack,afterConflict.timeline.map((e)=>e.type)]).toEqual(['2',alpha.id,undefined,['open','assign']]);
 // The incident was opened by the runner, not by a person.
 expect(afterConflict.timeline[0]?.origin).toBe('system');

 // Explicit reload keeps the draft, shows what changed and only then lets B submit again.
 await pageB.getByRole('button',{name:'Reload the current incident',exact:true}).click();
 await expect(pageB.getByTestId('revision')).toContainText('Revision 2');
 await expect(pageB.locator('[data-conflict="reloaded"]')).toContainText('was not applied');
 await expect(pageB.getByTestId('response-words')).toContainText(`Owner ${alpha.id}`);
 await expect(pageB.getByLabel('Reason (optional)')).toHaveValue(typed);
 await submit(pageB,'Acknowledge');
 await expect(outcome(pageB,'committed')).toContainText('revision 3');
 // ACK pauses reminders; the source is still firing and says so.
 await expect(pageB.getByTestId('ack-source-firing')).toContainText('the source is still firing');
 await expect(pageB.getByTestId('source-badge')).toHaveText('Source firing, fresh data');
 await expect(pageB.getByTestId('reminders')).toContainText('paused by the acknowledgement');
 await expect(pageB.getByTestId('worse-impact')).toContainText('eligible to notify');
 await expect(pageB.getByTestId('urgency')).toContainText('No notification policy has evaluated this incident');
 await expect(pageB.getByTestId('delivery')).toContainText('No delivery has been created');
 // The typed reason is plain text: no element was created and no handler ran.
 await expect(pageB.locator('.inc-timeline li[data-type="ack"]')).toContainText('<img src=x');
 expect(await pageB.locator('.inc-timeline img').count()).toBe(0);
 expect(await pageB.evaluate(()=>(window as unknown as {__pwn?:number}).__pwn)).toBeUndefined();
 const acked=await read(pageB,org,project,incident);
 expect([acked.version,acked.ack?.actor,acked.ack?.current,acked.timeline.at(-1)?.actor,acked.timeline.at(-1)?.origin]).toEqual(['3',bravo.id,true,bravo.id,'human']);

 // A reloads and sees B's ACK, then reports a worse impact: the ACK no longer covers it and delivery stays eligible.
 await pageA.getByRole('button',{name:'Reload incident',exact:true}).click();
 await expect(pageA.getByTestId('revision')).toContainText('Revision 3');
 await expect(pageA.locator('[data-section="incident-response"]')).toContainText(`Acknowledged by ${bravo.id}`);
 await openAction(pageA,'Report impact');
 await pageA.getByLabel('Severity').selectOption('critical');
 await submit(pageA,'Report impact');
 await expect(outcome(pageA,'committed')).toContainText('revision 4');
 await expect(pageA.getByTestId('reminders')).toContainText('Reminders are not paused');
 await expect(pageA.getByTestId('worse-impact')).toContainText('eligible to notify');
 await expect(pageA.getByTestId('response-words')).toContainText('worsened');
 await expect(pageA.locator('[data-section="alert-condition"]')).toContainText('Impact severity critical, impact revision 2');

 // B resolves while the source is firing: a reason is required and the unresolved-source banner is persistent.
 await pageB.getByRole('button',{name:'Reload incident',exact:true}).click();
 await expect(pageB.getByTestId('revision')).toContainText('Revision 4');
 await openAction(pageB,'Resolve');
 await expect(pageB.getByRole('note').filter({hasText:'The alert source is still firing'})).toBeVisible();
 let actionPosts=0;
 pageB.on('request',(r)=>{if(r.method()==='POST'&&r.url().endsWith('/api/v1/actions'))actionPosts++;});
 await submit(pageB,'Resolve');
 await expect(outcome(pageB,'invalid')).toContainText('A reason is required');
 expect(actionPosts).toBe(0);
 await pageB.getByLabel('Reason (required)').fill('Rolled back the deploy; the source has not recovered yet');
 await submit(pageB,'Resolve');
 await expect(outcome(pageB,'committed')).toContainText('revision 5');
 await expect(pageB.getByTestId('unresolved-source')).toContainText('the alert source is still firing');
 await expect(pageB.getByTestId('status-badge')).toHaveText('Incident: resolved by a person');
 await expect(pageB.getByTestId('source-badge')).toHaveText('Source firing, fresh data');
 await expect(pageB.getByText('A resolved incident accepts no further human actions')).toBeVisible();
 await pageB.reload();
 await expect(pageB.getByTestId('unresolved-source')).toBeVisible();
 await expect(pageB.getByTestId('source-badge')).toHaveText('Source firing, fresh data');

 // The shared queue shows the committed incident immediately. No destination exists in this org, so no policy evaluated the incident:
 // the row says so (no tier, no delivery) instead of showing a state, and no section is listed as "not available" or sent.
 await pageA.goto(`/${hash(org,project,'queue')}`);
 const row=pageA.locator(`tr[data-incident="${incident}"]`);
 await expect(row).toContainText('Resolved by a person');
 await expect(row).toContainText('Source firing');
 await expect(row).toContainText('Rate unknown');
 await expect(row.locator('[data-cell="urgency"]')).toContainText('No notification policy has evaluated this incident');
 await expect(row.locator('[data-cell="delivery"]')).toContainText('No delivery has been created');
 await expect(row.locator('[data-cell="unread"]')).toContainText('Unread change: No notification policy');
 await expect(pageA.locator('[data-section="delivery"]')).toHaveCount(0);
 await expect(pageA.getByText('not at a scheduled digest time')).toBeVisible();
 expect(await pageA.locator('main').innerText()).not.toMatch(/\b0\s*%/);

 // A wrong-scope incident and a missing one are one answer.
 await pageA.goto(`/${hash(org,project,'incidents',id())}`);
 await expect(pageA.locator('[data-state="unauthorized"]')).toContainText('not found or is not available');

 await ctxA.close();await ctxB.close();
});

test('a lost response is an unknown outcome and the same command ID returns the original result',async({page,browser,playwright})=>{
 test.setTimeout(180_000);
 await login(page,email,password);
 const org=id(),project=id();
 await command(page,org,'create_org',{id:org,name:'incident replay'});
 await command(page,org,'create_project',{id:project,name:'project'});
 const who={email:`replay-${id().slice(0,8)}@example.test`,password:'incident replay password 2026',id:id()};
 await command(page,org,'create_user',{id:who.id,email:who.email,password:who.password});
 await command(page,org,'membership',{user_id:who.id,enabled:true});
 await command(page,org,'org_admin',{user_id:who.id,enabled:true});
 const api=await playwright.request.newContext();
 const incident=await seed(page,api,org,project);
 const ctx=await browser.newContext();
 const p=await ctx.newPage();
 await login(p,who.email,who.password);
 await p.goto(`/${hash(org,project,'incidents',incident)}`);
 await expect(p.getByTestId('revision')).toContainText('Revision 1');
 const commandIds:string[]=[];
 let dropped=false;
 await p.route('**/api/v1/actions',async(route)=>{
  commandIds.push((route.request().postDataJSON() as {command_id:string}).command_id);
  if(!dropped){dropped=true;await route.fetch();await route.abort('failed');return;} // the server committed; the browser never hears
  await route.continue();
 });
 await openAction(p,'Acknowledge');
 await submit(p,'Acknowledge');
 await expect(outcome(p,'unknown')).toContainText('Outcome unknown');
 await expect(p.getByTestId('revision')).toContainText('Revision 1');
 await expect(p.getByTestId('ack-source-firing')).toHaveCount(0);
 const committed=await read(p,org,project,incident);
 expect([committed.version,committed.timeline.map((e)=>e.type)]).toEqual(['2',['open','ack']]);
 await p.getByRole('button',{name:'Resend the same request',exact:true}).click();
 await expect(outcome(p,'committed')).toContainText('revision 2');
 await expect(p.getByTestId('revision')).toContainText('Revision 2');
 expect(commandIds).toHaveLength(2);
 expect(commandIds[1]).toBe(commandIds[0]);
 const after=await read(p,org,project,incident);
 expect([after.version,after.timeline.map((e)=>e.type)]).toEqual(['2',['open','ack']]);
 await p.unroute('**/api/v1/actions');

 // A snooze hides neither the source nor the timeline, and its expiry refreshes the page exactly once.
 await openAction(p,'Snooze reminders');
 await p.getByLabel('Reason (required)').fill('known flapping dependency');
 await submit(p,'Snooze reminders');
 await expect(outcome(p,'committed')).toContainText('revision 3');
 await expect(p.getByTestId('snooze')).toContainText('active');
 await expect(p.getByTestId('source-badge')).toHaveText('Source firing, fresh data');
 await expect(p.locator('.inc-timeline li[data-type="snooze"]')).toContainText('known flapping dependency');
 const clocked=await browser.newContext();
 const c=await clocked.newPage();
 await login(c,who.email,who.password);
 let reads=0;
 c.on('request',(r)=>{if(r.url().endsWith('/api/v1/incidents/get'))reads++;});
 await c.clock.install();
 await c.goto(`/${hash(org,project,'incidents',incident)}`);
 await expect(c.getByTestId('snooze')).toContainText('active');
 expect(reads).toBe(1);
 await c.clock.fastForward('01:05:00');
 await expect.poll(()=>reads).toBe(2);
 await c.clock.fastForward('03:00:00');
 await c.waitForTimeout(1500);
 expect(reads).toBe(2);
 await clocked.close();await ctx.close();
});

// Console API sections 1, 2 and 10 are all served by this installation: the page is audited (names, labels, contrast in both themes, narrow width) with the real answers. An organization that has
// not connected GitLab says why a GitLab issue cannot be created; a copy and a note really work. Nothing is conditional on what the server serves.
test('the incident page with the real notes, copy and GitLab answers of an installation with no GitLab connection passes the audit',async({page,playwright})=>{
 test.setTimeout(240_000);
 await login(page,email,password);
 const org=id(),project=id();
 await command(page,org,'create_org',{id:org,name:'incident not built'});
 await command(page,org,'create_project',{id:project,name:'project'});
 const api=await playwright.request.newContext();
 const incident=await seed(page,api,org,project);
 const token=await csrf(page);
 const status=async(path:string,data:Record<string,unknown>):Promise<number>=>(await page.request.post(path,{headers:{'X-CSRF-Token':token,Origin:origin},data})).status();
 expect(await status('/api/v1/gitlab/issues',{op:'preview',org,project_id:project,entity:{kind:'incident',id:incident}})).toBe(200);
 expect(await status('/api/v1/incidents/markdown',{org,project_id:project,id:incident,format:'link'})).toBe(200);

 // The list: the open-by-ID form, the figures and the real row.
 await page.goto(`/${hash(org,project,'incidents')}`);
 await expect(page.getByRole('form',{name:'Open an incident'})).toBeVisible();
 await expect(page.getByTestId('incident-stats')).toContainText('Needs action');
 await expect(page.locator(`tr[data-incident="${incident}"]`)).toBeVisible();
 const listFound=await auditDom(page);
 expect(listFound,JSON.stringify(listFound,null,1)).toEqual([]);
 if(process.env.SOUNDPOST_SHOT_DIR)await page.screenshot({path:`${process.env.SOUNDPOST_SHOT_DIR}/incidents-list.png`,fullPage:true});

 await page.goto(`/${hash(org,project,'incidents',incident)}`);
 await expect(page.getByTestId('revision')).toContainText('Revision 1');
 // Lineage: every kind is there; what the incident does not link is shown as not linked.
 await expect(page.getByTestId('lineage')).toContainText('Issue');
 await expect(page.getByTestId('lineage')).toContainText('none linked');
 const pageFound=await auditDom(page);
 expect(pageFound,JSON.stringify(pageFound,null,1)).toEqual([]);
 // Both themes pass the contrast audit (the theme is an attribute of the document).
 await page.evaluate(()=>document.documentElement.setAttribute('data-theme','light'));
 const lightFound=await auditDom(page);
 expect(lightFound,JSON.stringify(lightFound,null,1)).toEqual([]);
 await page.evaluate(()=>document.documentElement.setAttribute('data-theme','dark'));
 if(process.env.SOUNDPOST_SHOT_DIR)await page.screenshot({path:`${process.env.SOUNDPOST_SHOT_DIR}/incident-page.png`,fullPage:true});
 // The resolve dialog (what it does to the other entities) passes the same audit.
 await openAction(page,'Resolve');
 await expect(page.getByRole('dialog')).toContainText('never reopened');
 const resolveFound=await auditDom(page);
 expect(resolveFound,JSON.stringify(resolveFound,null,1)).toEqual([]);
 if(process.env.SOUNDPOST_SHOT_DIR)await page.screenshot({path:`${process.env.SOUNDPOST_SHOT_DIR}/incident-resolve.png`});
 await page.keyboard.press('Escape');
 await expect(page.getByRole('dialog')).toHaveCount(0);
 await page.getByRole('button',{name:'Create GitLab issue',exact:true}).click();
 await expect(page.getByTestId('gitlab-unavailable')).toContainText('GitLab is not connected for this organization');
 await expect(page.getByRole('dialog')).not.toContainText('not available yet');
 const gitlabFound=await auditDom(page);
 expect(gitlabFound,JSON.stringify(gitlabFound,null,1)).toEqual([]);
 await page.keyboard.press('Escape');
 await expect(page.getByRole('dialog')).toHaveCount(0);
 await page.getByTestId('copy-menu').getByRole('button',{name:'Copy'}).click();
 await page.getByRole('menuitem',{name:'Link',exact:true}).click();
 await expect(page.locator('.gl-copy-note')).toContainText(/Link copied\.|did not allow copying/);
 await expect(page.locator('.gl-copy-note')).not.toContainText('not available yet');
 const composer=page.getByTestId('note-composer');
 await composer.getByLabel('Add a note to the timeline').fill('Canary rolled back');
 await composer.getByRole('button',{name:'Post note',exact:true}).click();
 await expect(page.locator('[data-note-outcome="committed"]')).toBeVisible();
 await expect(composer.getByLabel('Add a note to the timeline')).toBeEnabled();
 expect((await read(page,org,project,incident)).version).toBe('2');
 // At 390 px the list stacks and the page has no horizontal overflow.
 await page.setViewportSize({width:390,height:844});
 const narrowPage=await auditDom(page);
 expect(narrowPage,JSON.stringify(narrowPage,null,1)).toEqual([]);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
 if(process.env.SOUNDPOST_SHOT_DIR)await page.screenshot({path:`${process.env.SOUNDPOST_SHOT_DIR}/incident-narrow.png`,fullPage:true});
 await page.goto(`/${hash(org,project,'incidents')}`);
 await expect(page.locator(`tr[data-incident="${incident}"]`)).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
 if(process.env.SOUNDPOST_SHOT_DIR)await page.screenshot({path:`${process.env.SOUNDPOST_SHOT_DIR}/incidents-narrow.png`,fullPage:true});
});
