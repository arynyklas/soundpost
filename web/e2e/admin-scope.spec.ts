// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Browser,type BrowserContext,type Locator,type Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,field,id,login,onboardMetricSource,owner,postJson,reopen,setGrant} from './support/real';
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
const view=(name:string,org:string,project:string,page=''):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view:name,...(page?{page}:{})})}`;
const settings=(org:string,project:string,page='project'):string=>view('settings',org,project,page);
const routing=(org:string,project:string):string=>view('routing',org,project);
// The change forms of a list row open in a dialog (the page behind it is inert): close it before anything else on the page is used.
const closeDialogs=async(page:Page):Promise<void>=>{if(await page.locator('dialog[open]').count()>0)await page.getByRole('button',{name:'Close',exact:true}).click({timeout:3000}).catch(()=>undefined);};
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
 await page.locator('[data-settings-tab="operations"]').click();
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
 await page.locator('[data-settings-tab="project"]').click();
 await page.reload();
 await expect(page.locator('[data-state="unauthorized"]').first()).toBeVisible();
});

// [05.03-W5] Project settings through C11 /api/v1/policies against the real served process: the notification policy, retention and
// notification destinations are read and changed in the console. Every change is an audited command (the audit log names the person),
// nothing is shown as saved before the server answers committed, a stale page is told so and reloaded, a destination secret is
// write-only (never in any response or page), and the account that holds only policy.write changes its project's retention and policy
// but not the organization's destinations.
const form=(page:Page,name:string):Locator=>page.locator(`[data-write="${name}"]`);
async function save(f:Locator,reason:string,button:string):Promise<void>{
 await f.getByLabel('Reason (kept in the audit record)').fill(reason);
 await f.getByRole('button',{name:button,exact:true}).click();
}
async function policyView(page:Page,org:string,project:string):Promise<Record<string,unknown>>{
 const r=await postJson(page,'/api/v1/policies',{org,project_id:project,operation:'read'});
 expect(r.status,r.text).toBe(200);
 return r.json as Record<string,unknown>;
}

test('project settings change the notification policy and retention through audited commands',async({page,browser})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'admin scope policies org');
 const project=await createProject(page,org);
 const writer={id:id(),email:`policy-writer-${id().slice(0,8)}@example.test`,password:'policy writer password 2026'};
 await adminCommand(page,org,'create_user',{id:writer.id,email:writer.email,password:writer.password});
 await adminCommand(page,org,'membership',{user_id:writer.id,enabled:true});
 await adminCommand(page,org,'grant',{user_id:writer.id,project_id:project,enabled:true,permissions:['policy.write']});
 // The organization already has one destination (its own screen is covered by destination-settings.spec.ts): the policy writer reads it below.
 const destination=await postJson(page,'/api/v1/destinations',{org,project_id:project,operation:'save',command_id:id(),expected_version:'0',reason:'the organization already has a destination',destination:{id:id(),type:'smtp',address:'ops@example.test',enabled:true}});
 expect(destination.status,destination.text).toBe(200);

 // Notification routes: the urgency policy of the project.
 await page.goto(`/${routing(org,project)}`);
 const notification=page.locator('[data-section="policy-notification"]');
 await expect(notification).toContainText('approved default policy (revision 1)');
 await expect(page.getByTestId('policy-revision')).toContainText('You administer this organization');
 await expect(notification.locator('[data-urgency-step]')).toHaveCount(4);

 // The notification policy: a local mistake is refused before anything is sent; then a real save.
 const n=form(page,'notification_policy');
 await n.getByLabel('Failure rate (%)',{exact:true}).fill('150');
 await save(n,'too high','Save notification policy');
 await expect(n.locator('[data-write-result="local"]')).toContainText('Failure rate must be a percentage');
 await n.getByLabel('Failure rate (%)',{exact:true}).fill('7.5');
 await n.getByLabel('Minimum failures',{exact:true}).fill('9');
 await n.getByLabel('Critical operation codes (comma separated)').fill('payment_failed, auth_down');
 await n.getByLabel(/^First reminder/).fill('300');
 await save(n,'tighten the failure policy','Save notification policy');
 await expect(n.locator('[data-write-result="committed"]')).toContainText('The server committed this change');
 await expect(notification).toContainText('This project has its own policy, revision 2');
 await expect(notification.locator('[data-urgency-step="reminders"]')).toContainText('5 minutes');
 const saved=await policyView(page,org,project);
 expect(saved.notification).toMatchObject({source:'project',revision:'2',min_failures:9,rate_basis_points:750,critical_codes:['auth_down','payment_failed'],first_reminder_ns:'300000000000'});
 // A reload shows the committed policy, not a client copy.
 await page.reload();
 await expect(page.locator('[data-write="notification_policy"]').getByLabel('Minimum failures',{exact:true})).toHaveValue('9');

 // Project settings: retention. Nothing is shown as saved while the server has not answered.
 await reopen(page,`/${settings(org,project)}`);
 const r=form(page,'retention');
 await expect(page.locator('[data-retention="logs"]')).toContainText('Not set');
 const gate=Promise.withResolvers<void>();
 await page.route('**/api/v1/policies',async(route)=>{
  if(field(route.request().postDataJSON(),'operation')==='write')await gate.promise;
  await route.continue();
 });
 await r.getByLabel('Signal').selectOption('logs');
 await r.getByLabel('Days (1 to 3650)').fill('45');
 await save(r,'keep logs six weeks','Save retention');
 await expect(r).toHaveAttribute('data-write-phase','pending');
 await expect(r).toContainText('Nothing is saved until it confirms');
 await expect(page.locator('[data-retention="logs"]')).toContainText('Not set');
 gate.resolve();
 await expect(r.locator('[data-write-result="committed"]')).toBeVisible();
 await page.unroute('**/api/v1/policies');
 await expect(page.locator('[data-retention="logs"]')).toContainText('45');

 // Another signal changed elsewhere since the page read is no conflict: a stale page conflicts only on the SAME object (per-object epochs).
 const unrelatedBase=await page.getByTestId('policy-revision').getAttribute('data-revision');
 const unrelated=await postJson(page,'/api/v1/policies',{org,project_id:project,operation:'write',command_id:id(),expected_revision:unrelatedBase,reason:'another administrator, other signal',change:{kind:'retention',retention:{signal:'traces',days:11}}});
 expect(unrelated.status,unrelated.text).toBe(200);
 await r.getByLabel('Signal').selectOption('metrics');
 await r.getByLabel('Days (1 to 3650)').fill('7');
 await save(r,'tighten metrics','Save retention');
 await expect(r.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator('[data-retention="metrics"]')).toContainText('7');
 await expect(page.locator('[data-retention="traces"]')).toContainText('11');

 // A stale page is told so when the SAME signal changed meanwhile, nothing is changed, the typed reason survives, and the next save (on the reloaded revision) commits.
 const before=await page.getByTestId('policy-revision').getAttribute('data-revision');
 const other=await postJson(page,'/api/v1/policies',{org,project_id:project,operation:'write',command_id:id(),expected_revision:before,reason:'another administrator',change:{kind:'retention',retention:{signal:'metrics',days:11}}});
 expect(other.status,other.text).toBe(200);
 await r.getByLabel('Signal').selectOption('metrics');
 await r.getByLabel('Days (1 to 3650)').fill('9');
 await save(r,'change metrics again','Save retention');
 await expect(r.locator('[data-write-result="conflict"]')).toContainText('nothing was changed');
 await expect(r.getByLabel('Reason (kept in the audit record)')).toHaveValue('change metrics again');
 await expect(page.locator('[data-retention="metrics"]')).toContainText('11');
 expect(await page.getByTestId('policy-revision').getAttribute('data-revision')).not.toBe(before);
 await r.getByRole('button',{name:'Save retention',exact:true}).click();
 await expect(r.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator('[data-retention="metrics"]')).toContainText('9');

 // The account that holds only policy.write: its project's retention and policy, not the organization's destinations.
 const ctx=await browser.newContext();
 const wp=await ctx.newPage();
 await login(wp,writer.email,writer.password);
 await wp.goto(`/${routing(org,project)}`);
 await expect(wp.getByTestId('policy-revision')).toContainText('You hold policy.write on this project');
 await expect(wp.locator('[data-settings-page="destinations"]')).toContainText('Only organization administrators change destinations');
 await expect(wp.locator('[data-destination]')).toHaveCount(1);
 await expect(wp.locator('[data-write^="destination-"]')).toHaveCount(0);
 await expect(wp.getByRole('button',{name:/^New destination/})).toHaveCount(0);
 await reopen(wp,`/${settings(org,project)}`);
 await expect(wp.locator('[data-retention="logs"]')).toContainText('45');
 const wr=form(wp,'retention');
 await wr.getByLabel('Signal').selectOption('logs');
 await wr.getByLabel('Days (1 to 3650)').fill('60');
 await save(wr,'writer extends logs','Save retention');
 await expect(wr.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(wp.locator('[data-retention="logs"]')).toContainText('60');
 const forbidden=await postJson(wp,'/api/v1/policies',{org,project_id:project,operation:'write',command_id:id(),expected_revision:(await policyView(wp,org,project)).revision,reason:'try a destination',change:{kind:'destination',destination:{id:id(),type:'smtp',address:'x@example.test',enabled:true}}});
 expect(forbidden.status,forbidden.text).toBe(403);
 // The same grant on no project is the one denial.
 const stranger=await postJson(wp,'/api/v1/policies',{org,project_id:id(),operation:'read'});
 expect(stranger.status).toBe(404);

 // The audit log names who changed what.
 const audit=await postJson(page,'/api/v1/admin/read',{org_id:org,kind:'audit'});
 const audits=field(audit.json,'audits');
 if(!Array.isArray(audits))throw Error(`audit: ${audit.text}`);
 const named=(action:string,principal:string,reason:string):boolean=>audits.some((a)=>field(a,'action')===action&&field(a,'principal')===principal&&field(a,'reason')===reason);
 const me=field(await (await page.request.get('/api/v1/session')).json() as unknown,'user');
 if(typeof me!=='string')throw Error('no session user');
 expect(named('retention',writer.id,'writer extends logs')).toBe(true);
 expect(named('notification_policy',me,'tighten the failure policy')).toBe(true);
 await ctx.close();
});

// [05.03-W6] Organization, team, source policy and single sign-on settings over the real admin routes. Every change is an audited admin
// command and nothing is shown as saved before the server answers; a client secret is write-only; an administrator of another
// organization and an ordinary member cannot read or change any of it (the same not-found as a missing organization); revoking a
// grant, a team or an administrator removes the access at once.
interface Person{id:string;email:string;password:string}
async function person(page:Page,org:string,tag:string,member=true):Promise<Person>{
 const p={id:id(),email:`${tag}-${id().slice(0,8)}@example.test`,password:`${tag} password 2026`};
 await adminCommand(page,org,'create_user',{id:p.id,email:p.email,password:p.password});
 if(member)await adminCommand(page,org,'membership',{user_id:p.id,enabled:true});
 return p;
}
async function signedIn(browser:Browser,p:Person):Promise<{ctx:BrowserContext;page:Page}>{
 const ctx=await browser.newContext();
 const page=await ctx.newPage();
 await login(page,p.email,p.password);
 return {ctx,page};
}
const policyStatus=async(page:Page,org:string,project:string):Promise<number>=>(await postJson(page,'/api/v1/policies',{org,project_id:project,operation:'read'})).status;
const PAGES:Record<string,string>={organization:'organization',teams:'teams',sources:'source-policies',sso:'sso',operations:'operations'};
async function openTab(page:Page,org:string,project:string,tab:string):Promise<Locator>{
 // A fresh document every time: the specs that call this after an administration change elsewhere need the console to read the organization again.
 await reopen(page,`/${settings(org,project,tab)}`);
 const content=page.locator(`[data-settings-page="${PAGES[tab]}"]`);
 await expect(content).toBeVisible();
 return content;
}

test('organization settings: projects, members and grants are audited commands, and revoking a grant or a team removes access at once',async({page,browser})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'admin scope organization page');
 const project=await createProject(page,org);
 const member=await person(page,org,'org-member',false);
 const {ctx,page:mp}=await signedIn(browser,member);
 const content=await openTab(page,org,project,'organization');
 await expect(content.getByTestId('admin-revision')).toBeVisible();

 // A project is created by an audited command and listed only once the server has answered.
 const create=form(page,'create_project');
 await create.getByLabel('Project name').fill('second project');
 await save(create,'second project for the batch jobs','Create project');
 await expect(create.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator('[data-org-project]')).toHaveCount(2);

 // Enrol the member, then grant policy.write on the first project.
 const enrol=form(page,'membership');
 await enrol.getByLabel('User ID').fill(member.id);
 await save(enrol,'enrol the policy owner','Save membership');
 await expect(enrol.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-member="${member.id}"]`)).toHaveAttribute('data-member-state','enabled');
 expect(await policyStatus(mp,org,project)).toBe(404);
 const grant=form(page,'grant');
 await grant.getByLabel('User ID').fill(member.id);
 await grant.getByLabel(/^Project/).selectOption(project);
 await save(grant,'no permission chosen','Save grant');
 await expect(grant.locator('[data-write-result="local"]')).toContainText('at least one permission');
 await grant.getByLabel(/policy\.write/).check();
 await save(grant,'policy owner of the first project','Save grant');
 await expect(grant.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-grant="${member.id}:${project}"]`)).toContainText('policy.write');
 expect(await policyStatus(mp,org,project)).toBe(200);

 // Revoking the grant ends the access at once.
 await grant.getByLabel('User ID').fill(member.id);
 await grant.getByLabel(/Grant \(clear/).uncheck();
 await save(grant,'the policy owner moved teams','Save grant');
 await expect(grant.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-grant="${member.id}:${project}"]`)).toHaveCount(0);
 expect(await policyStatus(mp,org,project)).toBe(404);

 // A team grants the same permission to its members on its projects only, and a disabled team grants nothing.
 await page.locator('[data-settings-tab="teams"]').click();
 const team=form(page,'team-new');
 await team.getByLabel('Members (user IDs, comma separated)').fill(member.id);
 await team.getByLabel(new RegExp(project)).check();
 await save(team,'no permission chosen','Create team');
 await expect(team.locator('[data-write-result="local"]')).toContainText('at least one permission');
 await team.getByLabel(/policy\.write/).check();
 await save(team,'the policy owners team','Create team');
 await expect(team.locator('[data-write-result="committed"]')).toBeVisible();
 const row=page.locator('[data-team]');
 await expect(row).toHaveCount(1);
 await expect(row).toHaveAttribute('data-team-state','enabled');
 await expect(row).toContainText('policy.write');
 expect(await policyStatus(mp,org,project)).toBe(200);
 await row.getByRole('button',{name:/^Change team/}).click();
 const edit=row.locator('[data-write^="team-"]');
 await edit.getByLabel('Team enabled').uncheck();
 await save(edit,'the policy owners team is paused','Save team');
 await expect(edit.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(row).toHaveAttribute('data-team-state','disabled');
 expect(await policyStatus(mp,org,project)).toBe(404);
 await closeDialogs(page);

 // The audit trail names every change and who made it.
 await page.locator('[data-settings-tab="operations"]').click();
 const trail=page.locator('[data-section="org-audit"]');
 for(const action of ['create_project','membership','grant','team'])await expect(trail.locator(`[data-audit-action="${action}"]`).first()).toBeVisible();
 await expect(trail).toContainText('policy owner of the first project');
 await expect(trail).toContainText('the policy owners team is paused');
 await ctx.close();
});

test('organization settings: a stale page conflicts only on the same object, a change elsewhere is no conflict',async({page})=>{
 test.setTimeout(180_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'admin scope lost update');
 const project=await createProject(page,org);
 const target=await person(page,org,'target',false);
 await openTab(page,org,project,'organization');
 const enrol=form(page,'membership');
 await expect(page.locator('[data-org-project]')).toHaveCount(1);

 // Changes to OTHER objects after the page read: a new account, another project, another user's membership. None is a conflict.
 const bystander=await person(page,org,'bystander',false);
 await createProject(page,org,'raced project');
 await adminCommand(page,org,'membership',{user_id:bystander.id,enabled:true});
 await enrol.getByLabel('User ID').fill(target.id);
 await save(enrol,'saved after changes elsewhere','Save membership');
 await expect(enrol.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-member="${target.id}"]`)).toHaveAttribute('data-member-state','enabled');

 // Another administrator changes THIS user's membership after the page read it: the save is a lost update, refused, nothing changed.
 await adminCommand(page,org,'membership',{user_id:target.id,enabled:false});
 await enrol.getByLabel('User ID').fill(target.id);
 await save(enrol,'saved on a stale page','Save membership');
 await expect(enrol.locator('[data-write-result="conflict"]')).toContainText(/nothing was changed/i);
 await expect(page.locator(`[data-member="${target.id}"]`)).toHaveAttribute('data-member-state','disabled');
 await expect(enrol.getByLabel('User ID')).toHaveValue(target.id);

 // The reloaded page carries the new epoch: the same save now commits.
 await save(enrol,'saved on the reloaded page','Save membership');
 await expect(enrol.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-member="${target.id}"]`)).toHaveAttribute('data-member-state','enabled');
});

test('single sign-on settings: the mapping is validated, saved and shown, and the client secret is write-only',async({page})=>{
 test.setTimeout(180_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'admin scope sso page');
 const project=await createProject(page,org);
 const mapped=await person(page,org,'sso-user');
 const SSO_SECRET='E2E-SSO-CLIENT-SECRET-never-shown';
 const bodies:string[]=[];
 page.on('response',async(r)=>{if(r.url().includes('/api/v1/admin/'))bodies.push(await r.text().catch(()=>''));});
 const content=await openTab(page,org,project,'sso');
 await expect(content.locator('[data-state="empty"]')).toContainText('No single sign-on provider');

 const add=form(page,'sso-new');
 await add.getByLabel(/^Issuer/).fill('https://idp.example.test');
 await add.getByLabel('Client ID',{exact:true}).fill('soundpost-e2e');
 await add.getByLabel(/^Identity mapping/).fill('not a mapping line');
 await save(add,'trust the corporate identity provider','Add provider');
 await expect(add.locator('[data-write-result="local"]')).toContainText('identity subject = user ID');
 await add.getByLabel(/^Identity mapping/).fill(`alice = ${mapped.id}`);
 await add.getByLabel(/^Client secret/).fill(SSO_SECRET);
 await save(add,'trust the corporate identity provider','Add provider');
 await expect(add.locator('[data-write-result="committed"]')).toBeVisible();
 const provider=page.locator('[data-sso]');
 await expect(provider).toHaveCount(1);
await expect(provider).toContainText('https://idp.example.test');
 await expect(provider).toContainText('1 identity mapping');
 await expect(provider).toContainText('write-only (never shown)');
 await expect(page.locator('body')).not.toContainText(SSO_SECRET);
 await provider.getByRole('button',{name:/^Change provider/}).click();

 // An identity mapped to an account outside this organization is refused, and nothing changes.
 const edit=provider.locator('[data-write^="sso-"]');
 await edit.getByLabel(/^Identity mapping/).fill(`alice = ${mapped.id}\nghost = ${id()}`);
 await save(edit,'map a ghost','Save provider');
 await expect(edit.locator('[data-write-result="not_found"]')).toContainText('Nothing was changed');
 await expect(provider).toContainText('1 identity mapping');
 await closeDialogs(page);
 // A second identity, the secret left empty: the sealed one is kept and no response ever carries it.
 const second=await person(page,org,'sso-user-two');
 // Enrolling that account changed the organization behind this page's back: a save on the page as it was read would be refused (see
 // the stale-page test), so the page reads the organization again first.
 await openTab(page,org,project,'sso');
 await provider.getByRole('button',{name:/^Change provider/}).click();
 await expect(edit.getByLabel(/^Client secret/)).toHaveValue('');
 await edit.getByLabel(/^Identity mapping/).fill(`alice = ${mapped.id}\nbob = ${second.id}`);
 await save(edit,'map the second user','Save provider');
 await expect(edit.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(provider).toContainText('2 identity mappings');
 const read=await postJson(page,'/api/v1/admin/read',{org_id:org,kind:'sso'});
 expect(read.status).toBe(200);
 expect(read.text).not.toContain(SSO_SECRET);
 expect(read.text).not.toMatch(/client_?secret/i);
 for(const body of bodies)expect(body).not.toContain(SSO_SECRET);
});

test('source policies: the access policy and the admitted policy change through a visible fence',async({page})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'admin scope source page');
 const project=await createProject(page,org);
 const source=await onboardMetricSource(page,org,project);
 const content=await openTab(page,org,project,'sources');
 const row=content.locator(`[data-source="${source.id}"]`);
 await expect(row).toContainText('active');
 await expect(row).toContainText('admitted policy revision 1');
 await expect(row).toContainText('kinds metric, span');
 await expect(row).toContainText(/replay not enabled;/);
 await expect(row).toContainText('log templates none');
 await expect(content).not.toContainText(source.credential);

 // Onboarding a source writes its access policy (enabled, for its project), so its admitted policy can be changed at once. A
 // change takes effect through a fence: the person sees it in progress, never as done, and then complete.
const changeButton=row.getByRole('button',{name:/^Change the admitted policy/});
 const toggle=row.locator('[data-write^="source-policy-"]');
 await changeButton.click();
 await toggle.getByLabel('Session replay enabled').check();
 await save(toggle,'turn replay on','Save admitted policy');
 const first=content.locator('[data-fence]').first();
 await expect(first).toBeVisible();
 await expect(first).toHaveAttribute('data-fence-phase','complete',{timeout:90_000});
 await expect(row).toContainText(/replay enabled;/);
 await expect(row).toContainText('admitted policy revision 2');
 await expect(row).toHaveAttribute('data-source-state','active');
 await closeDialogs(page);
 await expect(changeButton).toBeVisible();
 await expect(content.locator(`[data-source-access="${source.id}"]`)).toContainText('enabled');

 // The access policy of a live source fences it too: disabling it closes the source's admitted policy, and says so while it happens.
 const access=form(page,'source_policy');
 await access.getByLabel('Source ID').fill(source.id);
 await access.getByLabel('Enabled',{exact:true}).uncheck();
 await save(access,'disable the source for its project','Save access policy');
 await expect(access.locator('[data-write-result="committed"]')).toContainText('still taking effect');
 const second=content.locator('[data-fence]').nth(1);
 await expect(second).toBeVisible();
 await expect(second).toHaveAttribute('data-fence-phase','complete',{timeout:90_000});
 await expect(content.locator(`[data-source-access="${source.id}"]`)).toContainText('disabled');
 await expect(row).toContainText(/policy disabled;/);
 await expect(row).toContainText('admitted policy revision 3');
 await expect(row).toHaveAttribute('data-source-state','active');
 await closeDialogs(page);
 await expect(changeButton).toBeVisible();

 // An admitted policy that enables the source while its access policy is disabled is refused, and nothing changes.
 await changeButton.click();
 await toggle.getByLabel('Policy enabled').check();
 await save(toggle,'enable it against the access policy','Save admitted policy');
 await expect(toggle.locator('[data-write-result="forbidden"]')).toContainText('Nothing was changed');
 await expect(row).toContainText(/policy disabled;/);
 await expect(row).toContainText('admitted policy revision 3');
 await closeDialogs(page);

 // Enabling the access policy again, through the same visible fence, lets the source ingest under the replay policy it keeps.
 await access.getByLabel('Enabled',{exact:true}).check();
 await save(access,'enable the source again','Save access policy');
 const third=content.locator('[data-fence]').nth(2);
 await expect(third).toHaveAttribute('data-fence-phase','complete',{timeout:90_000});
 await expect(content.locator(`[data-source-access="${source.id}"]`)).toContainText('enabled');
 await expect(row).toContainText(/policy enabled;/);
 await expect(row).toContainText(/replay enabled;/);
 await expect(row).toContainText('admitted policy revision 4');
 await expect(row).toHaveAttribute('data-source-state','active');
});

test('another organization\'s administrator and an ordinary member see none of it, and revoking an administrator ends the access',async({page,browser})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const orgA=await createOrg(page,'admin scope org A');
 const projectA=await createProject(page,orgA);
 const orgB=await createOrg(page,'admin scope org B');
 const projectB=await createProject(page,orgB,'b project');
 const adminB=await person(page,orgB,'admin-b');
 await adminCommand(page,orgB,'org_admin',{user_id:adminB.id,enabled:true});
 const plain=await person(page,orgA,'plain-member');
 await adminCommand(page,orgA,'grant',{user_id:plain.id,project_id:projectA,enabled:true,permissions:['telemetry.read']});
 const temp=await person(page,orgA,'temp-admin');

 // The owner makes `temp` an administrator through the console.
 await openTab(page,orgA,projectA,'organization');
 const admin=form(page,'org_admin');
 await admin.getByLabel('User ID').fill(temp.id);
 await save(admin,'temporary administrator','Save administrator');
 await expect(admin.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-admin="${temp.id}"]`)).toBeVisible();
 const t=await signedIn(browser,temp);
 const tempContent=await openTab(t.page,orgA,projectA,'organization');
 await expect(tempContent.getByTestId('admin-revision')).toBeVisible();

 // Another organization's administrator and an ordinary member: every page is the same not-found, and so is every route.
 for(const [name,p] of [['admin of B',adminB],['plain member',plain]] as const){
  const s=await signedIn(browser,p);
 await s.page.goto(`/${settings(orgA,projectA,'organization')}`);
  for(const tab of ['organization','teams','sources','sso']){
   await s.page.locator(`[data-settings-tab="${tab}"]`).click();
   await expect(s.page.locator(`[data-settings-page="${PAGES[tab]}"] [data-state="unauthorized"]`).first(),`${name}: ${tab}`).toBeVisible();
   await expect(s.page.locator(`[data-settings-page="${PAGES[tab]}"] form`),`${name}: ${tab}`).toHaveCount(0);
  }
  for(const kind of ['organization','audit','source','team','sso','source_policy','destination','retention']){
   const read=await postJson(s.page,'/api/v1/admin/read',{org_id:orgA,kind});
   expect([name,kind,read.status]).toEqual([name,kind,404]);
  }
  // The organization epoch is the precondition here, so no background commit (the global revision moves under them) can turn the answer into a conflict.
  const command=await postJson(s.page,'/api/v1/admin/commands',{command_id:id(),expected_epoch:'1',org_id:orgA,kind:'create_project',payload:{id:id(),name:'intruder',reason:'try'}});
  expect([name,command.status]).toEqual([name,404]);
  const policy=await postJson(s.page,'/api/v1/policies',{org:orgA,project_id:projectA,operation:'write',command_id:id(),expected_revision:'1',reason:'try',change:{kind:'retention',retention:{signal:'logs',days:1}}});
  expect([name,policy.status]).toEqual([name,404]);
  const source=await postJson(s.page,'/api/v1/sources/policy',{command_id:id(),source:id(),expected_revision:'1',policy:{},reason:'try'});
  expect([name,source.status]).not.toEqual([name,200]);
  await s.ctx.close();
 }
 // The administrator of B still administers B.
 const b=await signedIn(browser,adminB);
 const bContent=await openTab(b.page,orgB,projectB,'organization');
 await expect(bContent).toContainText('admin scope org B');
 await expect(bContent.locator('[data-org-project]')).toHaveCount(1);
 await b.ctx.close();

 // Revoking `temp` ends the access: the next read is the not-found, and the audit trail names who did it.
 await admin.getByLabel('User ID').fill(temp.id);
 await admin.getByLabel(/administrator of this organization/i).uncheck();
 await save(admin,'temporary administrator leaves','Save administrator');
 await expect(admin.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator(`[data-admin="${temp.id}"]`)).toHaveCount(0);
 await t.page.reload();
 await t.page.locator('[data-settings-tab="organization"]').click();
 await expect(t.page.locator('[data-settings-page="organization"] [data-state="unauthorized"]').first()).toBeVisible();
 expect((await postJson(t.page,'/api/v1/admin/read',{org_id:orgA,kind:'organization'})).status).toBe(404);
 await page.locator('[data-settings-tab="operations"]').click();
 await expect(page.locator('[data-section="org-audit"]')).toContainText('temporary administrator leaves');
 await t.ctx.close();
});
