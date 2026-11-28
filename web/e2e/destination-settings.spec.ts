// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Locator,type Page} from '@playwright/test';
import {activate,adminCommand,createOrg,createProject,field,id,login,owner,postJson,reopen} from './support/real';
// The destination settings page over the real served process: POST /api/v1/destinations (list | save). Saving a destination needs organization
// administration (D30: a destination routes every project of the organization), so an account that holds only policy.write on the project reads the
// list and is told it cannot change it, and the route itself refuses its save. Every save is an audited command based on the destination's own version:
// nothing is shown as saved before the server answers committed, a destination changed by someone else is a visible conflict (never an overwrite), an
// unconfirmed save resends the same command, and neither the secret nor the endpoint path is ever in a response or on the page.
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const settings=(org:string,project:string):string=>`#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view:'routing'})}`;
// The change forms of a list row open in a dialog (the page behind it is inert): close it before anything else on the page is used.
const closeDialogs=async(page:Page):Promise<void>=>{if(await page.locator('dialog[open]').count()>0)await page.getByRole('button',{name:'Close',exact:true}).click({timeout:3000}).catch(()=>undefined);};
const SECRET='E2E-DEST-SECRET-never-shown',TOKEN='TOKEN-DEST-in-the-path',ROTATED='E2E-ROTATED-secret-never-shown';
const form=(page:Page,name:string):Locator=>page.locator(`[data-write="${name}"]`);
async function save(f:Locator,reason:string,button:string):Promise<void>{
 await f.getByLabel('Reason (kept in the audit record)').fill(reason);
 await f.getByRole('button',{name:button,exact:true}).click();
}
async function openDestinations(page:Page,org:string,project:string):Promise<Locator>{
 // A fresh document, not a fragment change of the one on screen: Firefox answers goto(sameDocument#fragment) with a same-document navigation, its late `hashchange`
 // makes SessionBoundary revalidate and mount the console again.
 await reopen(page,`/${settings(org,project)}`);
 const content=page.locator('[data-settings-page="destinations"]');
 await expect(content).toBeVisible();
 return content;
}
const listOf=async(page:Page,org:string,project:string):Promise<unknown[]>=>{
 const r=await postJson(page,'/api/v1/destinations',{org,project_id:project,operation:'list'});
 expect(r.status,r.text).toBe(200);
 const list=field(r.json,'destinations');
 if(!Array.isArray(list))throw Error(`list: ${r.text}`);
 return list;
};
const saveBody=(org:string,project:string,version:string,destination:Record<string,unknown>,reason:string):Record<string,unknown>=>({org,project_id:project,operation:'save',command_id:id(),expected_version:version,reason,destination});

test('an organization administrator adds, pauses and rotates destinations through audited, versioned saves, and neither the secret nor the endpoint path is ever shown',async({page})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'destination settings org');
 const project=await createProject(page,org);
 const bodies:string[]=[];
 page.on('response',async(r)=>{if(r.url().includes('/api/v1/destinations')||r.url().includes('/api/v1/admin/'))bodies.push(await r.text().catch(()=>''));});

 const content=await openDestinations(page,org,project);
 await expect(content).toContainText('You administer this organization');
 await expect(content.locator('[data-state="empty"]')).toContainText('No destination is configured');

 // A local mistake is refused before anything is sent.
 await page.getByRole('button',{name:/^New destination/}).click();
 const add=form(page,'destination-new');
 await add.getByLabel('Endpoint (https, no credentials, query or fragment)').fill(`https://hooks.example.test/notify?token=${TOKEN}`);
 await save(add,'add the pager hook','Add destination');
 await expect(add.locator('[data-write-result="local"]')).toContainText('https endpoint without credentials, query or fragment');
 expect(await listOf(page,org,project)).toHaveLength(0);

 // A real save. Nothing is shown as saved while the server has not answered.
 await add.getByLabel('Endpoint (https, no credentials, query or fragment)').fill(`https://hooks.example.test/notify/${TOKEN}`);
 await add.getByLabel('Secret (write-only; sealed on save and never shown again)').fill(SECRET);
 const gate=Promise.withResolvers<void>();
 await page.route('**/api/v1/destinations',async(route)=>{
  if(field(route.request().postDataJSON(),'operation')==='save')await gate.promise;
  await route.continue();
 });
 await save(add,'add the pager hook','Add destination');
 await expect(add).toHaveAttribute('data-write-phase','pending');
 await expect(add).toContainText('Nothing is saved until it confirms');
 await expect(page.locator('[data-destination]')).toHaveCount(0);
 gate.resolve();
 await expect(add.locator('[data-write-result="committed"]')).toBeVisible();
 await page.unroute('**/api/v1/destinations');
 const hook=page.locator('[data-destination-channel="webhook"]');
 await expect(hook).toHaveCount(1);
 await expect(hook).toContainText('Webhook to hooks.example.test; enabled; secret set (write-only, never shown); version 1.');
 await expect(hook).toHaveAttribute('data-destination-enabled','true');
 await expect(hook).toHaveAttribute('data-destination-secret','set');
 await expect(hook).toHaveAttribute('data-destination-version','1');
 await expect(page.locator('body')).not.toContainText(SECRET);
 await expect(page.locator('body')).not.toContainText(TOKEN);
 const hookId=await hook.getAttribute('data-destination');
 if(hookId===null)throw Error('no destination id');

 // Email and Telegram are addressed by an address, not an endpoint.
 await add.getByLabel('Type').selectOption('smtp');
 await add.getByLabel('Recipient address').fill('not an address');
 await save(add,'add the on-call mailbox','Add destination');
 await expect(add.locator('[data-write-result="local"]')).toContainText('recipient address');
 await add.getByLabel('Recipient address').fill('oncall@example.test');
 await save(add,'add the on-call mailbox','Add destination');
 await expect(add.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator('[data-destination-channel="smtp"]')).toContainText('Email (SMTP) to ***@example.test; enabled; secret not set');
 await add.getByLabel('Type').selectOption('telegram');
 await add.getByLabel('Telegram chat (numeric ID or @channel)').fill('-1001234567890');
 await save(add,'add the chat','Add destination');
 await expect(add.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(page.locator('[data-destination-channel="telegram"]')).toContainText('Telegram; enabled');
 await expect(page.locator('[data-destination]')).toHaveCount(3);
 await closeDialogs(page);

 // Pausing keeps the endpoint and the secret (the page never held them) and moves the version.
 const row=page.locator(`[data-destination="${hookId}"]`);
 await row.getByRole('button',{name:/^Change/}).click();
 const change=form(page,`destination-${hookId}`);
 await change.getByLabel('Enabled').uncheck();
 await save(change,'pause while the receiver moves','Save destination');
 await expect(change.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(row).toHaveAttribute('data-destination-enabled','false');
 await expect(row).toHaveAttribute('data-destination-secret','set');
 await expect(row).toHaveAttribute('data-destination-version','2');
 const stored=await listOf(page,org,project);
 expect(stored.find((d)=>field(d,'id')===hookId)).toMatchObject({enabled:false,has_secret:true,version:'2',display:'hooks.example.test'});

 // Another administrator rotates the secret first: this page's version is stale, so its save is a visible conflict and changes nothing.
 const other=await postJson(page,'/api/v1/destinations',saveBody(org,project,'2',{id:hookId,enabled:false,secret:ROTATED},'another administrator rotates the secret'));
 expect(other.status,other.text).toBe(200);
 await change.getByLabel('Enabled').check();
 await save(change,'resume the hook','Save destination');
 await expect(change.locator('[data-write-result="conflict"]')).toContainText('nothing was changed');
 await expect(change.getByLabel('Reason (kept in the audit record)')).toHaveValue('resume the hook');
 await expect(row).toHaveAttribute('data-destination-version','3');
 await expect(row).toHaveAttribute('data-destination-enabled','false');
 // On the version it now shows, the same save commits.
 await change.getByLabel('Enabled').check();
 await change.getByRole('button',{name:'Save destination',exact:true}).click();
 await expect(change.locator('[data-write-result="committed"]')).toBeVisible();
 await expect(row).toHaveAttribute('data-destination-version','4');
 await expect(row).toHaveAttribute('data-destination-enabled','true');

 // A reload shows what the server holds.
 await page.reload();
 await activate(page);
 await expect(page.locator(`[data-destination="${hookId}"]`)).toHaveAttribute('data-destination-version','4');
 await expect(page.locator('[data-destination]')).toHaveCount(3);

 // The audit log names who saved what and why; no response or page ever carried the secret or the endpoint path.
 const me=field(await (await page.request.get('/api/v1/session')).json() as unknown,'user');
 if(typeof me!=='string')throw Error('no session user');
 const audit=await postJson(page,'/api/v1/admin/read',{org_id:org,kind:'audit'});
 const audits=field(audit.json,'audits');
 if(!Array.isArray(audits))throw Error(`audit: ${audit.text}`);
 const named=(principal:string,reason:string):boolean=>audits.some((a)=>field(a,'action')==='destination'&&field(a,'principal')===principal&&field(a,'reason')===reason);
 expect(named(me,'add the pager hook')).toBe(true);
 expect(named(me,'pause while the receiver moves')).toBe(true);
 expect(named(me,'resume the hook')).toBe(true);
 expect(named(me,'another administrator rotates the secret')).toBe(true);
 for(const body of bodies){expect(body).not.toContain(SECRET);expect(body).not.toContain(ROTATED);expect(body).not.toContain(TOKEN);}
 expect(bodies.length).toBeGreaterThan(8);
});

test('an account that holds only policy.write reads the destinations but cannot save one; a reader sees nothing',async({page,browser})=>{
 test.setTimeout(240_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'destination settings refusal org');
 const project=await createProject(page,org);
 const writer={id:id(),email:`dest-writer-${id().slice(0,8)}@example.test`,password:'destination writer password 2026'};
 const reader={id:id(),email:`dest-reader-${id().slice(0,8)}@example.test`,password:'destination reader password 2026'};
 for(const p of [writer,reader]){
  await adminCommand(page,org,'create_user',{id:p.id,email:p.email,password:p.password});
  await adminCommand(page,org,'membership',{user_id:p.id,enabled:true});
 }
 await adminCommand(page,org,'grant',{user_id:writer.id,project_id:project,enabled:true,permissions:['policy.write']});
 await adminCommand(page,org,'grant',{user_id:reader.id,project_id:project,enabled:true,permissions:['telemetry.read']});
 const created=await postJson(page,'/api/v1/destinations',saveBody(org,project,'0',{id:id(),type:'smtp',address:'ops@example.test',enabled:true},'the organization already has a destination'));
 expect(created.status,created.text).toBe(200);

 const wctx=await browser.newContext();
 const wp=await wctx.newPage();
 await login(wp,writer.email,writer.password);
 const content=await openDestinations(wp,org,project);
 await expect(content.locator('[data-destination]')).toHaveCount(1);
 await expect(content).toContainText('Only organization administrators change destinations');
 await expect(content.locator('form')).toHaveCount(0);
 // The route itself refuses the save: the page not offering it is not the protection.
 const refused=await postJson(wp,'/api/v1/destinations',saveBody(org,project,'0',{id:id(),type:'smtp',address:'x@example.test',enabled:true},'try as the policy writer'));
 expect(refused.status,refused.text).toBe(403);
 expect(await listOf(wp,org,project)).toHaveLength(1);

 const rctx=await browser.newContext();
 const rp=await rctx.newPage();
 await login(rp,reader.email,reader.password);
 const readerContent=await openDestinations(rp,org,project);
 await expect(readerContent.locator('[data-state="unauthorized"]').first()).toBeVisible();
 await expect(readerContent.locator('[data-destination]')).toHaveCount(0);
 await expect(readerContent.locator('form')).toHaveCount(0);
 expect((await postJson(rp,'/api/v1/destinations',{org,project_id:project,operation:'list'})).status).toBe(404);
 expect((await postJson(rp,'/api/v1/destinations',saveBody(org,project,'0',{id:id(),type:'smtp',address:'y@example.test',enabled:true},'try as the reader'))).status).toBe(404);
 await wctx.close();
 await rctx.close();
});
