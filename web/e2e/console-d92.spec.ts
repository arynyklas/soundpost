// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type APIRequestContext,type Page} from '@playwright/test';
import {createHmac} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createServer as createHttps,type Server} from 'node:https';
import type {IncomingHttpHeaders} from 'node:http';
import type {AddressInfo} from 'node:net';
import {adminCommand,createOrg,createProject,createReader,field,id,ingestError,login,onboardErrorSource,owner,postJson,reopen,type Source} from './support/real';
// The D92 console features against the REAL served process (internal/httpapi routes, the leader-only runner, the durable outbox), nothing seeded: an incident title and
// timeline notes, an error issue's owner, a project reader who reads issues, Copy as Markdown, the native GitLab create against a local stub (the stub stands in for a
// GitLab instance: no real GitLab is involved), an event webhook delivered to a local receiver whose signature is checked, and a release.write token that registers a
// release and records a deploy. The harness (web/e2e-harness/h.sh, E2E_NOTIFY_IP) starts the server with the private egress allow-list and the private CA, so the stub and
// the receiver (real HTTPS servers on the host's private address) are reached by the production dialer and egress rules unchanged.
const ip=process.env.E2E_NOTIFY_IP,pki=process.env.E2E_PKI;
if(!ip||!pki)throw new Error('E2E_NOTIFY_IP and E2E_PKI are required: run through web/e2e-harness/h.sh with E2E_NOTIFY_IP set to a private address of this host');
const nsOf=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:nsOf(Date.now()-3*3600_000),end:nsOf(Date.now()+3*3600_000)};
const link=(org:string,project:string,view:string,entity?:{param:'incident'|'target';id:string},page?:string):string=>`/#${new URLSearchParams({org,projects:project,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view,...(entity?{[entity.param]:`${project}:${entity.id}`}:{}),...(page?{page}:{})})}`;
const h1=(page:Page,name:string|RegExp)=>page.getByRole('heading',{level:1,name});
interface World{org:string;project:string;source:Source;incident:string;issue:string;user:string}
const sessionUser=async(page:Page):Promise<string>=>{const r=await page.request.get('/api/v1/session');const u=field(await r.json(),'user');if(typeof u!=='string')throw Error('no session user');return u;};

/** A real org + project + error source; one ingested unhandled error becomes (through the runner) an incident and an error issue. Returns both IDs read through the real routes. */
async function world(page:Page,api:APIRequestContext,name:string,errorClass='D92E2eFailure'):Promise<World>{
 const org=await createOrg(page,name);
 const project=await createProject(page,org);
 const source=await onboardErrorSource(page,org,project);
 await ingestError(api,source,{at:nsOf(Date.now()),class:errorClass,fatal:false,handled:false});
 let incident='',issue='';
 await expect.poll(async()=>{
  const q=await postJson(page,'/api/v1/queue',{org,projects:[project],limit:50});
  const entries=field(q.json,'entries');
  const first=Array.isArray(entries)?field(entries[0],'incident_id'):undefined;
  incident=typeof first==='string'?first:'';
  const l=await postJson(page,'/api/v1/issues/list',{org,projects:[project],limit:50});
  const items=field(l.json,'items');
  const i=Array.isArray(items)?field(items[0],'issue_id'):undefined;
  issue=typeof i==='string'?i:'';
  return incident!==''&&issue!=='';
 },{message:'the runner opens an incident and an issue for the ingested error',timeout:120_000,intervals:[250,500,1000]}).toBe(true);
 return {org,project,source,incident,issue,user:await sessionUser(page)};
}
async function incidentView(page:Page,w:World):Promise<{version:string;status:string;title?:string;owner?:string;external?:{state:string;url?:string}[];timeline:{type:string;note?:string;title?:string;external?:{kind:string;result?:string}}[]}>{
 const r=await postJson(page,'/api/v1/incidents/get',{org:w.org,project_id:w.project,target_id:w.incident});
 expect(r.status,r.text).toBe(200);
 return r.json as never;
}
async function issueItem(page:Page,w:World):Promise<{owner?:string;workflow:string;external?:{provider:string;state:string;iid?:string;url?:string}[]}>{
 const r=await postJson(page,'/api/v1/issues/list',{org:w.org,projects:[w.project],limit:50});
 expect(r.status,r.text).toBe(200);
 const items=field(r.json,'items') as {issue_id:string}[];
 return items.find((i)=>i.issue_id===w.issue) as never;
}
const outcome=(page:Page,kind:string)=>page.locator(`[data-outcome="${kind}"]`);

/** An HTTPS server on the host's private address with the run's leaf certificate (the server trusts the run CA and may reach exactly this address). */
function https(handler:Parameters<typeof createHttps>[1]):Promise<Server>{
 const {promise,resolve}=Promise.withResolvers<Server>();
 const server=createHttps({key:readFileSync(`${pki}/leaf.key`),cert:readFileSync(`${pki}/leaf.pem`)},handler);
 server.listen(0,ip,()=>resolve(server));
 return promise;
}
const portOf=(s:Server):number=>(s.address() as AddressInfo).port;
const GITLAB_TOKEN='e2e-stub-access-token-0001';

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
test('an incident gets a title and timeline notes, also after it is resolved; both read back from the server and a hostile note stays text',async({page,playwright})=>{
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const w=await world(page,api,'d92 incident title org');
 await reopen(page,link(w.org,w.project,'incidents',{param:'incident',id:w.incident}));
 const title=page.locator('h1.inc-title');
 await expect(title).toHaveText(/^Incident [0-9a-f]{8}/);
 await expect(page.getByTestId('revision')).toContainText('Revision 1');

 // Set the title through the More menu.
 const TITLE='Checkout fails for EU customers';
 const setTitle=async(text:string):Promise<void>=>{
  await page.getByRole('button',{name:/^More actions/}).click();
  await page.getByRole('menuitem',{name:'Set title',exact:true}).click();
  const dialog=page.getByTestId('incident-action-dialog');
  await dialog.getByLabel(/^Title/).fill(text);
  await dialog.locator('button[type=submit]').click();
 };
 await setTitle(TITLE);
 await expect(title).toHaveText(TITLE);
 expect(await incidentView(page,w)).toMatchObject({title:TITLE,version:'2'});
 await expect(page.locator('li[data-type="title"]')).toHaveCount(1);
 // The same title again is refused by the server with its own words, and nothing changes.
 await setTitle(TITLE);
 await expect(outcome(page,'refused')).toContainText('already has this title');
 expect((await incidentView(page,w)).version).toBe('2');
 await page.keyboard.press('Escape');
 await expect(page.getByTestId('incident-action-dialog')).toHaveCount(0);

 // Notes: append-only text; a hostile one is text.
 const composer=page.getByTestId('note-composer');
 const NOTE='Rolled the canary back; the EU shard still fails.';
 await composer.getByLabel('Add a note to the timeline').fill(NOTE);
 await composer.getByRole('button',{name:'Post note',exact:true}).click();
 await expect(page.locator('[data-note-outcome="committed"]')).toBeVisible();
 await expect(page.locator('li[data-type="note"] .inc-quote').filter({hasText:NOTE})).toBeVisible();
 const HOSTILE='<img src=x onerror="window.__pwn=1"> **bold** [x](https://evil.example.test)';
 await composer.getByLabel('Add a note to the timeline').fill(HOSTILE);
 await composer.getByRole('button',{name:'Post note',exact:true}).click();
 await expect(page.locator('li[data-type="note"] .inc-quote').filter({hasText:HOSTILE})).toBeVisible();
 expect(await page.evaluate(()=>(window as unknown as {__pwn?:number}).__pwn)).toBeUndefined();
 expect(await page.locator('li[data-type="note"] img').count()).toBe(0);
 let view=await incidentView(page,w);
 expect(view.timeline.filter((e)=>e.type==='note').map((e)=>e.note)).toEqual([NOTE,HOSTILE]);

 // Resolve: a resolved incident takes no response action, but still takes notes.
 await page.getByRole('button',{name:'Resolve incident',exact:true}).click();
 const dialog=page.getByTestId('incident-action-dialog');
 await dialog.getByLabel(/^Reason/).fill('Fixed by the rollback');
 await dialog.locator('button[type=submit]').click();
 await expect(page.getByTestId('revision')).toContainText('Revision 5');
 await expect(page.getByRole('button',{name:'Resolve incident',exact:true})).toHaveCount(0);
 await composer.getByLabel('Add a note to the timeline').fill('Post-incident: add a canary alert.');
 await composer.getByRole('button',{name:'Post note',exact:true}).click();
 await expect(page.locator('[data-note-outcome="committed"]')).toBeVisible();
 view=await incidentView(page,w);
 expect(view.status).toBe('resolved');
 expect(view.timeline.filter((e)=>e.type==='note')).toHaveLength(3);
 // A title can still name a resolved incident.
 await setTitle('Checkout failure (resolved)');
 await expect(title).toHaveText('Checkout failure (resolved)');
 // Reload: the server's own record is what the page shows.
 await reopen(page,link(w.org,w.project,'incidents',{param:'incident',id:w.incident}));
 await expect(title).toHaveText('Checkout failure (resolved)');
 await expect(page.locator('li[data-type="note"]')).toHaveCount(3);
 // The list names the incident by its title.
 await reopen(page,link(w.org,w.project,'incidents'));
 await expect(page.locator(`tr[data-incident="${w.incident}"]`)).toContainText('Checkout failure (resolved)');
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
test('an error issue is assigned and reassigned to a member by display name; the display name is set and cleared and the form checks the answer',async({page,playwright})=>{
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const w=await world(page,api,'d92 issue owner org');
 const member=await createReader(page,w.org,[w.project]);

 // The display name: set, cleared, set again, each confirmed by the server's own `set` / `cleared`.
 await reopen(page,link(w.org,w.project,'settings',undefined,'organization'));
 const form=page.getByRole('form',{name:'Set a display name'});
 await expect(form).toBeVisible();
 await form.getByLabel('Member').selectOption(member.id);
 await form.getByLabel(/^Display name/).fill('Rita Reader');
 await form.getByRole('button',{name:'Save display name'}).click();
 await expect(form.locator('.set-note-ok')).toHaveText('The display name was saved.');
 let dir=await postJson(page,'/api/v1/directory',{org:w.org});
 expect((field(dir.json,'members') as {id:string;display_name?:string}[]).find((m)=>m.id===member.id)?.display_name).toBe('Rita Reader');
 await form.getByLabel(/^Display name/).fill('');
 await form.getByRole('button',{name:'Save display name'}).click();
 await expect(form.locator('.set-note-ok')).toHaveText('The display name was cleared.');
 dir=await postJson(page,'/api/v1/directory',{org:w.org});
 expect((field(dir.json,'members') as {id:string;display_name?:string}[]).find((m)=>m.id===member.id)?.display_name).toBeUndefined();
 await form.getByLabel(/^Display name/).fill('Rita Reader');
 await form.getByRole('button',{name:'Save display name'}).click();
 await expect(form.locator('.set-note-ok')).toHaveText('The display name was saved.');
 // A name the server refuses (a control character) is not shown as saved.
 const bad=await postJson(page,'/api/v1/directory/names',{org:w.org,command_id:id(),user:member.id,display_name:'bad\u0007name'});
 expect(bad.status).toBe(400);
 expect(field(bad.json,'detail')).toBe('display_name_invalid');

 // The issue page: Reassign to the member by name.
 await reopen(page,link(w.org,w.project,'issues',{param:'target',id:w.issue}));
 await expect(page.locator(`h1[data-issue="${w.issue}"]`)).toBeVisible();
 await expect(page.getByTestId('issue-reassign')).toBeEnabled();
 await page.getByTestId('issue-reassign').click();
 const dialog=page.getByTestId('issue-owner-dialog');
 await dialog.getByRole('combobox',{name:'Owner',exact:true}).selectOption({label:'Rita Reader'});
 await dialog.getByRole('button',{name:'Assign',exact:true}).click();
 await expect(page.getByTestId('issue-action-committed')).toBeVisible();
 await expect(page.locator('.iss-actions')).toContainText('Rita Reader');
 expect((await issueItem(page,w)).owner).toBe(member.id);
 // An account that is not a member of the organization is refused with the server's own words; the owner stays.
 await page.getByTestId('issue-reassign').click();
 const again=page.getByTestId('issue-owner-dialog');
 await again.getByLabel('Or a member account ID').fill(id());
 await again.getByRole('button',{name:'Assign',exact:true}).click();
 await expect(again.locator('[data-outcome="refused"]')).toContainText('not a member of this organization');
 expect((await issueItem(page,w)).owner).toBe(member.id);
 // Remove the owner.
 await again.getByLabel('Or a member account ID').fill('');
 await again.getByRole('combobox',{name:'Owner',exact:true}).selectOption('');
 await again.getByRole('button',{name:'Remove the owner',exact:true}).click();
 await expect(page.getByTestId('issue-action-committed')).toBeVisible();
 await expect(page.locator('.iss-actions')).toContainText('Unassigned');
 expect((await issueItem(page,w)).owner).toBeUndefined();
 // The list filters by owner `none` and shows the row.
 await reopen(page,link(w.org,w.project,'issues'));
 await expect(page.locator(`[data-testid="issue-row"][data-issue="${w.issue}"]`)).toBeVisible();
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
test('a project reader reads the issues of the project (list and page) but cannot change them; a reader of another project reads none',async({page,browser,playwright})=>{
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const w=await world(page,api,'d92 reader org');
 const otherProject=await createProject(page,w.org,'other project');
 const reader=await createReader(page,w.org,[w.project]);
 const stranger=await createReader(page,w.org,[otherProject]);

 const ctx=await browser.newContext();
 const rp=await ctx.newPage();
 await login(rp,reader.email,reader.password);
 await reopen(rp,link(w.org,w.project,'issues'));
 const row=rp.locator(`[data-testid="issue-row"][data-issue="${w.issue}"]`);
 await expect(row).toBeVisible();
 await expect(rp.getByText('issue_evidence_needs_org_admin')).toHaveCount(0);
 await row.getByRole('link').first().click();
 await expect(rp.locator(`h1[data-issue="${w.issue}"]`)).toBeVisible();
 await expect(rp.locator('section[data-section="grouping"]')).toBeVisible();
 await expect(rp.locator('section[data-section="occurrences"]')).toBeVisible();
 // The reader holds no write grant: the server refuses the change as it refuses a missing issue, and the page says so; nothing changes.
 await rp.getByTestId('issue-reassign').click();
 const dialog=rp.getByTestId('issue-owner-dialog');
 await dialog.getByLabel('Or a member account ID').fill(reader.id);
 await dialog.getByRole('button',{name:'Assign',exact:true}).click();
 await expect(dialog.locator('[data-outcome="refused"]')).toContainText('not found or is not available to this account');
 expect((await issueItem(page,w)).owner).toBeUndefined();
 const evidence=await postJson(rp,'/api/v1/evidence/issue',{org:w.org,project:w.project,issue:w.issue});
 expect(evidence.status,evidence.text).toBe(200);
 // The same reader reads the Markdown of the issue; nobody reads another project's issue.
 const markdown=await postJson(rp,'/api/v1/issues/markdown',{org:w.org,project_id:w.project,id:w.issue,format:'description'});
 expect(markdown.status,markdown.text).toBe(200);

 const sctx=await browser.newContext();
 const sp=await sctx.newPage();
 await login(sp,stranger.email,stranger.password);
 const list=await postJson(sp,'/api/v1/issues/list',{org:w.org,projects:[w.project],limit:50});
 expect(list.status).toBe(404);
 const read=await postJson(sp,'/api/v1/evidence/issue',{org:w.org,project:w.project,issue:w.issue});
 expect(read.status).toBe(404);
 const own=await postJson(sp,'/api/v1/issues/list',{org:w.org,projects:[otherProject],limit:50});
 expect(own.status,own.text).toBe(200);
 expect(field(own.json,'items')).toEqual([]);
 await sctx.close();await ctx.close();
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
test('Copy as Markdown: link, task description and timeline come from the server; the description holds no title or note, the timeline escapes a hostile note',async({page,playwright,browserName,context})=>{
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const w=await world(page,api,'d92 markdown org');
 if(browserName==='chromium')await context.grantPermissions(['clipboard-read','clipboard-write']);
 await reopen(page,link(w.org,w.project,'incidents',{param:'incident',id:w.incident}));
 const SECRET_TITLE='Customer ACME-4711 cannot pay';
 const NOTE='Mentions @everyone and <b>bold</b> and #123';
 await page.getByRole('button',{name:/^More actions/}).click();
 await page.getByRole('menuitem',{name:'Set title',exact:true}).click();
 await page.getByTestId('incident-action-dialog').getByLabel(/^Title/).fill(SECRET_TITLE);
 await page.getByTestId('incident-action-dialog').locator('button[type=submit]').click();
 await expect(page.locator('h1.inc-title')).toHaveText(SECRET_TITLE);
 const composer=page.getByTestId('note-composer');
 await composer.getByLabel('Add a note to the timeline').fill(NOTE);
 await composer.getByRole('button',{name:'Post note',exact:true}).click();
 await expect(page.locator('[data-note-outcome="committed"]')).toBeVisible();

 const md=async(entity:'incidents'|'issues',format:string,project=w.project,target=entity==='incidents'?w.incident:w.issue)=>{
  const r=await postJson(page,`/api/v1/${entity}/markdown`,{org:w.org,project_id:project,id:target,format});
  expect(r.status,r.text).toBe(200);
  return r.json as {state:string;markdown?:string;reason?:string};
 };
 const linkMd=await md('incidents','link');
 expect(linkMd.state).toBe('ready');
 expect(linkMd.markdown).toContain(`incident=${w.project}:${w.incident}`);
 const description=await md('incidents','description');
 expect(description.markdown).not.toContain('ACME');
 expect(description.markdown).not.toContain('everyone');
 expect(description.markdown).toContain(w.incident);
 const timeline=await md('incidents','timeline');
 const text=timeline.markdown??'';
 expect(text).toContain('everyone');
 // Nothing in the copied note can ping, cross-link or inject: the trigger characters are defused with U+200B and the Markdown/HTML ones escaped.
 expect(text).not.toContain('@everyone');
 expect(text).not.toContain('<b>');
 expect(text).not.toContain('#123');
 const issueDescription=await md('issues','description');
 expect(issueDescription.markdown).toContain(w.issue);
 const bad=await postJson(page,'/api/v1/issues/markdown',{org:w.org,project_id:w.project,id:w.issue,format:'timeline'});
 expect(bad.status).toBe(400);

 // The menu: each item puts the server's Markdown on the clipboard (or, where the browser refuses it, shows it to copy by hand), in words.
 const copy=async(item:string,done:RegExp):Promise<string|undefined>=>{
  await page.getByTestId('copy-menu').getByRole('button',{name:'Copy'}).click();
  await page.getByRole('menuitem',{name:item,exact:true}).click();
  await expect(page.locator('.gl-copy-note')).toContainText(done);
  return browserName==='chromium'?await page.evaluate(()=>navigator.clipboard.readText()):undefined;
 };
 const copiedLink=await copy('Link',/Link copied\.|did not allow copying/);
 if(copiedLink!==undefined)expect(copiedLink).toBe(linkMd.markdown);
 const copiedDescription=await copy('Task description as Markdown',/Task description copied as Markdown\.|did not allow copying/);
 if(copiedDescription!==undefined)expect(copiedDescription).toBe(description.markdown);
 const copiedTimeline=await copy('Timeline as Markdown',/Timeline copied as Markdown\.|did not allow copying/);
 if(copiedTimeline!==undefined)expect(copiedTimeline).toBe(timeline.markdown);
 await expect(page.locator('.gl-copy-note')).not.toContainText('not available yet');
 // The issue page has the first two.
 await reopen(page,link(w.org,w.project,'issues',{param:'target',id:w.issue}));
 await page.getByTestId('copy-menu').getByRole('button',{name:'Copy'}).click();
 await expect(page.getByRole('menuitem')).toHaveCount(2);
 await page.getByRole('menuitem',{name:'Link',exact:true}).click();
 await expect(page.locator('.gl-copy-note')).toContainText(/Link copied\.|did not allow copying/);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
interface GitlabIssue{iid:number;title:string;description:string}
interface Stub{server:Server;url:string;issues:GitlabIssue[];posts:number;tokens:string[];paths:string[];mode:{value:'ok'|'create_then_500'}}
async function gitlabStub():Promise<Stub>{
 const stub:Stub={server:undefined as never,url:'',issues:[],posts:0,tokens:[],paths:[],mode:{value:'ok'}};
 stub.server=await https((req,res)=>{
  const url=new URL(req.url??'/','https://stub');
  stub.paths.push(`${req.method} ${url.pathname}`);
  stub.tokens.push(String(req.headers['private-token']??''));
  const send=(status:number,body:unknown):void=>{res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(body));};
  const web=(i:GitlabIssue):string=>`${stub.url}/group/project/-/issues/${i.iid}`;
  if(req.method==='GET'&&url.pathname==='/api/v4/personal_access_tokens/self')return send(200,{active:true,scopes:['api'],expires_at:'2099-01-01'});
  if(req.method==='GET'&&/\/issues$/.test(url.pathname)){
   const search=url.searchParams.get('search')??'';
   return send(200,stub.issues.filter((i)=>i.description.includes(search)).map((i)=>({iid:i.iid,web_url:web(i),description:i.description})));
  }
  if(req.method==='POST'&&/\/issues$/.test(url.pathname)){
   const chunks:Buffer[]=[];
   req.on('data',(c:Buffer)=>chunks.push(c));
   req.on('end',()=>{
    const body=JSON.parse(Buffer.concat(chunks).toString('utf8')) as {title:string;description:string};
    stub.posts++;
    const issue={iid:stub.issues.length+1,title:body.title,description:body.description};
    stub.issues.push(issue);
    if(stub.mode.value==='create_then_500')return send(500,{message:'boom'});
    send(201,{iid:issue.iid,web_url:web(issue),description:issue.description});
   });
   return;
  }
  send(404,{message:'not found'});
 });
 stub.url=`https://${ip}:${portOf(stub.server)}`;
 return stub;
}

test('GitLab: connect from the settings screen, then create one issue from an incident and from an error issue against a local stub; an unknown outcome is rechecked by its marker; a member sees but cannot edit',async({page,browser,playwright})=>{
 test.setTimeout(420_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const w=await world(page,api,'d92 gitlab org');
 const member=await createReader(page,w.org,[w.project]);
 const stub=await gitlabStub();
 try{
  // Before the connection: the dialog says why nothing can be created.
  await reopen(page,link(w.org,w.project,'incidents',{param:'incident',id:w.incident}));
  await page.getByRole('button',{name:'Create GitLab issue',exact:true}).click();
  await expect(page.getByTestId('gitlab-unavailable')).toContainText('not connected');
  await expect(page.getByRole('dialog')).not.toContainText('not available yet');
  await page.keyboard.press('Escape');

  // The settings screen.
  await reopen(page,link(w.org,w.project,'gitlab'));
  await expect(h1(page,'GitLab')).toBeVisible();
  await expect(page.getByTestId('gitlab-state')).toHaveText('Not connected');
  await page.getByRole('button',{name:'Connect GitLab',exact:true}).click();
  const form=page.getByRole('form',{name:'Change the GitLab connection'});
  await form.getByLabel(/^GitLab address/).fill(stub.url);
  await form.getByLabel(/^Access token/).fill(GITLAB_TOKEN);
  await form.getByRole('button',{name:'Map a project'}).click();
  await form.getByLabel('Mapping 1: Soundpost project').selectOption(w.project);
  await form.getByLabel('Mapping 1: GitLab project (group/project)').fill('group/project');
  await form.getByLabel('Mapping 1: default labels (comma separated)').fill('soundpost, e2e');
  await form.getByLabel(/^Reason/).fill('connect the stub');
  await form.getByRole('button',{name:'Connect',exact:true}).click();
  await expect(form.locator('[data-write-result="committed"]')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByTestId('gitlab-state')).toHaveText('Connected');
  await expect(page.locator(`[data-gitlab-project="${w.project}"]`)).toContainText('group/project');
  await page.getByRole('button',{name:'Test connection'}).click();
  await expect(page.getByTestId('gitlab-test')).toContainText('GitLab accepted the token');
  expect(stub.tokens.every((t)=>t===GITLAB_TOKEN)).toBe(true);
  // The token is never shown again.
  expect(await page.content()).not.toContain(GITLAB_TOKEN);

  // A member reads the connection (can_edit false): no button to change it.
  const mctx=await browser.newContext();
  const mp=await mctx.newPage();
  await login(mp,member.email,member.password);
  await reopen(mp,link(w.org,w.project,'gitlab'));
  await expect(mp.getByTestId('gitlab-state')).toHaveText('Connected');
  await expect(mp.getByText('Only organization administrators change the connection.')).toBeVisible();
  await expect(mp.getByRole('button',{name:'Change connection or token'})).toHaveCount(0);
  await expect(mp.getByRole('button',{name:'Test connection'})).toHaveCount(0);
  await mctx.close();

  // Create from the incident.
  await reopen(page,link(w.org,w.project,'incidents',{param:'incident',id:w.incident}));
  await page.getByRole('button',{name:'Create GitLab issue',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Create GitLab issue'});
  await expect(dialog.getByTestId('gitlab-description')).toContainText(w.incident);
  await expect(dialog.getByTestId('gitlab-description')).not.toContainText('soundpost-ref-');
  await expect(dialog.getByLabel('Title',{exact:true})).toHaveValue(/^Soundpost incident [0-9a-f]{8}$/);
  await dialog.getByLabel('Title',{exact:true}).fill('Checkout down');
  await dialog.getByRole('button',{name:'Create issue',exact:true}).click();
  await expect(dialog.locator('[data-gitlab-outcome="linked"]')).toContainText('GitLab issue created and linked');
  expect(stub.posts).toBe(1);
  expect(stub.issues[0]).toMatchObject({title:'Checkout down'});
  expect(stub.issues[0]?.description).toMatch(/soundpost-ref-/);
  expect(stub.issues[0]?.description).toContain(w.incident);
  const incident=await incidentView(page,w);
  expect(incident.timeline.map((e)=>e.type)).toEqual(expect.arrayContaining(['external_begin','external_end']));
  expect(incident.external?.[0]).toMatchObject({state:'linked',url:`${stub.url}/group/project/-/issues/1`});
  await page.keyboard.press('Escape');
  await reopen(page,link(w.org,w.project,'incidents',{param:'incident',id:w.incident}));
  await expect(page.getByRole('link',{name:/group\/project#1/})).toBeVisible();
  // One GitLab issue per entity, ever: the dialog shows the stored link and offers no second create.
  await page.getByRole('button',{name:'Create GitLab issue',exact:true}).click();
  await expect(page.getByTestId('gitlab-existing')).toContainText('already has the GitLab issue');
  await expect(page.getByRole('button',{name:'Create issue',exact:true})).toHaveCount(0);
  expect(stub.posts).toBe(1);
  await page.keyboard.press('Escape');

  // Create from the error issue; the stub answers 500 after it created the issue: the outcome is unknown, never a failure, and the recheck finds it by its marker.
  stub.mode.value='create_then_500';
  await reopen(page,link(w.org,w.project,'issues',{param:'target',id:w.issue}));
  await page.getByTestId('gitlab-create').click();
  const idialog=page.getByRole('dialog',{name:'Create GitLab issue'});
  await expect(idialog.getByRole('button',{name:'Create issue',exact:true})).toBeEnabled();
  await idialog.getByRole('button',{name:'Create issue',exact:true}).click();
  await expect(idialog.locator('[data-gitlab-outcome="unknown"]')).toContainText('Outcome unknown');
  expect(stub.posts).toBe(2);
  stub.mode.value='ok';
  await idialog.getByRole('button',{name:'Check whether it was created',exact:true}).click();
  await expect(idialog.locator('[data-gitlab-outcome="linked"]')).toBeVisible();
  expect(stub.posts).toBe(2);
  expect((await issueItem(page,w)).external?.[0]).toMatchObject({provider:'gitlab',state:'linked',iid:'2'});
  await page.keyboard.press('Escape');
  await reopen(page,link(w.org,w.project,'issues',{param:'target',id:w.issue}));
  await expect(page.locator('.iss-actions').getByRole('link',{name:/group\/project#2/})).toBeVisible();
  // The issues list shows the link too.
  await reopen(page,link(w.org,w.project,'issues'));
  await expect(page.locator(`[data-testid="issue-row"][data-issue="${w.issue}"]`).getByRole('link',{name:/group\/project#2/})).toBeVisible();
  // Only identifiers cross the boundary: never the title, a note or telemetry text.
  for(const i of stub.issues)expect(i.description).not.toContain('D92E2eFailure');
 }finally{
  stub.server.close();
 }
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
interface Hit{headers:IncomingHttpHeaders;body:string}
test('an event webhook: created in the settings screen, signed deliveries reach a local receiver with their signature checked, a rotated secret signs with both, a refusing receiver is shown as failing',async({page,playwright})=>{
 test.setTimeout(480_000);
 const who=owner();
 await login(page,who.email,who.password);
 const api=await playwright.request.newContext();
 const org=await createOrg(page,'d92 events org');
 const project=await createProject(page,org);
 const hits:Hit[]=[];
 let answer=200;
 const server=await https((req,res)=>{
  const chunks:Buffer[]=[];
  req.on('data',(c:Buffer)=>chunks.push(c));
  req.on('end',()=>{hits.push({headers:req.headers,body:Buffer.concat(chunks).toString('utf8')});res.writeHead(answer);res.end('ok');});
 });
 const SECRET='e2e-event-secret-0123456789abcdef';
 const NEW_SECRET='e2e-event-secret-ROTATED-0123456789';
 const sign=(secret:string,h:Hit):string=>{
  const ts=String(h.headers['soundpost-timestamp']),delivery=String(h.headers['soundpost-delivery-id']);
  return `v1=${createHmac('sha256',secret).update(`${ts}.${delivery}.${h.body}`).digest('hex')}`;
 };
 const signatures=(h:Hit):string[]=>String(h.headers['soundpost-signature']).split(',');
 const eventsOf=(name:string):Hit[]=>hits.filter((h)=>h.headers['soundpost-event']===name);
 try{
  await reopen(page,link(org,project,'events'));
  await expect(h1(page,'Event webhooks')).toBeVisible();
  await expect(page.getByRole('heading',{level:2,name:'Event webhooks are not available yet'})).toHaveCount(0);
  await expect(page.getByRole('list',{name:'Events an endpoint can receive'}).locator('li')).toHaveCount(8);
  await expect(page.getByRole('list',{name:'Events an endpoint can receive'})).toContainText('issue.reopened');
  await page.getByRole('button',{name:'New endpoint',exact:true}).click();
  const form=page.getByRole('form',{name:'Add an event endpoint'});
  await form.getByLabel('Name').fill('e2e receiver');
  await form.getByLabel(/^Address/).fill(`https://${ip}:${portOf(server)}/hook`);
  for(const n of ['incident.opened','issue.new','issue.resolved','issue.reopened'])await form.getByRole('checkbox',{name:new RegExp(`^${n.replace('.','\\.')}`)}).check();
  await form.getByLabel(/^Secret/).fill(SECRET);
  await form.getByLabel(/^Reason/).fill('receive events in the e2e');
  await form.getByRole('button',{name:'Add endpoint',exact:true}).click();
  await expect(form.locator('[data-write-result="committed"]')).toBeVisible();
  await page.keyboard.press('Escape');
  const row=page.locator('[data-endpoint]');
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute('data-endpoint-state','no_deliveries');
  await expect(row).not.toContainText(SECRET);

  // The test button: one request, exactly one signed test.ping to this endpoint only. A request made before the project's baseline runner pass is still delivered once.
  await page.getByRole('button',{name:'Show deliveries of e2e receiver'}).click();
  await page.getByRole('button',{name:'Send a test event'}).click();
  await expect(page.getByText(/A test event was requested/)).toBeVisible();
  await expect.poll(()=>eventsOf('test.ping').length,{timeout:90_000,intervals:[500,1000]}).toBe(1);
  const ping=eventsOf('test.ping')[0] as Hit;
  expect(signatures(ping)).toEqual([sign(SECRET,ping)]);
  const body=JSON.parse(ping.body) as Record<string,unknown>;
  expect(body).toMatchObject({version:1,event:'test.ping',org});
  expect(body.delivery_id).toBe(ping.headers['soundpost-delivery-id']);
  expect(Object.keys(body).sort()).toEqual(expect.arrayContaining(['delivery_id','event','occurred_at','org','project','url','version']));
  await page.getByLabel('Deliveries of an endpoint').getByRole('button',{name:'Refresh'}).click();
  await expect(page.locator('[data-delivery-phase]').first()).toBeVisible();
  await expect(page.locator('[data-delivery-phase]').first()).toContainText('Accepted');
  // The list of endpoints is read again by opening the page (the deliveries pane's own Refresh reads only that endpoint's deliveries).
  await reopen(page,link(org,project,'events'));
  await expect(page.locator('[data-endpoint]')).toHaveAttribute('data-endpoint-state','working',{timeout:60_000});

  // Real events from real committed transitions: an ingested error opens an incident and an issue.
  const source=await onboardErrorSource(page,org,project);
  await ingestError(api,source,{at:nsOf(Date.now()),class:'EventE2eFailure',fatal:false,handled:false});
  await expect.poll(()=>eventsOf('incident.opened').length+eventsOf('issue.new').length,{timeout:120_000,intervals:[500,1000]}).toBeGreaterThanOrEqual(2);
  const opened=JSON.parse(eventsOf('incident.opened')[0]!.body) as Record<string,unknown>;
  const fresh=JSON.parse(eventsOf('issue.new')[0]!.body) as Record<string,unknown>;
  expect(opened).toMatchObject({version:1,event:'incident.opened',org,project});
  expect(fresh).toMatchObject({version:1,event:'issue.new',org,project});
  expect(String(opened.url)).toContain('#view=incidents');
  // Identifiers and links only: nothing of the error's text.
  for(const h of hits)expect(h.body).not.toContain('EventE2eFailure');
  for(const h of eventsOf('issue.new').concat(eventsOf('incident.opened')))expect(signatures(h)).toEqual([sign(SECRET,h)]);
  const issue=String(fresh.issue);

  // A person resolves and then reopens the issue: issue.resolved, then issue.reopened (not issue.regressed).
  const act=async(button:string):Promise<void>=>{
   await page.getByTestId('issue-action-open').filter({hasText:button}).click();
   const dialog=page.getByTestId('issue-action-dialog');
   await dialog.getByLabel(/^Reason/).fill(`${button} in the e2e`);
   await dialog.locator('button[type=submit]').click();
   await expect(page.getByTestId('issue-action-committed')).toBeVisible();
  };
  await reopen(page,link(org,project,'issues',{param:'target',id:issue}));
  await act('Resolve error issue');
  await expect.poll(()=>eventsOf('issue.resolved').length,{timeout:90_000,intervals:[500,1000]}).toBe(1);
  await reopen(page,link(org,project,'issues',{param:'target',id:issue}));
  await act('Reopen');
  await expect.poll(()=>eventsOf('issue.reopened').length,{timeout:90_000,intervals:[500,1000]}).toBe(1);
  expect(eventsOf('issue.regressed')).toHaveLength(0);
  expect(JSON.parse(eventsOf('issue.reopened')[0]!.body)).toMatchObject({event:'issue.reopened',issue,org,project});
  // The same delivery is never delivered under two IDs.
  const ids=hits.map((h)=>h.headers['soundpost-delivery-id']);
  expect(new Set(ids).size).toBe(ids.length);

  // Rotate the secret: both secrets sign from now on.
  await reopen(page,link(org,project,'events'));
  await page.getByRole('button',{name:'Change event endpoint e2e receiver'}).click();
  const change=page.getByRole('form',{name:/^Change event endpoint/});
  await change.getByLabel(/^New secret/).fill(NEW_SECRET);
  await change.getByLabel(/^Reason/).fill('rotate');
  await change.getByRole('button',{name:'Save endpoint',exact:true}).click();
  await expect(change.locator('[data-write-result="committed"]')).toContainText('two signatures');
  await page.keyboard.press('Escape');
  const before=hits.length;
  await page.getByRole('button',{name:'Show deliveries of e2e receiver'}).click();
  await page.getByRole('button',{name:'Send a test event'}).click();
  await expect.poll(()=>hits.length,{timeout:90_000,intervals:[500,1000]}).toBeGreaterThan(before);
  const rotated=hits[hits.length-1] as Hit;
  expect(signatures(rotated)).toHaveLength(2);
  expect(signatures(rotated)).toEqual(expect.arrayContaining([sign(SECRET,rotated),sign(NEW_SECRET,rotated)]));

  // A receiver that refuses: the delivery is retried and the endpoint is shown as retrying or failing, never working.
  answer=500;
  const refused=hits.length;
  await page.getByRole('button',{name:'Send a test event'}).click();
  await expect.poll(()=>hits.length,{timeout:90_000,intervals:[500,1000]}).toBeGreaterThan(refused);
  await page.getByLabel('Deliveries of an endpoint').getByRole('button',{name:'Refresh'}).click();
  await expect(page.locator('[data-delivery-phase]').first()).toBeVisible();
  await reopen(page,link(org,project,'events'));
  await expect(page.locator('[data-endpoint]')).toHaveAttribute('data-endpoint-state',/retrying|failing/,{timeout:60_000});
 }finally{
  server.close();
 }
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
test('a release.write token registers a release and records its deploy for its own project only, and can do nothing else',async({page,playwright})=>{
 test.setTimeout(300_000);
 const who=owner();
 await login(page,who.email,who.password);
 const org=await createOrg(page,'d92 release token org');
 const project=await createProject(page,org);
 const other=await createProject(page,org,'other project');
 const source=await onboardErrorSource(page,org,project);
 const principal=await sessionUser(page);
 // A server token names a member of the organization as its principal (and, for release.write, an administrator of it): the creator administers the organization but is not yet a member.
 await adminCommand(page,org,'membership',{user_id:principal,enabled:true});
 const issued=await postJson(page,'/api/v1/admin/tokens/issue',{org_id:org,principal,projects:[project],permissions:['release.write'],expires:String(Math.floor(Date.now()/1000)+3600),reason:'e2e release pipeline'});
 expect(issued.status,issued.text).toBe(200);
 const token=String(field(issued.json,'token'));
 const tokenId=String(field(issued.json,'id'));
 expect(token.length).toBeGreaterThan(20);
 const bearer={Authorization:`Bearer ${token}`};
 const ci=await playwright.request.newContext();
 const post=(path:string,data:unknown)=>ci.post(path,{headers:bearer,data});

 // A token cannot read the control revision, so the server supplies it: the pipeline sends none, and a registration is an idempotent append.
 const release=id();
 const buildId=id(),commandId=id();
 const registerAs=(project:string,release:string,label:string,build=id(),command=id())=>post('/api/v1/releases/register',{org,project,command_id:command,release:{id:release,org,project,build_id:build,parents:[],build_time_ns:'5',debug_artifacts:[],display_label:label,revision:'0'}});
 const registered=await registerAs(project,release,'ci build 1',buildId,commandId);
 expect(registered.status(),await registered.text()).toBe(200);
 // The same identity and command again answers the original receipt; the same release id with another build, or another label, is a conflict.
 const again=await registerAs(project,release,'ci build 1',buildId,commandId);
 expect(again.status(),await again.text()).toBe(200);
 expect(await again.json()).toEqual(await registered.json());
 const otherBuild=await registerAs(project,release,'ci build 1',id());
 expect(otherBuild.status(),await otherBuild.text()).toBe(409);
 expect(field(await otherBuild.json(),'detail')).toBe('release_conflict');
 expect((await registerAs(project,release,'a new label',buildId)).status()).toBe(409);
 // A deploy marker: an environment an active source policy of the project lists.
 const record=await post('/api/v1/releases/deploys',{op:'record',org,project,release,environment:source.environment,command_id:id()});
 expect(record.status(),await record.text()).toBe(200);
 expect(await record.json()).toMatchObject({project_id:project,release_id:release,environment:source.environment,count:'1'});
 const deployAgain=await post('/api/v1/releases/deploys',{op:'record',org,project,release,environment:source.environment,command_id:id()});
 expect(await deployAgain.json()).toMatchObject({count:'2'});
 // Another project, another environment and every other route are refused; the token reads nothing.
 expect((await registerAs(other,id(),'not mine')).status()).toBe(404);
 expect((await post('/api/v1/releases/deploys',{op:'record',org,project:other,release,environment:source.environment,command_id:id()})).status()).toBe(404);
 expect((await post('/api/v1/releases/deploys',{op:'record',org,project,release,environment:id(),command_id:id()})).status()).toBe(400);
 for(const path of ['/api/v1/releases/list','/api/v1/issues/list','/api/v1/queue'])expect((await post(path,{org,projects:[project]})).status(),path).toBeGreaterThanOrEqual(400);
 expect((await post('/api/v1/admin/tokens/list',{org_id:org})).status()).toBeGreaterThanOrEqual(400);

 // The token list (an administrator, fresh session) shows it without the secret; the console shows the release with its deploy.
 const list=await postJson(page,'/api/v1/admin/tokens/list',{org_id:org});
 expect(list.status,list.text).toBe(200);
 expect(list.text).not.toContain(token);
 expect(field(list.json,'tokens')).toEqual([expect.objectContaining({id:tokenId,principal,projects:[project],permissions:['release.write'],state:'active'})]);
 const rows=await postJson(page,'/api/v1/releases/list',{org,projects:[project],limit:50});
 expect(rows.status,rows.text).toBe(200);
 const item=(field(rows.json,'items') as {release_id:string;deploy_state:string;deploys:{environment:string}[];counts_state:string}[]).find((i)=>i.release_id===release);
 expect(item).toMatchObject({deploy_state:'known',deploys:[{environment:source.environment}]});
 await reopen(page,link(org,project,'releases'));
 await expect(page.getByText('ci build 1')).toBeVisible();
 await expect(page.getByText(/deploy time unknown/)).toHaveCount(0);

 // Revoked, the token no longer authenticates: refused with 401 (the same bearer that was answered above).
 const revoke=await postJson(page,'/api/v1/admin/tokens/revoke',{org_id:org,id:tokenId,reason:'e2e done'});
 expect(revoke.status,revoke.text).toBe(200);
 expect((await post('/api/v1/releases/deploys',{op:'record',org,project,release,environment:source.environment,command_id:id()})).status()).toBe(401);
});
