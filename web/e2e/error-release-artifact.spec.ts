// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Browser,type BrowserContext,type Page,type Request} from '@playwright/test';
import {createHash} from 'node:crypto';
import {adminCommand,id,login,origin,owner,postJson,csrf} from './support/real';
import {CANARY_FN,CANARY_LABEL,MAP_SECRET,REAL_CLASS,REAL_CODE,groupingFingerprint,issueId,member,revoke,seedEvidence,type EvidenceSeed,type Member} from './support/evidence';

// Real server, real Chrome. The organization, users, grants, source policy and source go through the real admin and
// onboarding routes; the source map is admitted through the real multipart POST /api/v1/artifacts upload; releases are
// registered through the real POST /api/v1/releases/register and the one grouping issue is made by the runner's issue
// producer from two real ingested error occurrences; every read below is the real /api/v1/evidence/* route (plus the
// committed /api/v1/artifacts and /api/v1/actions routes) as a real logged-in person. No seed route exists.
// The symbolication sandbox MUST be ready (native mode, `symbolicator: ready (sandbox probes passed)`). The admitted map has the single mapping `AAAA`
// (generated 1:0), so a frame at another position is answered `unmapped` by the real worker and an unknown artifact `artifact_unavailable`.
test.describe.configure({mode:'serial'});
let seed:EvidenceSeed,ownerPage:Page,browserRef:Browser;
const contexts:BrowserContext[]=[];

const nowNs=():string=>String(BigInt(Date.now())*1_000_000n);
function hash(org:string,view:string,target?:{project:string;id:string}):string{
 const p=new URLSearchParams({org,projects:seed.project,start:'1',end:nowNs(),tz:'UTC',view});
 if(target)p.set('target',`${target.project}:${target.id}`);
 return `#${p}`;
}
async function as(m:Member,fragment:string):Promise<Page>{
 const context=await browserRef.newContext();
 contexts.push(context);
 const page=await context.newPage();
 await login(page,m.email,m.password);
 await page.goto(`/${fragment}`);
 return page;
}
const artifactPost=(page:Page,operation:string,org:string,project:string,artifactId:string)=>
 postJson(page,'/api/v1/artifacts',{operation,org,project,id:artifactId});

test.beforeAll(async({browser})=>{
 test.setTimeout(300_000);
 browserRef=browser;
 const o=owner();
 ownerPage=await (await browser.newContext()).newPage();
 await login(ownerPage,o.email,o.password);
 seed=await seedEvidence(ownerPage,browser);
});
test.afterEach(async()=>{for(const c of contexts.splice(0))await c.close();});

test('release page: identity, label as a separate revision, ancestry from parent edges only, unknown never guessed, label text is text',async()=>{
 const page=await as(seed.admin,hash(seed.org,'releases',{project:seed.project,id:seed.releases.child}));
 await expect(page.getByRole('heading',{name:/^Release /})).toBeVisible();
 // The renamed label is the current display label; the original is kept in the label history; the artifact binding did not change.
 await expect(page.getByTestId('release-label')).toContainText('v1.1-renamed');
 await expect(page.getByRole('list',{name:'Label history'}).getByRole('listitem')).toHaveText(['Revision 1: v1.1','Revision 2: v1.1-renamed']);
 await expect(page.getByTestId('release-artifacts')).toContainText(seed.artifact);
 await expect(page.getByTestId('release-artifacts')).toContainText(seed.debugId);
 await expect(page.getByTestId('release-build')).toContainText(seed.build);
 await expect(page.getByTestId('release-parents').locator('li')).toHaveCount(1);
 await expect(page.getByTestId('release-parents').locator('li').first()).toContainText(seed.releases.root);
 await expect(page.getByTestId('release-parents').locator('li').first()).toContainText('registered');
 // Compare: a parent (descendant), a sibling (concurrent), itself, and a release that was never registered (unknown).
 await page.getByLabel(/Compare with release IDs/).fill([seed.releases.root,seed.releases.sibling,seed.releases.child,seed.releases.unregistered].join(', '));
 await page.getByRole('button',{name:'Compare ancestry'}).click();
 const cmp=page.getByTestId('release-comparisons').locator('li');
 await expect(cmp).toHaveCount(4);
 await expect(cmp.filter({hasText:seed.releases.root})).toHaveAttribute('data-order','descendant');
 await expect(cmp.filter({hasText:seed.releases.sibling})).toHaveAttribute('data-order','concurrent');
 await expect(cmp.filter({hasText:seed.releases.child})).toHaveAttribute('data-order','same');
 await expect(cmp.filter({hasText:seed.releases.unregistered})).toHaveAttribute('data-order','unknown');
 await expect(cmp.filter({hasText:seed.releases.unregistered})).toContainText('no order is claimed');
 await expect(page.locator('li[data-section="regression"]')).toHaveAttribute('data-state','empty');
 // A release whose parent was never registered is incomplete, with the unknown parent called out; no regression is claimed.
 await page.goto(`/${hash(seed.org,'releases',{project:seed.project,id:seed.releases.orphan})}`);
 await expect(page.getByTestId('release-parents').locator('li')).toHaveAttribute('data-known','no');
 await expect(page.getByTestId('release-parents')).toContainText('ancestry unknown');
 await expect(page.locator('[data-state="incomplete"]').first()).toBeVisible();
 // The HTML in a release label is text: no element, no handler.
 await page.goto(`/${hash(seed.org,'releases',{project:seed.project,id:seed.releases.sibling})}`);
 await expect(page.getByTestId('release-label')).toContainText(CANARY_LABEL);
 expect(await page.locator('main img, #root img').count()).toBe(0);
 expect(await page.evaluate(()=>Reflect.get(window,'__pwn'))).toBeUndefined();
});

test('release page: a project reader is told it needs an organization administrator; strangers and wrong scopes see one Not found',async()=>{
 const reader=await as(seed.telemetry,hash(seed.org,'releases',{project:seed.project,id:seed.releases.child}));
 await expect(reader.locator('.status').getByText('Release records can only be read by an organization administrator')).toBeVisible();
 await expect(reader.getByTestId('release-label')).toHaveCount(0);
 const stranger=await as(seed.outsider,hash(seed.org,'releases',{project:seed.project,id:seed.releases.child}));
 const missing=await as(seed.admin,hash(seed.org,'releases',{project:seed.project,id:id()}));
 const ungranted=await as(seed.outsider,hash(seed.otherOrg,'releases',{project:seed.project,id:seed.releases.child}));
 const texts:string[]=[];
 for(const p of [stranger,missing,ungranted]){
  await expect(p.getByRole('heading',{name:/^Release /})).toBeVisible();
  const status=p.locator('.status').first();
  await expect(status).toContainText('Not found');
  texts.push((await status.innerText()).replace(/Request\s+[0-9a-f]{32}\.?/,'').trim());
  await expect(p.getByTestId('release-label')).toHaveCount(0);
 }
 expect(new Set(texts).size).toBe(1);
});

test('issue page: grouping version and hash, occurrences, unknown ancestry, no regression claimed; the stored detail needs telemetry.read; strangers and project readers',async()=>{
 const page=await as(seed.admin,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(page.getByRole('heading',{name:/^Issue /})).toBeVisible();
 await expect(page.getByTestId('grouping-version')).toHaveText('1');
 await expect(page.getByTestId('grouping-hash')).toContainText(seed.issue.fingerprint);
 await expect(page.getByTestId('workflow')).toContainText('open');
 const rows=page.locator('[data-section="occurrences"] tr[data-occurrence]');
 await expect(rows).toHaveCount(2);
 await expect(page.locator(`tr[data-occurrence="${seed.issue.knownOccurrence}"]`)).toHaveAttribute('data-ancestry','known');
 await expect(page.locator(`tr[data-occurrence="${seed.issue.unknownOccurrence}"]`)).toHaveAttribute('data-ancestry','unknown');
 await expect(page.locator(`tr[data-occurrence="${seed.issue.unknownOccurrence}"]`)).toContainText('no regression is claimed');
 // The producer groups both occurrences into the current grouping version: nothing is stored apart as late history.
 await expect(page.locator('tr[data-late="yes"]')).toHaveCount(0);
 await expect(page.getByTestId('regression-note')).toContainText('never inferred from timestamps or release labels');
 await expect(page.getByTestId('regression-none')).toBeVisible();
 // An administrator holds the issue evidence but not the telemetry: the stored record behind an occurrence is withheld, with the reason in words, and nothing of it is shown.
 const detail=page.locator('li[data-section="occurrence_detail"]');
 await expect(detail).toHaveAttribute('data-state','not_available');
 await expect(detail).toContainText('telemetry.read');
 await page.getByRole('button',{name:`Show stored detail of occurrence ${seed.issue.knownOccurrence}`}).click();
 const stored=page.locator('[data-section="occurrence-detail"]');
 await expect(stored.locator('.status')).toContainText('telemetry.read');
 await expect(stored.getByTestId('occ-class')).toHaveCount(0);
 await expect(page.getByTestId('issue-expected-version')).toHaveText(/^\d+$/);
 for(const label of ['Resolve','Ignore','Stop ignoring','Reopen'])await expect(page.getByRole('radio',{name:label})).toBeVisible();
 // An issue that does not exist and one in another scope are the same Not found.
 const unknown=await as(seed.admin,hash(seed.org,'issues',{project:seed.project,id:id()}));
 await expect(unknown.locator('.status').first()).toContainText('Not found');
 const stranger=await as(seed.outsider,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(stranger.locator('.status').first()).toContainText('Not found');
 await expect(stranger.getByTestId('grouping-hash')).toHaveCount(0);
 const reader=await as(seed.telemetry,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(reader.locator('.status').getByText('Persisted issue evidence can only be read by an organization administrator')).toBeVisible();
 await expect(reader.getByTestId('grouping-hash')).toHaveCount(0);
 // An administrator who also holds telemetry.read stays the administrator: the evidence and the stored detail are both readable.
 const analyst=await as(seed.analyst,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(analyst.getByTestId('grouping-hash')).toContainText(seed.issue.fingerprint);
 await expect(analyst.locator('li[data-section="occurrence_detail"]')).toHaveAttribute('data-state','ready');
});

const reasonField=(page:Page)=>page.getByLabel(/^Reason/);
async function submitIssueAction(page:Page,label:string,reason:string,fixedIn?:string):Promise<void>{
 await page.getByRole('radio',{name:label}).check();
 await reasonField(page).fill(reason);
 if(fixedIn!==undefined)await page.getByLabel(/^Fixed in releases/).fill(fixedIn);
 await page.getByRole('button',{name:`Submit: ${label}`}).click();
}
const revisionOf=async(page:Page):Promise<number>=>Number((await page.getByTestId('issue-expected-version').innerText()).trim());

test('issue actions: ignore, stop ignoring, resolve and reopen are committed by the server and shown from the stored issue; a moved revision, a forbidden transition and a refusal are told apart',async()=>{
 const target={project:seed.project,id:seed.actions.issue};
 const page=await as(seed.admin,hash(seed.org,'issues',target));
 await expect(page.getByTestId('workflow')).toContainText('open');
 const r0=await revisionOf(page);
 const posts:string[]=[];
 page.on('request',(r)=>{if(r.method()==='POST'&&new URL(r.url()).pathname==='/api/v1/actions')posts.push(r.postData()??'');});
 // No reason: the browser refuses to send, and a blank reason is refused before anything is sent.
 await page.getByRole('radio',{name:'Ignore'}).check();
 await page.getByRole('button',{name:'Submit: Ignore'}).click();
 expect(await reasonField(page).evaluate((el:HTMLTextAreaElement)=>el.validity.valueMissing)).toBe(true);
 await reasonField(page).fill('   ');
 await page.getByRole('button',{name:'Submit: Ignore'}).click();
 await expect(page.getByRole('alert').filter({hasText:'Give a reason'})).toBeVisible();
 expect(posts).toHaveLength(0);
 await expect(page.getByTestId('workflow')).toContainText(`open (revision ${r0})`);

 // Ignore: pending first, then committed with the revision the server names, and the page re-reads the stored issue.
 await submitIssueAction(page,'Ignore','noise from a retry loop');
 const committed=page.getByTestId('issue-action-committed');
 await expect(committed).toContainText('Ignore committed');
 await expect(committed).toContainText(`revision ${r0+1}`);
 await expect(page.getByTestId('workflow')).toContainText(`ignored (revision ${r0+1})`);
 await expect(page.getByTestId('issue-expected-version')).toHaveText(String(r0+1));
 expect(posts).toHaveLength(1);
 const sent=JSON.parse(posts[0]??'{}') as Record<string,unknown>;
 expect(sent).toMatchObject({entity_kind:'issue',kind:'ignore',target_id:seed.actions.issue,expected_version:String(r0),payload:{reason:'noise from a retry loop'}});
 for(const forbidden of ['actor','origin','principal','timestamp','at'])expect(Object.keys(sent)).not.toContain(forbidden);

 // A transition the workflow forbids at the revision on screen: a conflict that says so, nothing changed, the revision is the same.
 await submitIssueAction(page,'Reopen','trying to reopen an ignored issue');
 const forbidden=page.getByTestId('issue-action-conflict');
 await expect(forbidden).toHaveAttribute('data-conflict','issue_state_conflict');
 await expect(forbidden).toContainText('does not allow this action');
 await expect(page.getByTestId('workflow')).toContainText(`ignored (revision ${r0+1})`);

 // Stop ignoring, then resolve naming the release that contains the fix.
 await submitIssueAction(page,'Stop ignoring','the noise is fixed upstream');
 await expect(page.getByTestId('issue-action-committed')).toContainText('Stop ignoring committed');
 await expect(page.getByTestId('workflow')).toContainText(`open (revision ${r0+2})`);
 await submitIssueAction(page,'Resolve','fixed in the child release',seed.releases.child);
 await expect(page.getByTestId('issue-action-committed')).toContainText('Resolve committed');
 await expect(page.getByTestId('workflow')).toContainText(`resolved (revision ${r0+3})`);
 await expect(page.locator('section[data-section="grouping"]')).toContainText('Resolved at');

 // A second browser opens the resolved issue; the first reopens it; the second is now acting on a revision that moved.
 const second=await as(seed.admin,hash(seed.org,'issues',target));
 await expect(second.getByTestId('workflow')).toContainText(`resolved (revision ${r0+3})`);
 await submitIssueAction(page,'Reopen','a customer reported it again');
 await expect(page.getByTestId('workflow')).toContainText(`open (revision ${r0+4})`);
 await submitIssueAction(second,'Reopen','reopen from the stale page');
 const stale=second.getByTestId('issue-action-conflict');
 await expect(stale).toHaveAttribute('data-conflict','issue_version_conflict');
 await expect(stale).toContainText(`revision ${r0+4}`);
 await expect(stale).toContainText(`revision ${r0+3}`);
 // The page re-read the issue after the conflict: it shows what is stored now and the revision the next action will expect.
 await expect(second.getByTestId('workflow')).toContainText(`open (revision ${r0+4})`);
 await expect(second.getByTestId('issue-expected-version')).toHaveText(String(r0+4));

 // A refusal is not a conflict: an administrator whose rights end while the page is open is told the action was not applied, and nothing changed.
 const demoted=await member(ownerPage,seed.org,seed.project,'demoted',['artifacts.read'],true);
 const gone=await as(demoted,hash(seed.org,'issues',target));
 await expect(gone.getByTestId('workflow')).toContainText(`open (revision ${r0+4})`);
 await adminCommand(ownerPage,seed.org,'org_admin',{user_id:demoted.id,enabled:false});
 await submitIssueAction(gone,'Ignore','after my rights ended');
 const refused=gone.getByTestId('issue-action-refused');
 await expect(refused).toContainText('Not applied');
 await expect(refused).toContainText('not_found');
 await expect(gone.getByTestId('issue-action-committed')).toHaveCount(0);
 await second.getByRole('button',{name:'Reload issue'}).click();
 await expect(second.getByTestId('workflow')).toContainText(`open (revision ${r0+4})`);
 // The same actions without the grant or from another organization are the same not-found at the route, with nothing changed.
 for(const who of [seed.telemetry,seed.outsider]){
  const p=await as(who,hash(seed.org,'queue'));
  const r=await postJson(p,'/api/v1/actions',{org:seed.org,command_id:id(),expected_version:String(r0+4),project_id:seed.project,target_id:seed.actions.issue,entity_kind:'issue',kind:'ignore',payload:{reason:'no grant'}});
  expect(r.status).toBe(404);
 }
});

test('real bundle: the frames of the real failure are mapped by the real source map to the source function and line; a label rename cannot change the map; a corrupt map is refused',async()=>{
 const {bundle}=seed.real;
 const open=async():Promise<Page>=>{
  const page=await as(seed.analyst,hash(seed.org,'issues',{project:seed.project,id:seed.real.issue}));
  await page.getByRole('button',{name:`Show stored detail of occurrence ${seed.real.occurrence}`}).click();
  await expect(page.getByTestId('stored-frames').getByRole('article')).toHaveCount(2);
  return page;
 };
 const page=await open();
 const frames=page.getByTestId('stored-frames').getByRole('article');
 // The frames are the stored ones of the real stack, not typed: original generated position and function first.
 for(const [i,f] of bundle.frames.entries()){
  await expect(frames.nth(i)).toHaveAttribute('data-reason','resolved');
  await expect(frames.nth(i).getByTestId('frame-state')).toHaveText('Mapped');
  await expect(frames.nth(i).getByTestId('frame-original')).toContainText(`${seed.artifact}:${f.line}:${f.column} in ${f.function}`);
 }
 // The throw site maps to the line of `throw new Error` in the source; the call site to the line of the call, where the real map names the function.
 await expect(frames.nth(0).getByTestId('frame-mapped')).toContainText(`${bundle.sourceFile}:${bundle.throwLine}:`);
 await expect(frames.nth(1).getByTestId('frame-mapped')).toContainText(`${bundle.sourceFile}:${bundle.callLine}:`);
 await expect(frames.nth(1).getByTestId('frame-mapped')).toContainText('in riskyCheckout');
 for(const i of [0,1]){
  await expect(frames.nth(i).getByTestId('frame-mapped')).toContainText(seed.build);
  await expect(frames.nth(i).getByTestId('frame-mapped')).toContainText(seed.mapHash);
 }
 // No private source text is released to a caller without the sources grant, and nothing was requested.
 await expect(page.locator('body')).not.toContainText(MAP_SECRET);
 await expect(frames.nth(0).getByTestId('frame-source-state')).toHaveAttribute('data-source','withheld');
 const mapped=await frames.getByTestId('frame-mapped').allInnerTexts();

 // The display label of the release is a separate, revisioned value: renaming it changes the release page and nothing about the mapping.
 await seed.renameChild('v1.1-label-renamed-again','2');
 const release=await as(seed.analyst,hash(seed.org,'releases',{project:seed.project,id:seed.releases.child}));
 await expect(release.getByTestId('release-label')).toContainText('v1.1-label-renamed-again');
 await expect(release.getByRole('list',{name:'Label history'}).getByRole('listitem')).toHaveCount(3);
 await expect(release.getByTestId('release-artifacts')).toContainText(seed.artifact);
 await expect(release.getByTestId('release-artifacts')).toContainText(seed.debugId);
 const again=await open();
 expect(await again.getByTestId('stored-frames').getByTestId('frame-mapped').allInnerTexts()).toEqual(mapped);
 // A label is never an identity: it is refused as a frame's artifact before anything is sent.
 await again.getByLabel('Build ID').fill(seed.build);
 await again.getByLabel(/^Frames \(/).fill(`v1.1-label-renamed-again ${bundle.frames[0]?.line} 7 boom`);
 await again.getByRole('button',{name:'Resolve frames'}).click();
 await expect(again.getByRole('alert').filter({hasText:'not a path, URL or label'})).toBeVisible();

 // A corrupt map never becomes an artifact: admission refuses it, and the real map keeps mapping the same frames.
 const writer=await browserRef.newContext({baseURL:origin()});
 contexts.push(writer);
 const w=await writer.newPage();
 await login(w,seed.srcOwner.email,seed.srcOwner.password);
 const corrupt=Buffer.from('{"version":3,"sources":["a.ts"],"names":[],"mappings":"!!!!"}');
 const sha=(b:Buffer):string=>createHash('sha256').update(b).digest('hex');
 const manifest=`{"version":1,"org":"${seed.org}","project":"${seed.project}","source":"${seed.source}","build":"${seed.build}","debug_id":"debug-corrupt","generated_sha256":"${sha(Buffer.from('x'))}","map_sha256":"${sha(corrupt)}","path":"dist/corrupt.js","source_content":false,"size":"${corrupt.length}","retain_until_ns":"4102444800000000000"}`;
 const upload=await w.request.post(`${origin()}/api/v1/artifacts`,{headers:{'X-CSRF-Token':await csrf(w),Origin:origin()},multipart:{manifest:{name:'manifest',mimeType:'application/json',buffer:Buffer.from(manifest)},file:{name:'corrupt.js.map',mimeType:'application/json',buffer:corrupt}}});
 expect(upload.status()).toBeGreaterThanOrEqual(400);
 expect(upload.status()).toBeLessThan(500);
 expect(await upload.text()).not.toMatch(/"id":"[0-9a-f]{32}"/);
 const last=await open();
 expect(await last.getByTestId('stored-frames').getByTestId('frame-mapped').allInnerTexts()).toEqual(mapped);
});

test('stored occurrence: class, mechanism, handled and fatal, code, chain and frames come from the real stored record; the links go to the release and the real trace',async()=>{
 const page=await as(seed.analyst,hash(seed.org,'issues',{project:seed.project,id:seed.real.issue}));
 await expect(page.getByTestId('grouping-hash')).toContainText(seed.real.fingerprint);
 await expect(page.locator('li[data-section="occurrence_detail"]')).toHaveAttribute('data-state','ready');
 await page.getByRole('button',{name:`Show stored detail of occurrence ${seed.real.occurrence}`}).click();
 const d=page.locator('[data-section="occurrence-detail"]');
 await expect(d.getByTestId('occ-class')).toHaveText(REAL_CLASS);
 await expect(d.getByTestId('occ-mechanism')).toContainText('uncaught_exception');
 await expect(d.getByTestId('occ-mechanism')).toContainText('reached the top of the program');
 await expect(d.getByTestId('occ-handled-fatal')).toHaveText('Not handled, fatal.');
 await expect(d.getByTestId('occ-handled-fatal')).toHaveAttribute('data-handled','no');
 await expect(d.getByTestId('occ-handled-fatal')).toHaveAttribute('data-fatal','yes');
 await expect(d.getByTestId('occ-code')).toHaveText(REAL_CODE);
 await expect(d.getByTestId('occ-build')).toContainText(seed.build);
 // The exception chain as stored: two errors, the suppressed context said so, the edge and the reason the chain may be incomplete.
 const chain=d.getByTestId('occ-chain');
 await expect(chain.getByRole('list',{name:'Errors in the chain',exact:true}).getByRole('listitem')).toHaveCount(2);
 await expect(chain.locator('li[data-node="1"]')).toContainText('CheckoutCause');
 await expect(chain.locator('li[data-node="1"]')).toContainText('suppressed the context');
 await expect(chain.locator('li[data-edge-kind="cause"]')).toHaveText(`${REAL_CLASS} (node 0) to CheckoutCause (node 1): cause`);
 await expect(d.getByTestId('occ-chain-reasons').locator('li[data-reason="cause_accessor"]')).toContainText('accessor');
 // The issue's second tab: an occurrence of another issue is not reachable through this one (the route answers one not-found).
 const crossed=await postJson(page,'/api/v1/evidence/occurrence',{org:seed.org,project:seed.project,issue:seed.real.issue,occurrence:seed.issue.knownOccurrence});
 expect(crossed.status).toBe(404);
 // Links: the release the record names and the trace and span it happened under.
 await expect(d.getByTestId('occ-release-link')).toContainText(seed.real.release);
 await expect(d.getByTestId('occ-trace')).toContainText(seed.real.span);
 await d.getByTestId('occ-release-link').click();
 await expect(page.getByRole('heading',{name:/^Release /})).toContainText(seed.real.release);
 await expect(page.getByTestId('release-artifacts')).toContainText(seed.artifact);
 await page.goBack();
 await expect(page.getByRole('heading',{name:/^Issue /})).toBeVisible();
 await page.getByRole('button',{name:`Show stored detail of occurrence ${seed.real.occurrence}`}).click();
 await page.locator('[data-section="occurrence-detail"]').getByTestId('occ-trace-link').click();
 await expect(page.getByRole('heading',{name:/^Trace /})).toContainText(seed.real.trace);
 await expect(page.getByTestId('critical-path')).toContainText('op.request');
});

async function resolve(page:Page,build:string,lines:string[],sources:boolean):Promise<void>{
 await page.getByLabel('Build ID').fill(build);
 await page.getByLabel(/^Frames \(/).fill(lines.join('\n'));
 if(sources)await page.getByLabel(/Also request source context/).check();
 await page.getByRole('button',{name:'Resolve frames'}).click();
 await expect(page.getByTestId('frame-results').getByRole('article').first()).toBeVisible();
}
const frameLine=(artifact:string,line:number,fn:string):string=>`${artifact} ${line} 7 ${fn}`;

test('regression: the stored explanation of each occurrence after a resolution is shown on the issue and on the release; unknown ancestry is decided by the boundary and says so; nothing is inferred from timestamps',async()=>{
 const klass='E2eRegressionTarget';
 await seed.occurrenceOf(klass,seed.releases.root);
 const identity=issueId(seed.org,seed.project,groupingFingerprint(seed.org,seed.project,klass,'manual'));
 const target={project:seed.project,id:identity};
 const page=await as(seed.admin,hash(seed.org,'issues',target));
 // Never resolved, so never evaluated: the empty list has its own words, and a recent occurrence on a release names no regression.
 await expect(page.getByTestId('regression-none')).toBeVisible();
 await expect(page.locator('li[data-section="regression"]')).toHaveAttribute('data-state','empty');
 await expect(page.getByTestId('regression-note')).toContainText('never inferred from timestamps or release labels');
 // Resolve naming the child release as the fix.
 await submitIssueAction(page,'Resolve','fixed in the child release',seed.releases.child);
 await expect(page.getByTestId('workflow')).toContainText('resolved');
 const rows=page.getByTestId('regression-list').locator('tbody tr');
 const reload=async():Promise<void>=>{await page.getByRole('button',{name:'Reload issue'}).click();await expect(page.getByRole('button',{name:'Reload issue'})).toBeEnabled();};

 // 1. An occurrence in the root release, an ancestor of the fix: evaluated, not eligible, nothing reopened, the issue stays resolved.
 const onRoot=await seed.occurrenceOf(klass,seed.releases.root);
 await reload();
 await expect(rows).toHaveCount(1);
 await expect(rows.nth(0)).toHaveAttribute('data-occurrence',onRoot);
 await expect(rows.nth(0)).toHaveAttribute('data-eligible','no');
 await expect(rows.nth(0)).toHaveAttribute('data-reopened','no');
 await expect(rows.nth(0)).toHaveAttribute('data-ancestry','known');
 await expect(rows.nth(0).getByTestId('regression-reason')).toHaveText('release is not the fix frontier or a descendant of it');
 await expect(rows.nth(0).getByTestId('regression-outcome')).toHaveText('Did not reopen the issue.');
 await expect(rows.nth(0)).toContainText(seed.releases.child);
 await expect(rows.nth(0)).toContainText('qualifying of 1 needed');
 await expect(page.getByTestId('workflow')).toContainText('resolved');

 // 2. An occurrence in the child release, the fix itself: eligible by release ancestry, and the stored evaluation reopened the issue.
 const onChild=await seed.occurrenceOf(klass,seed.releases.child);
 await reload();
 await expect(rows).toHaveCount(2);
 await expect(rows.nth(1)).toHaveAttribute('data-occurrence',onChild);
 await expect(rows.nth(1)).toHaveAttribute('data-eligible','yes');
 await expect(rows.nth(1)).toHaveAttribute('data-reopened','yes');
 await expect(rows.nth(1).getByTestId('regression-reason')).toHaveText('release is the fix frontier or a descendant of it');
 await expect(rows.nth(1).getByTestId('regression-outcome')).toHaveText('Reopened the issue.');
 await expect(page.getByTestId('workflow')).toContainText('open');

 // 3. Resolved again with no named fix, an occurrence that names no release: its ancestry is unknown, so only the explicit resolution time boundary decides, and the page says exactly that.
 await submitIssueAction(page,'Resolve','accepted for now');
 await expect(page.getByTestId('workflow')).toContainText('resolved');
 const noRelease=await seed.occurrenceOf(klass);
 await reload();
 await expect(rows).toHaveCount(3);
 const last=rows.last();
 await expect(last).toHaveAttribute('data-occurrence',noRelease);
 await expect(last).toHaveAttribute('data-ancestry','unknown');
 await expect(last).toHaveAttribute('data-eligible','yes');
 await expect(last.getByTestId('regression-reason')).toHaveText('ancestry unknown: event after the explicit resolution boundary');
 await expect(last.getByTestId('regression-verdict')).toContainText('Ancestry unknown: decided by the explicit resolution time boundary, not by release ancestry.');
 await expect(last).toContainText('The occurrence names no release.');
 await expect(page.getByTestId('workflow')).toContainText('open');

 // The release page lists the stored evaluations whose occurrence ran in it, each with its issue; a release none ran in says so and claims nothing.
 const root=await as(seed.admin,hash(seed.org,'releases',{project:seed.project,id:seed.releases.root}));
 const rootRows=root.getByTestId('regression-list').locator('tbody tr');
 await expect(rootRows).toHaveCount(1);
 await expect(rootRows.nth(0)).toHaveAttribute('data-occurrence',onRoot);
 await expect(rootRows.nth(0)).toHaveAttribute('data-eligible','no');
 await expect(rootRows.nth(0).getByRole('link').first()).toHaveAttribute('href',new RegExp(`view=issues&target=${seed.project}%3A${identity}$`));
 await expect(root.locator('li[data-section="regression"]')).toHaveAttribute('data-state','ready');
 const child=await as(seed.admin,hash(seed.org,'releases',{project:seed.project,id:seed.releases.child}));
 const childRows=child.getByTestId('regression-list').locator('tbody tr');
 await expect(childRows).toHaveCount(1);
 await expect(childRows.nth(0)).toHaveAttribute('data-occurrence',onChild);
 await expect(childRows.nth(0)).toHaveAttribute('data-reopened','yes');
 const sibling=await as(seed.admin,hash(seed.org,'releases',{project:seed.project,id:seed.releases.sibling}));
 await expect(sibling.getByTestId('release-regressions-none')).toBeVisible();
 await expect(sibling.locator('li[data-section="regression"]')).toHaveAttribute('data-state','empty');
 // The issue link on the release page opens the issue with the same evaluations.
 await rootRows.nth(0).getByRole('link').first().click();
 await expect(root.getByRole('heading',{name:/^Issue /})).toContainText(identity);
 await expect(root.getByTestId('regression-list').locator('tbody tr')).toHaveCount(3);
 // A project reader is told the evidence needs an administrator and sees no evaluation; a stranger sees the one not-found.
 const reader=await as(seed.telemetry,hash(seed.org,'issues',target));
 await expect(reader.getByTestId('regression-list')).toHaveCount(0);
 const stranger=await as(seed.outsider,hash(seed.org,'issues',target));
 await expect(stranger.locator('.status').first()).toContainText('Not found');
 await expect(stranger.getByTestId('regression-list')).toHaveCount(0);
});
test('frames: the real map is found for its build, an unmapped position is said so, original frames and reasons are shown, no URL is ever fetched, markup is text',async()=>{
 const page=await as(seed.srcOwner,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(page.getByRole('form',{name:'Resolve frames'})).toBeVisible();
 const requests:Request[]=[];
 page.on('request',(r)=>requests.push(r));
 await resolve(page,seed.build,[frameLine(seed.artifact,10,CANARY_FN),frameLine(seed.artifact,11,'second'),frameLine(id(),12,'ghost')],true);
 const results=page.getByTestId('frame-results');
 await expect(results).toBeFocused();
 const frames=results.getByRole('article');
 await expect(frames).toHaveCount(3);
 // Real artifact + its build: the map is read from the real store and the real worker finds no mapping at line 10: a specific safe reason, original frame kept.
 await expect(frames.nth(0)).toHaveAttribute('data-reason','unmapped');
 await expect(frames.nth(0).getByTestId('frame-state')).toHaveText('Not mapped');
 await expect(frames.nth(0).getByTestId('frame-original')).toContainText(`${seed.artifact}:10:7 in ${CANARY_FN}`);
 await expect(frames.nth(0).getByTestId('frame-reason')).toContainText('Not mapped');
 await expect(frames.nth(0).getByTestId('frame-mapped')).toHaveCount(0);
 // An artifact that is not in this scope is indistinguishable from an absent one.
 await expect(frames.nth(2)).toHaveAttribute('data-reason','artifact_unavailable');
 // The source owner holds the sources grant, but an unmapped frame has no source context: said so, not claimed as withheld.
 await expect(frames.nth(0).getByTestId('frame-source-state')).toContainText('not a statement about your grant');
 await expect(page.locator('.source-context')).toHaveCount(0);
 await expect(page.locator('body')).not.toContainText(MAP_SECRET);
 // A different build identity does not select this map.
 await page.getByLabel('Build ID').fill(seed.otherBuild);
 await page.getByRole('button',{name:'Resolve frames'}).click();
 await expect(results.getByRole('article').first()).toHaveAttribute('data-reason','identity_mismatch');
 await expect(results.getByRole('article').first().getByTestId('frame-reason')).toContainText('not part of this build');
 // The HTML in a function name is text.
 expect(await page.locator('#root img, main img').count()).toBe(0);
 expect(await page.evaluate(()=>Reflect.get(window,'__pwn'))).toBeUndefined();
 // Every request the page made is a same-origin POST to an evidence route: no map, source or runtime URL was fetched by the page, and the artifact route was never called from it.
 const made=requests.map((r)=>`${r.method()} ${new URL(r.url()).origin===origin()?new URL(r.url()).pathname:r.url()}`);
 expect(made).toContain('POST /api/v1/evidence/frames');
 for(const m of made)expect(['POST /api/v1/evidence/frames','POST /api/v1/evidence/issue']).toContain(m);
});

test('frames: a map-only reader asked for sources is told the source grant is missing; a telemetry-only reader sees sanitized frames and no mapping',async()=>{
 const mapOnly=await as(seed.mapOnly,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await resolve(mapOnly,seed.build,[frameLine(seed.artifact,10,'boom')],true);
 const frame=mapOnly.getByTestId('frame-results').getByRole('article').first();
 await expect(frame).toHaveAttribute('data-reason','source_context_denied');
 await expect(frame.getByTestId('frame-source-state')).toHaveAttribute('data-source','withheld');
 await expect(frame.getByTestId('frame-source-state')).toContainText('separate sources grant');
 await expect(frame.getByTestId('frame-original')).toContainText(`${seed.artifact}:10:7 in boom`);
 await expect(mapOnly.locator('body')).not.toContainText(MAP_SECRET);
 // Without asking for sources the same reader's frame is simply not mapped here (no mapping at that position), and the source is not requested.
 await mapOnly.getByLabel(/Also request source context/).uncheck();
 await mapOnly.getByRole('button',{name:'Resolve frames'}).click();
 await expect(mapOnly.getByTestId('frame-results').getByRole('article').first().getByTestId('frame-source-state')).toContainText('never fetched by default');

 const tele=await as(seed.telemetry,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await resolve(tele,seed.build,[frameLine(seed.artifact,10,'boom')],true);
 const t=tele.getByTestId('frame-results').getByRole('article').first();
 await expect(t).toHaveAttribute('data-reason','artifact_read_not_granted');
 await expect(t.getByTestId('frame-reason')).toContainText('artifacts.read');
 await expect(t.getByTestId('frame-original')).toContainText(`${seed.artifact}:10:7 in boom`);
 await expect(t.getByTestId('frame-source-state')).toHaveAttribute('data-source','withheld');
 await expect(tele.locator('body')).not.toContainText(MAP_SECRET);

 // Another organization's reader asking about this scope gets one Not found, and nothing about the frames.
 const stranger=await as(seed.outsider,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(stranger.locator('.status').first()).toContainText('Not found');
});

test('artifact bytes: the scoped route releases the map without source text to a map reader, source text only to the named source reader, and revocation ends it',async()=>{
 const ctx=async(m:Member):Promise<Page>=>{const c=await browserRef.newContext();contexts.push(c);const p=await c.newPage();await login(p,m.email,m.password);return p;};
 const srcOwner=await ctx(seed.srcOwner),mapOnly=await ctx(seed.mapOnly),tele=await ctx(seed.telemetry),stranger=await ctx(seed.outsider);
 const mapRead=await artifactPost(mapOnly,'read',seed.org,seed.project,seed.artifact);
 expect(mapRead.status).toBe(200);
 expect(mapRead.text).not.toContain(MAP_SECRET);
 expect(mapRead.text).not.toContain('sourcesContent');
 const sources=await artifactPost(srcOwner,'sources',seed.org,seed.project,seed.artifact);
 expect(sources.status).toBe(200);
 expect(sources.text).toContain(MAP_SECRET);
 // Not granted, not a named reader, wrong scope and a guessed ID: one indistinguishable answer.
 const denials=[
  await artifactPost(mapOnly,'sources',seed.org,seed.project,seed.artifact),
  await artifactPost(tele,'read',seed.org,seed.project,seed.artifact),
  await artifactPost(tele,'sources',seed.org,seed.project,seed.artifact),
  await artifactPost(stranger,'sources',seed.org,seed.project,seed.artifact),
  await artifactPost(stranger,'read',seed.otherOrg,seed.otherProject,seed.artifact),
  await artifactPost(srcOwner,'sources',seed.org,seed.project,id()),
 ];
 const shape=(r:{status:number;text:string})=>`${r.status} ${r.text.replace(/"request_id":"[0-9a-f]+"/,'')}`;
 for(const d of denials){expect(d.status).toBe(404);expect(d.text).not.toContain(MAP_SECRET);expect(shape(d)).toBe(shape(denials[0]!));}
 // Revocation: the source reader's raw.read grant is withdrawn, and the very next read of the same artifact is the same Not found.
 await revoke(ownerPage,seed.org,seed.project,seed.srcOwner.id,['raw.read']);
 const after=await artifactPost(srcOwner,'sources',seed.org,seed.project,seed.artifact);
 expect(after.status).toBe(404);
 expect(after.text).not.toContain(MAP_SECRET);
 expect(shape(after)).toBe(shape(denials[0]!));
 // The sessions' CSRF binding is real: the same POST without the token is refused.
 const token=await csrf(srcOwner);
 expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
 const noToken=await srcOwner.request.post(`${origin()}/api/v1/artifacts`,{headers:{Origin:origin()},data:{operation:'read',org:seed.org,project:seed.project,id:seed.artifact}});
 expect(noToken.status()).toBeGreaterThanOrEqual(400);
});

test('keyboard and labels: every control is reachable by label and role and the results take focus',async()=>{
 const page=await as(seed.admin,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 for(const name of ['Open an issue','Resolve frames','Issue action'])await expect(page.getByRole('form',{name})).toBeVisible();
 await page.getByLabel('Build ID').focus();
 await page.keyboard.type(seed.build);
 await page.keyboard.press('Tab');
 await expect(page.getByLabel(/^Frames \(/)).toBeFocused();
 await page.keyboard.type(frameLine(seed.artifact,10,'boom'));
 await page.getByRole('button',{name:'Resolve frames'}).focus();
 await page.keyboard.press('Enter');
 await expect(page.getByTestId('frame-results')).toBeFocused();
 // State is words, never colour alone.
 await expect(page.getByTestId('frame-state').first()).toHaveText(/Mapped|Not mapped/);
 await expect(page.getByTestId('frame-reason').first()).not.toBeEmpty();
});
