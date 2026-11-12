// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type Browser,type BrowserContext,type Page,type Request} from '@playwright/test';
import {id,login,origin,owner,postJson,csrf} from './support/real';
import {CANARY_FN,CANARY_LABEL,MAP_SECRET,revoke,seedEvidence,type EvidenceSeed,type Member} from './support/evidence';

// Real server, real Chrome. The organization, users, grants, source policy and source go through the real admin and
// onboarding routes; the source map is admitted through the real multipart POST /api/v1/artifacts upload; every read
// below is the real /api/v1/evidence/* route (plus the committed /api/v1/artifacts and /api/v1/actions routes) as a real
// logged-in person. Release registration and one grouping issue are seeded by the temporary harness routes (see the report).
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
 await expect(page.locator('[data-section="regression"]')).toContainText('Not available');
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

test('issue page: grouping version and hash, occurrences, late history apart, unknown ancestry, no regression claimed, actions truthfully not available',async()=>{
 const page=await as(seed.admin,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(page.getByRole('heading',{name:/^Issue /})).toBeVisible();
 await expect(page.getByTestId('grouping-version')).toHaveText('3');
 await expect(page.getByTestId('grouping-hash')).toContainText(seed.issue.fingerprint);
 await expect(page.getByTestId('workflow')).toContainText('resolved');
 const rows=page.locator('[data-section="occurrences"] tr[data-occurrence]');
 await expect(rows).toHaveCount(3);
 await expect(page.locator(`tr[data-occurrence="${seed.issue.knownOccurrence}"]`)).toHaveAttribute('data-ancestry','known');
 await expect(page.locator(`tr[data-occurrence="${seed.issue.unknownOccurrence}"]`)).toHaveAttribute('data-ancestry','unknown');
 await expect(page.locator(`tr[data-occurrence="${seed.issue.unknownOccurrence}"]`)).toContainText('no regression is claimed');
 const late=page.locator(`tr[data-occurrence="${seed.issue.lateOccurrence}"]`);
 await expect(late).toHaveAttribute('data-late','yes');
 await expect(late).toContainText('version 2');
 await expect(page.locator('table:has(caption:text-is("Stored occurrences")) tr[data-late="yes"]')).toHaveCount(0);
 await expect(page.getByTestId('regression-note')).toContainText('No regression is claimed');
 await expect(page.locator('[data-section="occurrence_detail"]')).toContainText('Not available');
 await expect(page.locator('[data-section="regression"]')).toContainText('Not available');
 // Actions go through the existing action dispatch, which answers a typed not_available for an issue; nothing is changed or shown as changed.
 await expect(page.getByTestId('issue-expected-version')).toHaveText('4');
 for(const label of ['Resolve','Ignore','Stop ignoring','Reopen'])await expect(page.getByRole('radio',{name:label})).toBeVisible();
 await page.getByRole('radio',{name:'Ignore'}).check();
 await page.getByRole('button',{name:'Submit: Ignore'}).click();
 const note=page.getByTestId('issue-action-not-available');
 await expect(note).toBeVisible();
 await expect(note).toContainText('Not available. Nothing was changed.');
 await expect(note).toContainText('has no control handler');
 await expect(page.getByTestId('workflow')).toContainText('resolved');
 // An issue that does not exist and one in another scope are the same Not found.
 const unknown=await as(seed.admin,hash(seed.org,'issues',{project:seed.project,id:id()}));
 await expect(unknown.locator('.status').first()).toContainText('Not found');
 const stranger=await as(seed.outsider,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(stranger.locator('.status').first()).toContainText('Not found');
 await expect(stranger.getByTestId('grouping-hash')).toHaveCount(0);
 const reader=await as(seed.telemetry,hash(seed.org,'issues',{project:seed.project,id:seed.issue.id}));
 await expect(reader.locator('.status').getByText('Persisted issue evidence can only be read by an organization administrator')).toBeVisible();
 await expect(reader.getByTestId('grouping-hash')).toHaveCount(0);
});

async function resolve(page:Page,build:string,lines:string[],sources:boolean):Promise<void>{
 await page.getByLabel('Build ID').fill(build);
 await page.getByLabel(/^Frames \(/).fill(lines.join('\n'));
 if(sources)await page.getByLabel(/Also request source context/).check();
 await page.getByRole('button',{name:'Resolve frames'}).click();
 await expect(page.getByTestId('frame-results').getByRole('article').first()).toBeVisible();
}
const frameLine=(artifact:string,line:number,fn:string):string=>`${artifact} ${line} 7 ${fn}`;

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
