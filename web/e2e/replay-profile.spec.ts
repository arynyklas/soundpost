// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {test,expect,request as pwRequest,type APIRequestContext,type Response,type Browser,type BrowserContext,type FrameLocator,type Page} from '@playwright/test';
import {at,createOrg,createProject,createReader,login,owner,id,type Reader} from './support/real';
import {NATIVE_PROFILE,PROFILE_WINDOW,UNSUPPORTED_PROFILE,onboardReplaySource,seedProfiles,seedReplays,setPermissions,type ReplaySeed} from './support/replay';

// Real server, real Chrome. Every replay chunk and profile record below was admitted through the real ingest route with a real
// source credential, stored by the real storage engine and read back through the real POST /api/v1/replays/stream and
// POST /api/v1/profiles/view routes by real readers. Nothing here fakes a server answer. NOT covered, on purpose and stated:
//  - REAL recorder chunks (packages/browser/src/replay): the recorder emits node fields rect/pres and a wider tag enum that the
//    Go validator and packages/core/src/wire.ts refuse, so they cannot be admitted. The chunks here use the closed format.
//  - live perf: the native profile is the real nativeperf assembler over sanitized synthetic events (no perf privileges here).
test.describe.configure({mode:'serial'});
const ALL=['telemetry.read','replay.read','profiles.read'];
let br:Browser,ctx:BrowserContext,owners:Page,api:APIRequestContext,org:string,p1:string,reader:Reader,telemetryOnly:Reader,seed:ReplaySeed;

const hash=(view:string,target:string,start=at(0),end=at(70)):string=>`#${new URLSearchParams({org,projects:p1,start:String(start),end:String(end),tz:'UTC',view,target:`${p1}:${target}`})}`;
const frameOf=(page:Page):FrameLocator=>page.frameLocator('[data-testid=replay-frame]');
const hostStatus=(page:Page)=>page.getByTestId('viewer-status');
const timeline=(page:Page)=>frameOf(page).locator('[data-replay-timeline] li');

async function openReplay(page:Page,replay:string):Promise<void>{
 await page.goto(`/${hash('replays',replay)}`);
 await expect(page.getByRole('heading',{name:/^Replay /})).toBeVisible();
}
async function openProfile(page:Page,profile:string):Promise<void>{
 await page.goto(`/${hash('profiles',profile,PROFILE_WINDOW.start,PROFILE_WINDOW.end)}`);
 await expect(page.getByRole('heading',{name:/^Profile /})).toBeVisible();
}
async function loggedIn(who:Reader):Promise<Page>{
 const c=await br.newContext();
 const page=await c.newPage();
 await login(page,who.email,who.password);
 return page;
}
const step=(page:Page)=>page.getByRole('button',{name:'Step to the next event'}).click();
async function waitStarted(page:Page):Promise<void>{await expect(hostStatus(page)).not.toHaveAttribute('data-status','none');}

test.beforeAll(async({browser})=>{
 test.setTimeout(240_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 api=await pwRequest.newContext();
 org=await createOrg(owners,'replay profile e2e org');
 p1=await createProject(owners,org,'replay P1');
 reader=await createReader(owners,org,[p1]);
 await setPermissions(owners,org,reader.id,p1,true,ALL);
 telemetryOnly=await createReader(owners,org,[p1]); // telemetry.read only: no replay.read, no profiles.read
 const source=await onboardReplaySource(owners,org,p1);
 seed=await seedReplays(api,source);
 await seedProfiles(api,source);
 ctx=await browser.newContext();
 const page=await ctx.newPage();
 await login(page,reader.email,reader.password);
 await page.close();
});
test.afterEach(async()=>{for(const p of ctx.pages())await p.close();});

test('a missing middle chunk pauses the viewer at the gap and playback resumes only at the next verified checkpoint',async()=>{
 const page=await ctx.newPage();
 await openReplay(page,seed.gap.replay);
 await waitStarted(page);
 await expect(page.getByTestId('replay-frame')).toHaveAttribute('sandbox','allow-scripts');
 for(let n=1;n<=3;n++){await step(page);await expect(hostStatus(page)).toContainText(`Events delivered to the viewer: ${n}`);}
 await expect(hostStatus(page)).toHaveAttribute('data-status','ready');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2','delta 3']);
 // The server's typed gap (sequences 4 to 5 never arrived) is the next event: the viewer pauses.
 await step(page);
 await expect(hostStatus(page)).toHaveAttribute('data-status','gap');
 await expect(hostStatus(page)).toContainText('paused at a history gap');
 await expect(frameOf(page).locator('[data-replay-status]')).toHaveText('History gap');
 await expect(frameOf(page).locator('[data-replay-root]')).toHaveAttribute('data-state','gap');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2','delta 3','gap 4-5 missing_chunk']);
 // Only the checkpoint resumes it.
 await step(page);
 await expect(hostStatus(page)).toHaveAttribute('data-status','ready');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2','delta 3','gap 4-5 missing_chunk','checkpoint 6']);
 await expect(page.getByTestId('replay-gaps')).toContainText('In this recording playback resumes only at checkpoint 6; nothing between is shown.');
 await page.getByRole('button',{name:'Play',exact:true}).click();
 await expect(hostStatus(page)).toContainText('All received events were delivered.');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2','delta 3','gap 4-5 missing_chunk','checkpoint 6','delta 7','delta 8']);
 const log=await page.getByTestId('viewer-status-log').locator('li').allTextContents();
 expect(log.indexOf('gap')).toBeGreaterThan(0);
 expect(log.slice(log.indexOf('gap')+1)).toContain('ready');
 expect(log[0]).toBe('loading');
});

test('deltas that follow a hole are never replayed: only a checkpoint resumes',async()=>{
 const page=await ctx.newPage();
 await openReplay(page,seed.afterGap.replay);
 await waitStarted(page);
 await page.getByRole('button',{name:'Play',exact:true}).click();
 await expect(hostStatus(page)).toContainText('All received events were delivered.');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2','delta 3','gap 4-6 missing_chunk','checkpoint 7','delta 8']);
 await expect(frameOf(page).locator('[data-replay-timeline] li[data-sequence="5"]')).toHaveCount(0);
 await expect(frameOf(page).locator('[data-replay-timeline] li[data-sequence="6"]')).toHaveCount(0);
});

test('masked text, opaque regions, policy revision and recording loss are labelled in words',async()=>{
 const page=await ctx.newPage();
 await openReplay(page,seed.gap.replay);
 await waitStarted(page);
 await page.getByRole('button',{name:'Play',exact:true}).click();
 await expect(hostStatus(page)).toContainText('All received events were delivered.');
 const labels=page.getByTestId('replay-labels');
 await expect(labels.getByTestId('label-masked')).toContainText('[masked]');
 await expect(labels.getByTestId('label-opaque')).toContainText('[opaque]');
 await expect(labels.getByTestId('label-policy')).toHaveText('1');
 await expect(labels.getByTestId('label-loss')).toContainText('3 events were dropped by the recorder');
 await expect(labels.getByTestId('label-chunks')).toContainText('6 (2 checkpoints)');
 // The viewer itself draws only constants: masked text and the opaque region label.
 await expect(frameOf(page).locator('[data-masked]').first()).toBeVisible();
 expect(await frameOf(page).locator('[data-opaque]').count()).toBeGreaterThan(0);
 await expect(page.getByTestId('replay-labels')).not.toContainText('unknown');
});

test('the frame is sandboxed with no network and no raw DOM execution; canaries never reach content or requests',async()=>{
 expect(seed.canary.status).toBe(422); // raw node text is refused by the real ingest route before storage
 const page=await ctx.newPage();
 const requests:string[]=[],consoleErrors:string[]=[];
 let frameResponse:Response|undefined;
 page.on('request',(r)=>requests.push(r.url()));
 const refused:string[]=[];
 page.on('response',(r)=>{if(r.url().endsWith('/assets/replay-frame.html'))frameResponse=r;if(r.status()>=400)refused.push(`${r.status()} ${r.request().method()} ${r.url()}`);});
 page.on('console',(m)=>{if(m.type()==='error')consoleErrors.push(m.text());});
 await openReplay(page,seed.clean.replay);
 await waitStarted(page);
 await page.getByRole('button',{name:'Play',exact:true}).click();
 await expect(hostStatus(page)).toContainText('All received events were delivered.');
 const frame=page.frame({url:/replay-frame\.html$/});
 if(!frame)throw Error('no viewer frame');
 expect(await frame.evaluate(()=>window.origin)).toBe('null'); // opaque origin: no allow-same-origin
 const origin=new URL(page.url()).origin;
 // The frame cannot reach into its parent (opaque origin), and the policy the browser received for the frame document is the
 // hash-only no-network one, whose script hash is the hash of the exact script text it ran (it ran: the viewer reported status).
 expect(await frame.evaluate(()=>{try{return String(window.parent.document.cookie);}catch{return 'blocked';}})).toBe('blocked');
 expect(frameResponse).toBeDefined();
 const csp=frameResponse?.headers()['content-security-policy']??'';
 for(const want of ["default-src 'none'","connect-src 'none'","img-src 'none'","frame-src 'none'","form-action 'none'","base-uri 'none'","sandbox allow-scripts"])expect(csp).toContain(want);
 expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|allow-same-origin|\*|data:|blob:/);
 const doc=await (await page.request.get('/assets/replay-frame.html')).text();
 const script=/<script>([\s\S]*)<\/script>/.exec(doc)?.[1]??'';
 expect(script.length).toBeGreaterThan(1000);
 expect(csp).toContain(`script-src 'sha256-${createHash('sha256').update(script).digest('base64')}'`);
 expect(doc.match(/<script/g)).toHaveLength(1);
 // A hostile chunk posted straight at the frame (markup in every string) builds no element and runs nothing.
 await page.evaluate(()=>{
  const hostile={replay_id:'a'.repeat(32),nodes:[{id:'1',parent:'0',tag:'img',class:'<img src=x onerror="window.__pwn=1">',text:'<img src=x onerror="window.__pwn=1">'}]};
  const frameWindow=(document.querySelector('[data-testid=replay-frame]') as HTMLIFrameElement).contentWindow;
  frameWindow?.postMessage({soundpost:'replay',item:{kind:'chunk',bytes:new TextEncoder().encode(JSON.stringify(hostile)).buffer}},'*');
 });
 await page.waitForTimeout(500);
 expect(await frame.evaluate(()=>document.querySelectorAll('img,script[src],iframe,a,form,input,button').length)).toBe(0);
 expect(await frame.evaluate(()=>String((window as unknown as {__pwn?:unknown}).__pwn))).toBe('undefined');
 expect(await page.evaluate(()=>String((window as unknown as {__pwn?:unknown}).__pwn))).toBe('undefined');
 // Network: only this origin; the frame document is fetched once; nothing carries a canary.
 expect(requests.filter((u)=>!u.startsWith(origin+'/'))).toEqual([]);
 expect(requests.filter((u)=>u.includes('replay-frame.html'))).toHaveLength(1);
 const everything=[await page.content(),await frame.content(),...requests].join('\n');
 expect(everything).not.toContain(seed.canary.text);
 // The app shell itself probes POST /api/v1/admin/read for admin features; a non-admin reader is refused there (not part of the replay).
 expect(refused.filter((r)=>!r.includes('/api/v1/admin/read'))).toEqual([]);
 expect(consoleErrors.filter((e)=>!/Refused to|Content Security Policy|status of 403/i.test(e))).toEqual([]);
});

test('without the separate replay.read grant the replay does not exist for the reader',async()=>{
 const page=await loggedIn(telemetryOnly);
 await openReplay(page,seed.gap.replay);
 await expect(page.getByText('This selection was not found or is not available to this account.')).toBeVisible();
 await expect(page.getByTestId('replay-frame')).toHaveCount(0);
 await expect(page.getByTestId('replay-labels')).toHaveCount(0);
 const unknown=await loggedIn(reader);
 await openReplay(unknown,id());
 await expect(unknown.getByText('This selection was not found or is not available to this account.')).toBeVisible();
 await page.context().close();await unknown.context().close();
});

test('revoking replay.read while the replay is open clears it and nothing further is requested',async()=>{
 const victim=await createReader(owners,org,[p1]);
 await setPermissions(owners,org,victim.id,p1,true,ALL);
 const page=await loggedIn(victim);
 const requests:string[]=[];
 page.on('request',(r)=>requests.push(r.url()));
 await openReplay(page,seed.gap.replay);
 await waitStarted(page);
 await step(page);await expect(hostStatus(page)).toContainText('Events delivered to the viewer: 1');
 await step(page);await expect(hostStatus(page)).toContainText('Events delivered to the viewer: 2');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2']);
 await setPermissions(owners,org,victim.id,p1,true,['telemetry.read','profiles.read']); // replay.read withdrawn
 await expect(page.getByTestId('replay-ended')).toBeVisible({timeout:20_000});
 await expect(page.getByTestId('replay-frame')).toHaveCount(0);
 await expect(page.getByTestId('replay-host')).toHaveCount(0);
 await expect(page.getByTestId('replay-labels')).toHaveCount(0);
 await expect(page.locator('body')).not.toContainText('checkpoint 1');
 const seen=requests.length;
 await page.waitForTimeout(4500);
 // The shell's own session refresh (GET /api/v1/session) is not part of the replay; no replay request of any kind follows.
 expect(requests.slice(seen).filter((u)=>!u.endsWith('/api/v1/session'))).toEqual([]);
 const reopened=await page.request.post('/api/v1/replays/stream',{headers:{'X-CSRF-Token':(await (await page.request.get('/api/v1/session')).json() as {csrf:string}).csrf,Origin:new URL(page.url()).origin},data:{org,project:p1,replay:seed.gap.replay}});
 expect(reopened.status()).toBe(404);
 await page.context().close();
});

test('a native CPU profile keeps OS on-CPU samples, blocked time, runnable delay and the unknown split apart',async()=>{
 const page=await ctx.newPage();
 await openProfile(page,NATIVE_PROFILE);
 await expect(page.getByTestId('profile-method')).toContainText('native_cpu');
 const cpu=page.getByTestId('unit-oscpu');
 await expect(cpu).toContainText('3');
 await expect(cpu).toContainText('901');
 await expect(page.getByTestId('unit-blocked')).toContainText('60 ns');
 await expect(page.getByTestId('unit-runnable')).toContainText('30 ns');
 await expect(page.getByTestId('unit-unknown-split')).toContainText('unknown split');
 // never summed: no cell states 93 ns or 96 ns as one duration
 await expect(page.locator('body')).not.toContainText(/\b(90|93|96|99) ns\b/);
 const rows=page.getByTestId('capability-row');
 await expect(rows).toHaveCount(3);
 // The server lists capability records in no promised order: each method is checked by name.
 await expect(rows.filter({hasText:'native_cpu'})).toHaveAttribute('data-status','supported');
 await expect(rows.filter({hasText:'native_offcpu'})).toHaveAttribute('data-status','supported');
 await expect(rows.filter({hasText:'native_runqueue_split'})).toHaveAttribute('data-status','denied');
 await expect(page.getByTestId('frame-list')).toContainText('unresolved frame');
 await expect(page.getByTestId('profile-correlation')).toContainText('no request link');
 await expect(page.getByTestId('profile-correlation')).toContainText('is not counted against any request');
});

test('an unavailable browser sampling method reads unsupported, never zero',async()=>{
 const page=await ctx.newPage();
 await openProfile(page,UNSUPPORTED_PROFILE);
 const row=page.getByTestId('capability-row');
 await expect(row).toHaveAttribute('data-status','unsupported');
 await expect(row).toContainText('unsupported');
 await expect(page.getByTestId('unit-engine')).toContainText('unsupported');
 await expect(page.locator('body')).not.toContainText(/\b0 samples\b/);
});

test('profiles need their own grant, an unknown profile is the same not-found, and revocation clears the profile on refresh',async()=>{
 const denied=await loggedIn(telemetryOnly);
 await openProfile(denied,NATIVE_PROFILE);
 await expect(denied.getByText('This selection was not found or is not available to this account.')).toBeVisible();
 await expect(denied.getByTestId('profile-method')).toHaveCount(0);
 const victim=await createReader(owners,org,[p1]);
 await setPermissions(owners,org,victim.id,p1,true,ALL);
 const page=await loggedIn(victim);
 await openProfile(page,id());
 await expect(page.getByText('This selection was not found or is not available to this account.')).toBeVisible();
 await openProfile(page,NATIVE_PROFILE);
 await expect(page.getByTestId('profile-method')).toContainText('native_cpu');
 await setPermissions(owners,org,victim.id,p1,true,['telemetry.read','replay.read']); // profiles.read withdrawn
 await page.getByRole('button',{name:'Refresh'}).click();
 await expect(page.getByText('This selection was not found or is not available to this account.')).toBeVisible();
 await expect(page.getByTestId('profile-method')).toHaveCount(0);
 await expect(page.getByTestId('frame-list')).toHaveCount(0);
 await denied.context().close();await page.context().close();
});
