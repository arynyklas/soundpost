// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {execFile} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync,readdirSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {promisify} from 'node:util';
import {test,expect,request as pwRequest,type APIRequestContext,type Response,type Browser,type BrowserContext,type FrameLocator,type Page} from '@playwright/test';
import {activate,at,createOrg,createProject,createReader,login,onboardSdkProfileSource,origin,owner,id,sdkConfig,type Reader,type Source} from './support/real';
import {NATIVE_CAPTURE,NATIVE_PROFILE,PROFILE_WINDOW,SCHEDULER_PROFILE,UNSUPPORTED_PROFILE,deleteEntity,onboardReplaySource,seedOwnProfile,seedOwnReplay,seedProfiles,seedReplays,setPermissions,type ReplaySeed} from './support/replay';
import {PAGE_CANARIES,onboardBrowserReplaySource,record,recorderApp} from './support/recorder';

// Real server, real Chrome. Every replay chunk and profile record below was admitted through the real ingest route with a real
// source credential, stored by the real storage engine and read back through the real POST /api/v1/replays/stream and
// POST /api/v1/profiles/view routes by real readers. Nothing here fakes a server answer. The seeded replays use the closed chunk format
// built by support/replay.ts (so gaps can be made on purpose); two tests at the end instead run the REAL browser SDK recorder
// (packages/browser, support/recorder.ts) in the real Chrome over a page of canary text, delivered by the SDK's own transport. NOT covered, on purpose and stated:
//  - scheduler events: this host cannot capture them (the probe reports scheduler_event_open unsupported, tracefs_unavailable, without CAP_PERFMON), so the blocked/runnable/unknown-split display is checked on SCHEDULER_PROFILE, nativeperf.AssembleProfile over synthetic intervals. The CPU profile (NATIVE_PROFILE) is a real perf capture.
test.describe.configure({mode:'serial'});
const ALL=['telemetry.read','replay.read','profiles.read'];
let br:Browser,ctx:BrowserContext,owners:Page,api:APIRequestContext,org:string,p1:string,reader:Reader,telemetryOnly:Reader,seed:ReplaySeed,replaySource:Source;

const hash=(view:string,target:string,start=at(0),end=at(70)):string=>`#${new URLSearchParams({org,projects:p1,start:String(start),end:String(end),tz:'UTC',view,target:`${p1}:${target}`})}`;
const frameOf=(page:Page):FrameLocator=>page.frameLocator('[data-testid=replay-frame]');
const hostStatus=(page:Page)=>page.getByTestId('viewer-status');
const timeline=(page:Page)=>frameOf(page).locator('[data-replay-timeline] li');

async function openReplay(page:Page,replay:string):Promise<void>{
 await page.goto(`/${hash('replays',replay)}`);
 await activate(page);
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
 replaySource=await onboardReplaySource(owners,org,p1);
 seed=await seedReplays(api,replaySource);
 await seedProfiles(api,replaySource);
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

test('a native CPU profile keeps OS on-CPU samples, as really captured, and reads the scheduler units this host cannot measure as their capability word, never zero',async()=>{
 const c=NATIVE_CAPTURE;
 const group=(n:number):string=>String(n).replace(/\B(?=(\d{3})+(?!\d))/g,',');
 const page=await ctx.newPage();
 await openProfile(page,NATIVE_PROFILE);
 await expect(page.getByTestId('profile-method')).toContainText('native_cpu');
 const cpu=page.getByTestId('unit-oscpu');
 await expect(cpu).toHaveAttribute('data-state','measured');
 await expect(cpu).toContainText(`${group(c.cpu_samples)} on-CPU samples`);
 await expect(cpu).toContainText(`period ${group(c.period)}`);
 await expect(cpu).toContainText('requested 99 Hz');
 // The scheduler units read what the probe of this host reported for native_offcpu ('supported' without intervals: not measured), never a duration.
 const scheduler=c.off_cpu==='supported'?'not_measured':c.off_cpu;
 for(const unit of ['unit-blocked','unit-runnable','unit-unknown-split']){
  await expect(page.getByTestId(unit)).toHaveAttribute('data-state',scheduler);
  await expect(page.getByTestId(unit)).not.toContainText(/\b\d+ ns\b/);
 }
 const rows=page.getByTestId('capability-row');
 await expect(rows).toHaveCount(3);
 // The server lists capability records in no promised order: each method is checked by name, against what the probe reported.
 await expect(rows.filter({hasText:'native_cpu'})).toHaveAttribute('data-status',c.cpu);
 await expect(rows.filter({hasText:'native_offcpu'})).toHaveAttribute('data-status',c.off_cpu);
 await expect(rows.filter({hasText:'native_runqueue_split'})).toHaveAttribute('data-status',c.runqueue_split);
 await expect(page.getByTestId('frame-list')).toContainText('unresolved frame');
 await expect(page.getByTestId('profile-correlation')).toContainText('no request link');
 await expect(page.getByTestId('profile-correlation')).toContainText('is not counted against any request');
});

test('the scheduler units of a native profile (a SYNTHETIC profile: this host cannot capture scheduler events) keep blocked time, runnable delay and the unknown split apart',async()=>{
 const page=await ctx.newPage();
 await openProfile(page,SCHEDULER_PROFILE);
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
 await expect(rows.filter({hasText:'native_cpu'})).toHaveAttribute('data-status','supported');
 await expect(rows.filter({hasText:'native_offcpu'})).toHaveAttribute('data-status','supported');
 await expect(rows.filter({hasText:'native_runqueue_split'})).toHaveAttribute('data-status','denied');
 await expect(page.getByTestId('frame-list')).toContainText('unresolved frame');
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

/** The paths under `dir` (the real server's data directory) whose bytes contain any of `needles`. */
function filesContaining(dir:string,needles:readonly string[]):string[]{
 const hits:string[]=[];
 const walk=(d:string):void=>{
  for(const entry of readdirSync(d,{withFileTypes:true})){
   const path=join(d,entry.name);
   if(entry.isDirectory()){walk(path);continue;}
   if(!entry.isFile())continue;
   const bytes=readFileSync(path);
   if(needles.some((n)=>bytes.includes(n)))hits.push(path);
  }
 };
 walk(dir);
 return hits;
}

test('a replay recorded by the real browser SDK recorder in a real page is delivered by the SDK itself, stored masked and plays in the sandboxed viewer; no page text exists anywhere',async()=>{
 test.setTimeout(240_000);
 const app=await recorderApp();
 const rctx=await br.newContext();
 try{
  const config=await onboardBrowserReplaySource(owners,org,p1,app.origin);
  const page=await rctx.newPage();
  const recorded=await record(page,app,config,async(p)=>{
   // Real input through the real browser: typing into a password field and a textarea, a click, pointer movement, and a DOM mutation.
   await p.fill('#name',PAGE_CANARIES.typed);
   await p.fill('#note',PAGE_CANARIES.area);
   await p.mouse.move(40,60);await p.mouse.move(120,140);
   await p.click('#go');
   await p.evaluate((text)=>{const n=document.createElement('p');n.textContent=text;document.getElementById('result')?.append(n);},PAGE_CANARIES.paragraph+'-late');
  });
  expect(recorded.outcome.replayPolicyAllowed).toBe(true);
  expect(recorded.outcome.chunksEmitted).toBeGreaterThan(1);
  expect(recorded.outcome.flush).toEqual({pending:0,lost:0,receipts:expect.any(Number)});
  expect(recorded.outcome.flush.receipts).toBeGreaterThan(0);
  // The SDK delivered by itself: the page's only traffic beyond its own two files is the real server's ingest route.
  const foreign=recorded.requests.filter((u)=>!u.startsWith(app.origin+'/'));
  expect(foreign.length).toBeGreaterThan(0);
  expect(foreign.every((u)=>u.startsWith(origin()+'/ingest/v1/batches'))).toBe(true);
  await page.close();

  const viewer=await ctx.newPage();
  const texts:string[]=[];
  viewer.on('response',(r)=>{if(r.url().endsWith('/api/v1/replays/stream'))void r.text().then((t)=>texts.push(t),()=>undefined);});
  await openReplay(viewer,recorded.replay);
  await waitStarted(viewer);
  await viewer.getByRole('button',{name:'Play',exact:true}).click();
  await expect(hostStatus(viewer)).toContainText('All received events were delivered.');
  const labels=viewer.getByTestId('replay-labels');
  await expect(labels.getByTestId('label-loss')).toContainText('none reported by the recorder');
  await expect(labels.getByTestId('label-policy')).toHaveText('1');
  const chunks=Number(/^(\d+) /.exec(await labels.getByTestId('label-chunks').innerText())?.[1]);
  expect(chunks).toBe(recorded.outcome.chunksEmitted);
  const items=await timeline(viewer).allTextContents();
  expect(items[0]).toBe('checkpoint 1');
  expect(items.length).toBeGreaterThan(1);
  await expect(viewer.getByTestId('replay-gaps')).not.toContainText('missing');
  await expect(frameOf(viewer).locator('[data-masked]').first()).toBeVisible();
  // The page's own text, in every form it was typed or written, exists nowhere the viewer or the server can reach: not in what the viewer received,
  // not in the viewer's page or frame, and not in a byte of the server's data directory or log.
  const canaries=Object.values(PAGE_CANARIES);
  const seen=[await viewer.content(),await frameOf(viewer).locator('body').innerHTML(),...texts];
  for(const c of canaries)expect(seen.join('\n'),c).not.toContain(c);
  const dataDir=process.env.E2E_DATA_DIR;
  expect(dataDir,'the harness exports E2E_DATA_DIR').toBeDefined();
  expect(filesContaining(dataDir as string,canaries)).toEqual([]);
  const log=process.env.E2E_SERVER_LOG;
  if(log!==undefined)for(const c of canaries)expect(readFileSync(log,'utf8')).not.toContain(c);
  await viewer.close();
 }finally{
  await rctx.close();
  await app.close();
 }
});

test('a replay of the real recorder is gone for a reader who lacks replay.read, exactly like any other replay',async()=>{
 const app=await recorderApp();
 const rctx=await br.newContext();
 try{
  const config=await onboardBrowserReplaySource(owners,org,p1,app.origin);
  const page=await rctx.newPage();
  const recorded=await record(page,app,config,async(p)=>{await p.click('#go');});
  expect(recorded.outcome.flush.pending).toBe(0);
  await page.close();
  const denied=await loggedIn(telemetryOnly);
  await openReplay(denied,recorded.replay);
  await expect(denied.getByText('This selection was not found or is not available to this account.')).toBeVisible();
  await expect(denied.getByTestId('replay-frame')).toHaveCount(0);
  await denied.context().close();
 }finally{
  await rctx.close();
  await app.close();
 }
});

test('a profile produced by the real Python SDK (a bounded wall-sampling run of a named hot loop) is delivered by the SDK and reads as engine-reported samples, never as OS CPU time',async()=>{
 test.setTimeout(240_000);
 // The SDK reads its own clocks, samples its own threads, composes the capability and chunk records and delivers them over its own HTTPS transport
 // (the driver exits non-zero without durable receipts). Nothing is built by the test.
 const source=await onboardSdkProfileSource(owners,org,p1);
 const dir=mkdtempSync(join(tmpdir(),'sp-sdk-profile-'));
 const config=join(dir,'sdk.json');
 writeFileSync(config,JSON.stringify(sdkConfig(source)),{mode:0o600});
 const {stdout}=await promisify(execFile)(process.env.E2E_PYTHON??'python3',[resolve(process.cwd(),'e2e/support/sdk_profile.py')],{env:{...process.env,PYTHONPATH:resolve(process.cwd(),'../sdk/python/src'),SOUNDPOST_SDK_CONFIG:config},timeout:120_000});
 const sdk=JSON.parse(stdout.trim().split('\n').pop()??'{}') as {profile:string;samples:number;chunks:number;method:string;units:string};
 expect(sdk.method).toBe('python_wall_samples');
 expect(sdk.units).toBe('samples');
 const now=BigInt(Date.now())*1_000_000n;
 const page=await ctx.newPage();
 await page.goto(`/${hash('profiles',sdk.profile,now-3_600n*1_000_000_000n,now+3_600n*1_000_000_000n)}`);
 await expect(page.getByRole('heading',{name:/^Profile /})).toBeVisible();
 await expect(page.getByTestId('profile-method')).toContainText('runtime_cpu');
 const caps=page.getByTestId('capability-row');
 await expect(caps).toHaveCount(1);
 await expect(caps).toHaveAttribute('data-method','python_wall_samples');
 await expect(caps).toHaveAttribute('data-status','supported');
 const engine=await page.getByTestId('unit-engine').innerText();
 expect(Number(/([\d,. \u202f\u00a0]+) samples, engine-reported/.exec(engine)?.[1]?.replace(/\D/g,'')),engine).toBe(sdk.samples);
 await expect(page.getByTestId('frame-list')).toContainText('e2e_hot_loop');
 await expect(page.getByTestId('frame-list')).toContainText('e2e_sleeper');
 // Engine samples are not OS CPU: no OS on-CPU, blocked or runnable-delay figure is claimed for them.
 await expect(page.getByTestId('unit-oscpu')).not.toContainText(/\d/);
 await expect(page.getByTestId('unit-blocked')).not.toContainText(/\d+ ns/);
 await page.close();
});

for(const runtime of ['node','bun'] as const){
 test(`a profile produced by the real ${runtime==='node'?'Node':'Bun'} SDK (a bounded engine-sampling run of a named hot loop) is delivered by the SDK and reads as engine-reported samples, never as OS CPU time`,async()=>{
  test.setTimeout(240_000);
  // The SDK samples its own engine through the in-process inspector session, composes the capability and chunk records and delivers them over its own HTTPS
  // transport (the driver exits non-zero without durable receipts). Nothing is built by the test.
  const source=await onboardSdkProfileSource(owners,org,p1);
  const dir=mkdtempSync(join(tmpdir(),`sp-sdk-profile-${runtime}-`));
  const config=join(dir,'sdk.json');
  writeFileSync(config,JSON.stringify(sdkConfig(source)),{mode:0o600});
  const driver=resolve(process.cwd(),'e2e/support/sdk_profile_js.ts');
  const command=runtime==='node'?[process.env.E2E_NODE??'node',['--experimental-transform-types','--no-warnings',driver,'node']] as const:[process.env.E2E_BUN??'bun',[driver,'bun']] as const;
  const {stdout}=await promisify(execFile)(command[0],[...command[1]],{env:{...process.env,SOUNDPOST_SDK_CONFIG:config},timeout:120_000});
  const sdk=JSON.parse(stdout.trim().split('\n').pop()??'{}') as {profile:string;samples:number;chunks:number;method:string;units:string;runtime:string};
  expect(sdk.method).toBe('runtime_engine_samples');
  expect(sdk.units).toBe('samples');
  expect(sdk.runtime.toLowerCase()).toContain(runtime);
  const now=BigInt(Date.now())*1_000_000n;
  const page=await ctx.newPage();
  await page.goto(`/${hash('profiles',sdk.profile,now-3_600n*1_000_000_000n,now+3_600n*1_000_000_000n)}`);
  await expect(page.getByRole('heading',{name:/^Profile /})).toBeVisible();
  await expect(page.getByTestId('profile-method')).toContainText('runtime_cpu');
  const caps=page.getByTestId('capability-row');
  await expect(caps).toHaveCount(1);
  await expect(caps).toHaveAttribute('data-method','runtime_engine_samples');
  await expect(caps).toHaveAttribute('data-status','supported');
  const engine=await page.getByTestId('unit-engine').innerText();
  expect(Number(/([\d,. \u202f\u00a0]+) samples, engine-reported/.exec(engine)?.[1]?.replace(/\D/g,'')),engine).toBe(sdk.samples);
  await expect(page.getByTestId('frame-list')).toContainText('e2e_hot_loop_js');
  // Engine samples are not OS CPU: no OS on-CPU, blocked or runnable-delay figure is claimed for them.
  await expect(page.getByTestId('unit-oscpu')).not.toContainText(/\d/);
  await expect(page.getByTestId('unit-blocked')).not.toContainText(/\d+ ns/);
  await page.close();
 });
}

test('deleting a replay while it is open ends the view, clears the page and releases no further chunk',async()=>{
 test.setTimeout(120_000);
 const own=await seedOwnReplay(api,replaySource,8);
 const victim=await createReader(owners,org,[p1]);
 await setPermissions(owners,org,victim.id,p1,true,ALL);
 const page=await loggedIn(victim);
 const requests:string[]=[];
 page.on('request',(r)=>requests.push(r.url()));
 await openReplay(page,own);
 await waitStarted(page);
 await step(page);await expect(hostStatus(page)).toContainText('Events delivered to the viewer: 1');
 await step(page);await expect(hostStatus(page)).toContainText('Events delivered to the viewer: 2');
 await expect(timeline(page)).toHaveText(['checkpoint 1','delta 2']);
 await deleteEntity(owners,org,p1,own,'replay_chunk');
 await expect(page.getByTestId('replay-ended')).toBeVisible({timeout:20_000});
 await expect(page.getByTestId('replay-frame')).toHaveCount(0);
 await expect(page.getByTestId('replay-host')).toHaveCount(0);
 await expect(page.getByTestId('replay-labels')).toHaveCount(0);
 await expect(page.locator('body')).not.toContainText('checkpoint 1');
 const seen=requests.length;
 await page.waitForTimeout(4500);
 expect(requests.slice(seen).filter((u)=>!u.endsWith('/api/v1/session'))).toEqual([]);
 const reopened=await page.request.post('/api/v1/replays/stream',{headers:{'X-CSRF-Token':(await (await page.request.get('/api/v1/session')).json() as {csrf:string}).csrf,Origin:new URL(page.url()).origin},data:{org,project:p1,replay:own}});
 expect(reopened.status()).toBe(404);
 // Deleting one replay leaves the others: the shared seed is still there for the same reader.
 await openReplay(page,seed.clean.replay);
 await waitStarted(page);
 await page.context().close();
});

test('deleting a profile while it is open clears it on the next read and the same profile is then Not found',async()=>{
 test.setTimeout(120_000);
 const own=await seedOwnProfile(api,replaySource);
 const victim=await createReader(owners,org,[p1]);
 await setPermissions(owners,org,victim.id,p1,true,ALL);
 const page=await loggedIn(victim);
 await openProfile(page,own);
 await expect(page.getByTestId('profile-method')).toContainText('native_cpu');
 await expect(page.getByTestId('frame-list')).toBeVisible();
 await deleteEntity(owners,org,p1,own,'profile_chunk');
 await page.getByRole('button',{name:'Refresh'}).click();
 await expect(page.getByText('This selection was not found or is not available to this account.')).toBeVisible();
 await expect(page.getByTestId('profile-method')).toHaveCount(0);
 await expect(page.getByTestId('frame-list')).toHaveCount(0);
 await expect(page.locator('body')).not.toContainText('native_cpu');
 // The shared native profile is untouched.
 await openProfile(page,NATIVE_PROFILE);
 await expect(page.getByTestId('profile-method')).toContainText('native_cpu');
 await page.context().close();
});
