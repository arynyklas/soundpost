// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {readFileSync} from 'node:fs';
import {test,expect,type Browser,type BrowserContext,type Page} from '@playwright/test';
import {createOrg,createProject,createReader,login,owner,type Reader} from './support/real';
import {setPermissions} from './support/replay';
import {onboardBrowserProfileSource,profileApp,runProfile,type ProfileApp,type ProfileRun} from './support/browser_profile';

// Real server, and in EACH Playwright browser project the REAL browser SDK profiler (packages/browser startClientProfile, bundled by bun) on an ORDINARY
// page: the page is served over HTTPS with the `Document-Policy: js-profiling` header, runs a named busy loop, and the SDK probes its own engine (it
// constructs the W3C `Profiler`; it never reads a version), builds the capability record and any profile chunk and delivers them itself, with its own
// transport and a browser source's credential, to the real ingest route. The records are read back through the real console: the profile view page
// (deep link) and the Explore raw-record export. Nothing here builds, converts or fakes a capability or a chunk; the test only observes what this
// engine really answers and encodes exactly that, per project:
//  - chromium (the header opts the page in): a supported sampling capability and real samples with frames of the busy loop;
//  - firefox, webkit: the engine has no JS Self-Profiling API (`Profiler` is not exposed), so the SDK's answer is `unsupported` with the typed reason
//    `js_self_profiling_unavailable`, and NO profile chunk exists: no sample is invented and nothing is shown as zero.
// NOT covered, stated: Safari is out of scope (D10), and Playwright WebKit is not a Safari release; see docs/support/browsers.md.
test.describe.configure({mode:'serial'});

interface Answer{runtime:RegExp;status:string;reason:string;profilerGlobal:string;sampled:boolean}
// What each engine really answers, observed on the VM (logs/B-green-*.log of the evidence directory print the full outcome of every run).
// `runtime` is the engine the SDK names in its capability record from the browser's own identity (Playwright WebKit presents itself as Safari 27.2 and is not a Safari release).
const ENGINE:Record<string,Answer>={
 chromium:{runtime:/^(Chromium|Chrome)\/\d+/,status:'supported',reason:'ok',profilerGlobal:'function',sampled:true},
 firefox:{runtime:/^Firefox\/\d+/,status:'unsupported',reason:'js_self_profiling_unavailable',profilerGlobal:'undefined',sampled:false},
 webkit:{runtime:/^Safari\/\d+/,status:'unsupported',reason:'js_self_profiling_unavailable',profilerGlobal:'undefined',sampled:false},
};

let br:Browser;
let ctx:BrowserContext,owners:Page,org:string;
const ALL=['telemetry.read','replay.read','profiles.read'];

// The console windows are read around now: the SDK stamps its records with the page's own wall clock.
const windowNs=():{start:string;end:string}=>{const now=BigInt(Date.now())*1_000_000n,hour=3_600n*1_000_000_000n;return {start:String(now-hour),end:String(now+hour)};};
const hash=(project:string,view:string,target?:string):string=>`#${new URLSearchParams({org,projects:project,...windowNs(),tz:'UTC',view,...(target===undefined?{}:{target:`${project}:${target}`})})}`;

async function loggedIn(who:Reader):Promise<Page>{
 const c=await br.newContext();
 const page=await c.newPage();
 await login(page,who.email,who.password);
 return page;
}

interface ExportLine{time_ns:string;project:string;payload:Record<string,unknown>}
/** The real Explore export (asynchronous, authorized again per chunk) of one signal of one project in the window around now, downloaded through the real console. */
async function exported(page:Page,project:string,signal:string):Promise<ExportLine[]>{
 await page.goto(`/${hash(project,'logs')}`);
 await expect(page.getByRole('heading',{level:1,name:'Logs',exact:true})).toBeVisible();
 const panel=page.locator('[data-section="export"]');
 await panel.getByLabel('Signal').selectOption(signal);
 await panel.getByRole('button',{name:'Start export',exact:true}).click();
 await expect(panel.getByTestId('export-status')).toContainText('Complete:',{timeout:30_000});
 const [download]=await Promise.all([page.waitForEvent('download'),panel.getByRole('button',{name:'Download the export',exact:true}).click()]);
 const text=readFileSync(await download.path(),'utf8');
 return text.trim()===''?[]:text.trim().split('\n').map((l)=>JSON.parse(l) as ExportLine);
}

test.beforeAll(async({browser})=>{
 test.setTimeout(240_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 org=await createOrg(owners,'browser profile capability e2e org');
 ctx=await browser.newContext();
});

let app:ProfileApp|undefined;
test.afterAll(async()=>{await app?.close();});

test('the real browser profiler on an ordinary page reports what this engine really answers; the real ingest route stores it and the console reads it back without inventing samples',async({},info)=>{
 test.setTimeout(240_000);
 const engine=info.project.name;
 const want=ENGINE[engine];
 if(want===undefined)throw Error(`no expectation for the browser project ${engine}`);
 const project=await createProject(owners,org,`browser profile ${engine}`);
 const reader=await createReader(owners,org,[project]);
 await setPermissions(owners,org,reader.id,project,true,ALL);
 app=await profileApp('js-profiling');
 const config=await onboardBrowserProfileSource(owners,org,project,app.origin);
 const page=await ctx.newPage();
 const run:ProfileRun=await runProfile(page,app,config);
 const {outcome,deliveries}=run;
 // The observed answer of this engine, printed in full (the evidence log keeps it; it is the only source of the expectations above).
 console.log(`BROWSER_PROFILE_OBSERVED ${engine} ${JSON.stringify({outcome,deliveries:deliveries.map((d)=>({status:d.status,kinds:d.kinds})),requestOrigins:run.requestOrigins})}`);

 // ---- what the engine answered, as the SDK reported it ----
 expect(outcome.profilerGlobal,`typeof Profiler in ${outcome.userAgent}`).toBe(want.profilerGlobal);
 expect(outcome.runtime).toMatch(want.runtime);
 expect(outcome.status).toBe(want.status);
 expect(outcome.reason).toBe(want.reason);
 if(want.sampled){
  expect(outcome.sampleCount).toBeGreaterThan(0);
  expect(outcome.ack.status).toBe('obtained');
  expect(outcome.frameFunctions).toContain('e2eBrowserHotLoop');
 }else{
  expect(outcome.sampleCount).toBe(0);
  expect(outcome.frameFunctions).toEqual([]);
  expect(outcome.stoppedBy).toBe('not_started');
  expect(outcome.coverage).toEqual({frames:'none',threads:'none',workers:'none',tasks:'none'});
 }
 // ---- what the browser really sent, and what the real server answered: the page talked to itself and to the real server only ----
 expect(run.requestOrigins.sort()).toEqual([app.origin,new URL(config.endpoint as string).origin].sort());
 expect(deliveries.length).toBeGreaterThan(0);
 expect(deliveries.map((d)=>d.status)).toEqual(deliveries.map(()=>200));
 const records=deliveries.flatMap((d)=>d.records);
 const capabilities=records.filter((r)=>r.kind==='capability');
 const chunks=records.filter((r)=>r.kind==='profile_chunk');
 expect(capabilities).toHaveLength(1);
 const capability=capabilities[0]!.payload;
 expect(capability).toMatchObject({signal:'profile_chunk',method:'browser_js_self_profile',status:want.status,reason:want.reason});
 expect(chunks.length>0).toBe(want.sampled);

 // ---- read back through the real console ----
 const reading=await loggedIn(reader);
 const stored=await exported(reading,project,'capability');
 expect(stored).toHaveLength(1);
 expect(stored[0]!.project).toBe(project);
 // The export carries each record in the server's own union envelope (one member per signal kind): a capability record is the `Capability` member and no other member is set.
 expect(stored[0]!.payload).toMatchObject({Capability:{signal:'profile_chunk',method:'browser_js_self_profile',status:want.status,reason:want.reason,runtime:outcome.runtime,version:outcome.version},Profile:null});
 const storedChunks=await exported(reading,project,'profile_chunk');
 expect(storedChunks.length>0).toBe(want.sampled);

 const profileId=want.sampled?String(chunks[0]!.payload.profile_id):capabilities[0]!.id;
 await reading.goto(`/${hash(project,'profiles',profileId)}`);
 if(want.sampled){
  await expect(reading.getByRole('heading',{name:/^Profile /})).toBeVisible();
  await expect(reading.getByTestId('profile-method')).toContainText('runtime_cpu');
  const caps=reading.getByTestId('capability-row');
  await expect(caps).toHaveCount(1);
  await expect(caps).toHaveAttribute('data-method','browser_js_self_profile');
  await expect(caps).toHaveAttribute('data-status','supported');
  const text=await reading.getByTestId('unit-engine').innerText();
  expect(Number(/([\d,. \u202f\u00a0]+) samples, engine-reported/.exec(text)?.[1]?.replace(/\D/g,'')),text).toBe(outcome.sampleCount);
  await expect(reading.getByTestId('frame-list')).toContainText('e2eBrowserHotLoop');
  // Engine samples are not OS CPU: no OS on-CPU, blocked or runnable-delay figure is claimed for them.
  await expect(reading.getByTestId('unit-oscpu')).not.toContainText(/\d/);
  await expect(reading.getByTestId('unit-blocked')).not.toContainText(/\d+ ns/);
 }else{
  // A refused run stores the capability record alone (never a chunk), and the profile view is keyed by a profile: there is none to open, so the
  // console answers Not found for it, and nothing in the page is a profile or a zero.
  await expect(reading.locator('[data-state="unauthorized"]')).toContainText('Not found');
  await expect(reading.getByTestId('profile-method')).toHaveCount(0);
  await expect(reading.getByTestId('capability-row')).toHaveCount(0);
  await expect(reading.locator('body')).not.toContainText(/\b0 samples\b/);
 }
 await reading.context().close();
 await page.close();
});
