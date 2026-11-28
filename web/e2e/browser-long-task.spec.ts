// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {readFileSync} from 'node:fs';
import {test,expect,type Browser,type BrowserContext,type Page} from '@playwright/test';
import {createOrg,createProject,createReader,login,owner,type Reader} from './support/real';
import {setPermissions} from './support/replay';
import {onboardBrowserProfileSource,profileApp,runProfile,type ProfileApp,type ProfileRun} from './support/browser_profile';

// 10.17#13 end to end: the REAL browser SDK (packages/browser startClientProfile with longTasks) on an ordinary page, in each Playwright browser project, against the
// REAL server. The page lists the operation `long_task` in its SDK `operations`, its source's signed policy lists it too, and the page runs two separate busy tasks. The SDK
// observes the engine's Long Tasks API and delivers, with its own transport and a browser source's credential, one capability record of its own (signal `span`, method
// `long_task`) and one elapsed-time ROOT SPAN of operation `long_task` per task the engine reported. The real ingest route must admit them (HTTP 200 per batch), and the real
// console reads them back (the Explore export of the `span` signal and the trace view). Nothing here builds a span, a capability or a clock reading; the test compares what the
// page's report says with what the browser sent and what the server stored.
//  - chromium (Long Tasks API and JS Self-Profiling, the header opts the page in): `observed`, supported capability, >= 1 stored span per reported task;
//  - firefox, webkit: the engine has no JS Self-Profiling API, the profile run is refused before any observation (see packages/browser/src/profile.ts), so the page reports no
//    Long Task state, the SDK delivers NO long_task capability and NO span, and the server stores none: the absence is the engine's answer, never a zero or an invented span.
test.describe.configure({mode:'serial'});

const OBSERVING:Record<string,boolean>={chromium:true,firefox:false,webkit:false};

let br:Browser;
let ctx:BrowserContext,owners:Page,org:string;
const ALL=['telemetry.read','replay.read','profiles.read'];

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
 org=await createOrg(owners,'browser long task e2e org');
 ctx=await browser.newContext();
});

let app:ProfileApp|undefined;
test.afterAll(async()=>{await app?.close();});

interface SpanClock{wall_ns:string;mono_ns:string}
interface SpanWire{trace_id:string;span_id:string;parent_id:string|null;span_kind:string;operation:string;start:SpanClock;end:SpanClock|null;status:string;dependency_alias:string;links:unknown[]}

test('a real browser delivers its Long Tasks as long_task spans that the real server admits and the console reads back; an engine without the API delivers none and says so',async({},info)=>{
 test.setTimeout(240_000);
 const engine=info.project.name;
 const observing=OBSERVING[engine];
 if(observing===undefined)throw Error(`no expectation for the browser project ${engine}`);
 const project=await createProject(owners,org,`browser long task ${engine}`);
 const reader=await createReader(owners,org,[project]);
 await setPermissions(owners,org,reader.id,project,true,ALL);
 app=await profileApp('js-profiling');
 const config=await onboardBrowserProfileSource(owners,org,project,app.origin,true);
 const page=await ctx.newPage();
 const run:ProfileRun=await runProfile(page,app,config,600,true);
 const {outcome,deliveries}=run;
 console.log(`BROWSER_LONG_TASK_OBSERVED ${engine} ${JSON.stringify({status:outcome.status,reason:outcome.reason,longTasks:outcome.longTasks,diagnostics:outcome.diagnostics,deliveries:deliveries.map((d)=>({status:d.status,kinds:d.kinds}))})}`);

 // ---- what the engine and the SDK said ----
 expect(deliveries.length).toBeGreaterThan(0);
 expect(deliveries.map((d)=>d.status),'every batch the page sent was admitted by the real ingest route').toEqual(deliveries.map(()=>200));
 const records=deliveries.flatMap((d)=>d.records);
 const spanRecords=records.filter((r)=>r.kind==='span');
 const longTaskCapabilities=records.filter((r)=>r.kind==='capability'&&r.payload.method==='long_task');
 expect(outcome.diagnostics.invalid_clock,'no interval the SDK handed to its span path was refused as an impossible clock').toBeUndefined();

 const reading=await loggedIn(reader);
 const stored=await exported(reading,project,'span');
 if(!observing){
  expect(outcome.status).toBe('unsupported');
  expect(outcome.longTasks.entries).toEqual([]);
  expect(spanRecords).toEqual([]);
  expect(longTaskCapabilities).toEqual([]);
  expect(stored,'no span exists: an engine that cannot observe Long Tasks is not a page with none').toEqual([]);
  await reading.context().close();
  await page.close();
  return;
 }

 expect(outcome.status).toBe('supported');
 expect(outcome.longTasks.state).toBe('observed');
 expect(outcome.longTasks.entries.length,'the engine reported both busy tasks of the page as Long Tasks').toBe(2);
 for(const task of outcome.longTasks.entries)expect(task.durationMs).toBeGreaterThanOrEqual(50);
 expect(outcome.longTasks.dropped).toBe(0);

 // ---- what the browser really sent: a capability of its own, then exactly one root span per reported task, on the client's clock ----
 expect(longTaskCapabilities).toHaveLength(1);
 expect(longTaskCapabilities[0]!.payload).toMatchObject({signal:'span',method:'long_task',status:'supported',reason:'ok'});
 const sent=spanRecords.map((r)=>r.payload as unknown as SpanWire);
 expect(sent).toHaveLength(outcome.longTasks.entries.length);
 for(const span of sent){
  expect(span).toMatchObject({operation:'long_task',span_kind:'internal',status:'ok',parent_id:null,dependency_alias:'',links:[]});
  expect(span.end).not.toBeNull();
  expect(BigInt(span.end!.mono_ns)-BigInt(span.start.mono_ns)).toBeGreaterThanOrEqual(50_000_000n);
 }
 const clockPairs=(spans:{start:string;end:string}[]):string[]=>spans.map((s)=>`${s.start}-${s.end}`).sort();
 expect(clockPairs(sent.map((s)=>({start:s.start.mono_ns,end:s.end!.mono_ns})))).toEqual(clockPairs(outcome.longTasks.entries.map((t)=>({start:t.startMonoNs,end:t.endMonoNs}))));
 expect(new Set(sent.map((s)=>s.trace_id)).size,'every Long Task is its own one-span trace').toBe(sent.length);

 // ---- what the real server stored, read through the real console ----
 expect(stored).toHaveLength(sent.length);
 for(const line of stored){
  expect(line.project).toBe(project);
  expect(line.payload).toMatchObject({Span:{operation:'long_task',span_kind:'internal',status:'ok',parent_id:null,dependency_alias:''}});
 }
 const storedWire=stored.map((l)=>(l.payload as {Span:SpanWire}).Span);
 expect(storedWire.map((s)=>s.trace_id).sort()).toEqual(sent.map((s)=>s.trace_id).sort());
 expect(clockPairs(storedWire.map((s)=>({start:s.start.mono_ns,end:s.end!.mono_ns})))).toEqual(clockPairs(sent.map((s)=>({start:s.start.mono_ns,end:s.end!.mono_ns}))));
 const capabilities=await exported(reading,project,'capability');
 expect(capabilities.map((l)=>(l.payload as {Capability:{signal:string;method:string;status:string}}).Capability).filter((c)=>c.method==='long_task')).toMatchObject([{signal:'span',method:'long_task',status:'supported'}]);

 const first=sent[0]!;
 await reading.goto(`/${hash(project,'traces',first.trace_id)}`);
 await expect(reading.getByRole('heading',{name:/^Trace /})).toBeVisible();
 await expect(reading.locator('[data-state="loading"]')).toHaveCount(0);
 await expect(reading.getByTestId('critical-path')).toContainText('long_task');
 await expect(reading.getByTestId('observed-duration')).toContainText('Observed duration of this trace');
 await reading.context().close();
 await page.close();
});
