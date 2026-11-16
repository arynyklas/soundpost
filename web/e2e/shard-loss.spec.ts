// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type APIRequestContext,type BrowserContext,type Page,type Request} from '@playwright/test';
import {at,createOrg,createProject,createReader,faultControl,field,ingestLog,ingestMetric,login,onboardLogSource,onboardMetricSource,owner,postJson,queryBody,removeShards,tcpPath,type Reader,type Source} from './support/real';
// Real server, real Chrome, REAL shard loss. The server under test is built with -tags soundpost_faults (E2E_FAULTS=1 h.sh prep) and
// closes the replica groups of chosen data slots on request, so a reader finds some of the 64 shards unanswering. Nothing here fakes
// a server answer: data goes in through the real ingest route and every state below is what the real query/live routes answered.
// The removal is irreversible for the server, so this spec owns its server: `E2E_FAULTS=1 h.sh prep; h.sh run pw e2e/shard-loss.spec.ts`.
// It is skipped when the server has no fault-control seam, so a full run against an ordinary server never reaches it.
test.skip(!faultControl(),'needs a server built with -tags soundpost_faults (E2E_FAULTS=1) and a server of its own: shards are removed for good');
test.describe.configure({mode:'serial'});
const SERIES=24,EXPRESSION='{__name__=~"shard_s.+"}';
// What the console asks after the loss must not be answerable from before it. The server keeps a COMPLETE answer in its result cache for a minute (key: scope, expression,
// evaluation) and serves a repeat from it without asking a shard, so a repeat of a pre-removal query inside that minute is a cache hit and not a query to the lost shards.
// Measured (l3w18d1, WebKit): the first post-removal query came 53.7 s after the pre-removal one (the connection-cut test is skipped there), both projects `complete`, 24
// series, stats.cached=true, 10.8 s after the removal was acknowledged. Chromium and Firefox reach it about 61 s after (the cut test runs, 3.8 s on Chromium): past the minute by luck.
// Every query after the removal therefore uses an expression no step ran before it (it matches the same 24 series).
const COLD_EXPRESSION='{__name__=~"shard_s[0-9]+"}';
const name=(i:number):string=>`shard_s${String(i).padStart(2,'0')}`;
const hashFor=(org:string,projects:string[]):string=>`#${new URLSearchParams({org,projects:projects.join(','),start:String(at(0)),end:String(at(70)),tz:'UTC',view:'explore'})}`;
let org:string,p1:string,p2:string,reader:Reader,metric:Record<string,Source>,logSource:Source,admin:Page,api:APIRequestContext,ctx:BrowserContext,readerApi:Page;

test.beforeAll(async({browser})=>{
 test.setTimeout(300_000);
 const o=owner();
 admin=await (await browser.newContext()).newPage();
 await login(admin,o.email,o.password);
 api=await pwRequest.newContext();
 org=await createOrg(admin,'shard loss e2e org');p1=await createProject(admin,org,'shard P1');p2=await createProject(admin,org,'shard P2');
 reader=await createReader(admin,org,[p1,p2]);
 metric={[p1]:await onboardMetricSource(admin,org,p1),[p2]:await onboardMetricSource(admin,org,p2)};
 logSource=await onboardLogSource(admin,org,p1,{names:Array.from({length:12},(_,i)=>`user${i}`)});
 for(const p of [p1,p2])for(let i=0;i<SERIES;i++)await ingestMetric(api,metric[p]!,{name:name(i),at:at(10),value:i+1});
 ctx=await browser.newContext();
 readerApi=await ctx.newPage();
 await login(readerApi,reader.email,reader.password);
});

const seriesOf=(json:unknown,project:string):Map<string,string>=>{
 const out=new Map<string,string>();
 const projects=field(json,'projects');
 for(const p of Array.isArray(projects)?projects:[]){
  if(field(p,'project_id')!==project)continue;
  const vector=field(field(p,'value'),'vector');
  for(const s of Array.isArray(vector)?vector:[]){
   const labels=field(s,'labels');
   const n=(Array.isArray(labels)?labels:[]).find((l)=>field(l,'name')==='__name__');
   out.set(String(field(n,'value')),String(field(field(s,'sample'),'float')));
  }
 }
 return out;
};
const completeness=(json:unknown,project:string):unknown=>{
 const projects=field(json,'projects');
 for(const p of Array.isArray(projects)?projects:[])if(field(p,'project_id')===project)return field(p,'completeness');
 return undefined;
};
const cachedOf=(json:unknown,project:string):unknown=>{
 const projects=field(json,'projects');
 for(const p of Array.isArray(projects)?projects:[])if(field(p,'project_id')===project)return field(field(p,'stats'),'cached');
 return undefined;
};

test('a replica that has not applied the cursor a reader requires is stale, or partial with opt-in, and never an empty graph',async()=>{
 test.setTimeout(120_000);
 const complete=await postJson(readerApi,'/api/v1/query',queryBody({org,projects:[p1,p2],expression:EXPRESSION,instant:at(60)}));
 expect(complete.status).toBe(200);
 expect(completeness(complete.json,p1)).toBe('complete');
 expect(seriesOf(complete.json,p1).size).toBe(SERIES);
 const marks=field((field(complete.json,'projects') as unknown[])[0],'watermarks');
 const cursors=(Array.isArray(marks)?marks:[]) as {group:string;index:string}[];
 expect(cursors.length).toBeGreaterThan(0);
 // "Hold a replica": the reader requires a cursor beyond what the group has applied.
 const ahead=[{group:cursors[0]!.group,index:String(BigInt(cursors[0]!.index)+1000n)}];
 const strict=await postJson(readerApi,'/api/v1/query',{...queryBody({org,projects:[p1],expression:EXPRESSION,instant:at(60)}),min_cursors:ahead});
 expect(strict.status).not.toBe(200);
 expect(strict.text).toMatch(/stale/);
 expect(field(strict.json,'projects'),'a refused read carries no per-project result').toBeUndefined();
 const lenient=await postJson(readerApi,'/api/v1/query',{...queryBody({org,projects:[p1],expression:EXPRESSION,instant:at(60),allowPartial:true}),min_cursors:ahead});
 expect(lenient.status).toBe(200);
 expect(completeness(lenient.json,p1)).toBe('partial');
 for(const [n,v] of seriesOf(lenient.json,p1))expect(seriesOf(complete.json,p1).get(n),`${n} is exactly what the complete answer held`).toBe(v);
});

const panel=(page:Page,project:string)=>page.getByTestId('results').locator(`[data-project="${project}"]`);
async function openExplore(projects:string[]):Promise<Page>{
 const page=await ctx.newPage();
 await page.goto(`/${hashFor(org,projects)}`);
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 return page;
}
async function run(page:Page,expression:string):Promise<void>{
 await page.getByLabel('Query expression').fill(expression);
 await page.getByRole('button',{name:'Run query',exact:true}).click();
 await expect(page.getByTestId('evaluated-with')).toBeVisible({timeout:60_000});
 await expect(page.getByTestId('results').locator('[data-state="loading"]')).toHaveCount(0,{timeout:60_000});
}
/** name -> value text of every series row in one project's panel. */
async function shown(page:Page,project:string):Promise<Map<string,string>>{
 const rows=await panel(page,project).locator('[data-series]').evaluateAll((els)=>els.map((e)=>({text:e.textContent??'',value:e.querySelector('[data-kind]')?.textContent??''})));
 const out=new Map<string,string>();
 for(const r of rows){const m=/shard_s\d\d/.exec(r.text);if(m)out.set(m[0],r.value);}
 return out;
}

test('a reader sees every shard answer before the removal',async()=>{
 const page=await openExplore([p1,p2]);
 await run(page,EXPRESSION);
 for(const p of [p1,p2]){
  await expect(panel(page,p)).toHaveAttribute('data-state','ready');
  const rows=await shown(page,p);
  expect(rows.size).toBe(SERIES);
  for(let i=0;i<SERIES;i++)expect(rows.get(name(i))).toBe(String(i+1));
 }
});

test('the same query repeated inside the cache minute is labelled as computed earlier, never as every shard answering now (D51)',async()=>{
 const page=await openExplore([p1,p2]);
 await run(page,EXPRESSION);
 await run(page,EXPRESSION);
 for(const p of [p1,p2]){
  const state=panel(page,p).getByTestId('project-state');
  await expect(state).toContainText('Complete when computed.');
  await expect(state).toContainText('served from the result cache');
  await expect(state).not.toContainText('Every shard answered');
 }
});

const rowsOf=(page:Page)=>page.locator('[data-row]');
async function startLive(page:Page):Promise<void>{
 await page.getByRole('radio',{name:'LogQL',exact:true}).check();
 await page.getByLabel('Query expression').fill('{app="web"}');
 await page.getByRole('button',{name:'Open the live log view for this query',exact:true}).click();
 await page.getByRole('button',{name:'Start live view',exact:true}).click();
 await expect(page.getByTestId('live-status')).toContainText('Live: connected to stream');
}
/** Every sequence from 1 to the newest shown is either a row or inside a gap: a hole nobody announced would fail this. */
async function accounted(page:Page):Promise<{rows:number[];gaps:[number,number][]}>{
 const items=await page.locator('.live-items > li').evaluateAll((els)=>els.map((e)=>({gap:e.hasAttribute('data-gap'),seq:e.getAttribute('data-sequence'),from:e.getAttribute('data-from'),to:e.getAttribute('data-to')})));
 const rows=items.filter((x)=>!x.gap).map((x)=>Number(x.seq)),gaps=items.filter((x)=>x.gap).map((x):[number,number]=>[Number(x.from),Number(x.to)]);
 const covered=new Set<number>(rows);
 for(const [a,b] of gaps)for(let n=a;n<=b;n++)covered.add(n);
 const top=Math.max(0,...covered);
 for(let n=1;n<=top;n++)expect(covered.has(n),`sequence ${n} is neither a row nor in an announced gap`).toBe(true);
 return {rows,gaps};
}
const liveGets=(page:Page):Request[]=>{const l:Request[]=[];page.on('request',(r)=>{if(r.url().includes('/api/v1/live?'))l.push(r);});return l;};

test('a lost connection is shown as lost, nothing reconnects by itself, and an explicit resume continues after the last sequence',async({browserName})=>{
 // Measured (l3w15-iso3, a relay that cuts the TCP connection three ways: FIN, RST, FIN after a flush): Chromium reports the loss in 6-10 ms
 // (net::ERR_CONNECTION_CLOSED / ERR_CONNECTION_RESET), Firefox in 10-16 ms (NS_ERROR_NET_PARTIAL_TRANSFER); this Linux WebKit build reports nothing for the streaming
 // fetch in 45 s in any of the three (no requestfailed, the view keeps saying "Live: connected"). That is the engine, not the console: the console shows
 // the loss exactly when the browser reports it. The assertions below are not relaxed for the engines that report it.
 test.skip(browserName==='webkit','this WebKit build does not report a TCP connection cut under a streaming fetch within 45 s (measured, l3w15-iso3), so the console cannot show it as lost');
 test.setTimeout(240_000);
 const path=await tcpPath();
 try{
  const page=await ctx.newPage();
  const gets=liveGets(page);
  await page.goto(`${path.origin}/${hashFor(org,[p1])}`);
  await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
  await startLive(page);
  for(let i=0;i<2;i++)await ingestLog(api,logSource,{at:at(i+20),name:`user${i}`});
  await expect(rowsOf(page)).toHaveCount(2);
  path.cut();
  await expect(page.locator('[data-end="interrupted"]')).toContainText('The connection ended without a final event.');
  await expect(page.getByTestId('live-status')).toHaveText('Ended.');
  await expect(rowsOf(page)).toHaveCount(2);
  // A line committed while the browser is cut off is not shown, and nothing reconnects by itself.
  await ingestLog(api,logSource,{at:at(22),name:'user2'});
  await page.waitForTimeout(3000);
  await expect(rowsOf(page)).toHaveCount(2);
  expect(gets).toHaveLength(1);
  await page.getByRole('button',{name:'Resume after sequence 2',exact:true}).click();
  await expect(page.getByTestId('live-status')).toContainText('Live: connected');
  await expect(rowsOf(page)).toHaveCount(3);
  expect(gets).toHaveLength(2);
  expect((await gets[1]!.allHeaders())['last-event-id']).toBe('2');
  expect((await accounted(page)).gaps).toEqual([]);
 }finally{await path.close();}
});

test('a consumer that stops reading is dropped by the server, the view says the connection ended, and a resume leaves no unannounced hole',async({browserName})=>{
 test.setTimeout(300_000);
 const path=await tcpPath();
 try{
  const page=await ctx.newPage();
  await page.goto(`${path.origin}/${hashFor(org,[p1])}`);
  await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
  await startLive(page);
  await ingestLog(api,logSource,{at:at(50),name:'user0'});
  await expect(rowsOf(page)).toHaveCount(1);
  path.stall(true);
  for(let i=0;i<400;i++)await ingestLog(api,logSource,{at:at(60+i),name:`user${i%12}`});
  await page.waitForTimeout(15_000);
  path.stall(false);
  if(browserName!=='chromium'){
   // Measured (l3w15-iso3): what ends this view in Chromium is its own HTTP/2 keepalive failing through the paused relay (net::ERR_HTTP2_PING_FAILED); the
   // server does not drop the consumer here (400 events, about 120 KB, are absorbed by the socket buffers, so its 10 s write deadline never fires:
   // that deadline is TestLiveStalledTCPReaderIsDroppedByTheWriteDeadline in internal/httpapi). Firefox and WebKit have no such ping, so the stream stays up
   // and delivers everything once the relay reads again. What these engines must still show is that nothing is lost or hidden.
   await expect(rowsOf(page)).toHaveCount(401,{timeout:60_000});
   expect((await accounted(page)).gaps).toEqual([]);
   await expect(page.getByTestId('live-status')).toContainText('Live: connected');
   return;
  }
  const ended=page.locator('[data-live-end]:not([data-live-end=""])');
  await expect(ended).toBeVisible({timeout:60_000});
  const how=await ended.getAttribute('data-live-end');
  expect(['interrupted','error']).toContain(how);
  await expect(page.locator(`[data-end="${how}"]`)).toBeVisible();
  const before=await rowsOf(page).count();
  await page.getByRole('button',{name:/^Resume after sequence/}).click();
  await expect(page.getByTestId('live-status')).toContainText('Live: connected');
  await page.waitForTimeout(3000);
  const seen=await accounted(page);
  const gapped=seen.gaps.reduce((n,[a,b])=>n+(b-a+1),0);
  expect(seen.rows.length+gapped,'every one of the 401 lines is a row or inside an announced gap').toBeGreaterThanOrEqual(401);
  expect(seen.rows.length).toBeGreaterThan(before);
 }finally{await path.close();}
});

test('shards removed under an open live view: the stream ends with a stated error, rows already received are kept, and a new view does not pretend',async()=>{
 test.setTimeout(240_000);
 const page=await openExplore([p1]);
 await startLive(page);
 for(let i=0;i<3;i++)await ingestLog(api,logSource,{at:at(i+1),name:`user${i}`});
 await expect(rowsOf(page)).toHaveCount(3);
 // Why the refusal tests below ask something never asked before: a complete answer computed while every shard answered is served from the result cache after the loss,
 // labelled as cached, without asking a shard. (Two requests a few milliseconds apart, far inside the cache's minute.)
 const askCached=():Promise<{status:number;json:unknown}>=>postJson(readerApi,'/api/v1/query',queryBody({org,projects:[p1],expression:EXPRESSION,instant:at(61)}));
 const before=await askCached();
 expect(before.status).toBe(200);
 expect(completeness(before.json,p1)).toBe('complete');
 expect(cachedOf(before.json,p1),'the first answer is computed, not cached').toBe(false);
 expect(await removeShards(Array.from({length:32},(_,i)=>i))).toBe(32);
 const afterLoss=await askCached();
 expect(afterLoss.status).toBe(200);
 expect(completeness(afterLoss.json,p1)).toBe('complete');
 expect(cachedOf(afterLoss.json,p1),'the repeat after the loss is the cached answer, no shard was asked').toBe(true);
 // Nothing is committed after the removal: the stream has to notice the missing shard by itself, within its idle fence (10 s),
 // and the server must say so with its own terminal error event before it closes (never as a lost connection, never as a silent "connected").
 const end=page.locator('[data-end="error"]');
 await expect(end).toBeVisible({timeout:40_000});
 await expect(end).toHaveAttribute('data-reason','feed_error');
 await expect(end).toContainText('this is not a complete tail');
 await expect(page.locator('[data-end="interrupted"]')).toHaveCount(0);
 await expect(page.getByTestId('live-status')).toHaveText('Ended.');
 await expect(rowsOf(page)).toHaveCount(3);
 await page.getByRole('button',{name:'Start a new live view',exact:true}).click();
 await expect(page.locator('[data-end="failed"]')).toContainText('could not be started or continued (unavailable)');
 await expect(rowsOf(page)).toHaveCount(0);
});

test('half the shards removed: without opt-in the whole query is refused; with opt-in each project is Partial, shows only what answered and never a zero',async()=>{
 test.setTimeout(240_000);
 const page=await openExplore([p1,p2]);
 // No opt-in: refused as a whole, nothing returned, no value and no panel of values.
 await run(page,COLD_EXPRESSION);
 await expect(page.getByTestId('results').locator('[data-state="error"]')).toBeVisible();
 await expect(page.locator('[data-series]')).toHaveCount(0);
 await expect(page.locator('[data-kind]')).toHaveCount(0);
 // The same refusal at the route: not 200 and no result.
 const refused=await postJson(readerApi,'/api/v1/query',queryBody({org,projects:[p1,p2],expression:COLD_EXPRESSION,instant:at(60)}));
 expect(refused.status).not.toBe(200);
 expect(field(refused.json,'projects'),'a refused read carries no per-project result').toBeUndefined();
 // Opt-in: partial, and what is shown is exactly what was ingested for the series that answered.
 await page.getByLabel('Allow partial results').check();
 await run(page,COLD_EXPRESSION);
 for(const p of [p1,p2]){
  await expect(panel(page,p)).toHaveAttribute('data-state','incomplete');
  await expect(panel(page,p)).toHaveAttribute('data-completeness','partial');
  await expect(panel(page,p).getByTestId('project-state')).toContainText('Partial.');
  await expect(panel(page,p).getByTestId('project-state')).toContainText('Missing data is not zero.');
  const rows=await shown(page,p);
  expect(rows.size).toBeGreaterThan(0);
  expect(rows.size).toBeLessThan(SERIES);
  for(const [n,v] of rows){
   const i=Number(n.slice(-2));
   expect(v,`${n} shows what was ingested, not a zero`).toBe(String(i+1));
  }
 }
 // The route says the same.
 const partial=await postJson(readerApi,'/api/v1/query',queryBody({org,projects:[p1,p2],expression:COLD_EXPRESSION,instant:at(60),allowPartial:true}));
 expect(partial.status).toBe(200);
 for(const p of [p1,p2]){
  expect(completeness(partial.json,p)).toBe('partial');
  const rows=seriesOf(partial.json,p);
  expect(rows.size).toBeGreaterThan(0);
  expect(rows.size).toBeLessThan(SERIES);
 }
 // The removed series are absent from the page, not drawn as zero.
 const have=await shown(page,p1);
 const missing=Array.from({length:SERIES},(_,i)=>name(i)).filter((n)=>!have.has(n));
 expect(missing.length).toBeGreaterThan(0);
 for(const n of missing)await expect(panel(page,p1)).not.toContainText(n);
});

test('every shard removed: with opt-in the answer is Partial with no series, not an empty or zero result',async()=>{
 test.setTimeout(240_000);
 expect(await removeShards(Array.from({length:64},(_,i)=>i))).toBe(64);
 const page=await openExplore([p1,p2]);
 await page.getByLabel('Allow partial results').check();
 await run(page,COLD_EXPRESSION);
 for(const p of [p1,p2]){
  await expect(panel(page,p)).toHaveAttribute('data-state','incomplete');
  await expect(panel(page,p).getByTestId('project-state')).toContainText('Partial.');
  await expect(panel(page,p).locator('[data-series]')).toHaveCount(0);
  await expect(panel(page,p).locator('[data-kind]')).toHaveCount(0);
 }
 await expect(page.getByTestId('results')).not.toContainText('Complete and empty.');
 const api2=await postJson(readerApi,'/api/v1/query',queryBody({org,projects:[p1,p2],expression:COLD_EXPRESSION,instant:at(60),allowPartial:true}));
 expect(api2.status).toBe(200);
 for(const p of [p1,p2]){expect(completeness(api2.json,p)).toBe('partial');expect(seriesOf(api2.json,p).size).toBe(0);}
});
