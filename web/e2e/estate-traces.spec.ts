// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,type BrowserContext,type Locator,type Page} from '@playwright/test';
import {field,login,owner,postJson} from './support/real';
import {ESTATE_WINDOW,estateLink,seedEstate,type Estate} from './support/estate';
// Real server, the real browser under test, real programs. The traces below were NOT composed by this suite: a Bun gateway (packages/bun),
// a Python API with psycopg and httpx (sdk/python) over a real PostgreSQL 16 server, an uninstrumented HTTPS dependency and the order page
// built by Vite with packages/build, all from examples/reference, delivered their spans through the committed SDKs to the real ingest route
// (support/estate.ts). The page that placed each order ran in this browser. The critical-path page reads them back through the real
// POST /api/v1/traces/view route as a reader holding telemetry.read. What the product may and may not say about such a trace:
//  - frontend -> gateway -> API -> PostgreSQL and the dependency: every instrumented hop is a span, one tree under the page's action; the
//    database (twice) and the uninstrumented dependency are boundaries (a call ends there; their internals are stated as not captured);
//  - the same page in front of an API that runs WITHOUT the SDK (an unavailable producer): none of the API's spans exist, so the call to the
//    API is the boundary and the page says so; the spans of the producers that did report are unchanged;
//  - a failure the real page threw (the unpriced order) is an error occurrence on the page's own action span, linked to its issue.
// Durations are the real run's and differ every time: the assertions are about structure, the page's own arithmetic over the displayed
// numbers, and the ids the run produced.
test.describe.configure({mode:'serial'});
let ctx:BrowserContext,estate:Estate,page:Page;

const path=(p:Page):Locator=>p.getByTestId('critical-path');
const limits=(p:Page):Locator=>p.getByTestId('limits');
const rows=(p:Page):Locator=>p.locator('table.path-table tbody tr[data-span]');
async function open(trace:string):Promise<Page>{
 const p=await ctx.newPage();
 await p.goto(estateLink(estate,'traces',{target:`${estate.project}:${trace}`}));
 await expect(p.getByRole('heading',{name:/^Trace /})).toBeVisible();
 await expect(p.locator('[data-state="loading"]')).toHaveCount(0);
 await expect(rows(p).first()).toBeVisible();
 return p;
}
interface Row{operation:string;level:number;self:number;observed:number;note:string;span:string}
const MS:Record<string,number>={ns:1e-6,'µs':1e-3,ms:1,s:1000};
const ms=(text:string):number=>{const m=/exactly ([\d.]+) (ns|µs|ms|s)\b/.exec(text);if(!m)throw Error(`no exact duration in ${text}`);return Number(m[1])*(MS[m[2] as string] as number);};
/** The critical-path table as the page prints it: operation (kind), level, time on the path itself, observed duration, note. */
async function table(p:Page):Promise<Row[]>{
 const spans=await rows(p).evaluateAll((rs)=>rs.map((r)=>({id:r.getAttribute('data-span')??'',text:(r as HTMLElement).innerText})));
 return spans.map((r)=>{const c=r.text.split('\t').map((x)=>x.trim());return {span:r.id,operation:c[0]??'',level:Number(/Level (\d+)/.exec(c[1]??'')?.[1]),self:ms(c[2]??''),observed:ms(c[3]??''),note:c[4]??''};});
}
const BOUNDARY='dependency boundary: internals not captured';

test.beforeAll(async({browser})=>{
 test.setTimeout(900_000);
 const o=owner();
 const owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 estate=await seedEstate(owners,browser);
 ctx=await browser.newContext({ignoreHTTPSErrors:true});
 page=await ctx.newPage();
 await login(page,estate.analyst.email,estate.analyst.password);
});
test.afterAll(async()=>{await estate?.close();});
test.afterEach(async()=>{for(const p of ctx.pages())if(p!==page)await p.close();});

test('the estate delivered everything it produced: every program flushed with nothing pending and nothing lost, three distinct traces',()=>{
 for(const n of ['gateway','gateway-dark','api'])expect(estate.flushed[n],n).toMatchObject({pending:0,lost:0});
 for(const o of [estate.priced,estate.unpriced,estate.dark])expect(o.flush).toMatchObject({pending:0,lost:0});
 expect(estate.priced.result).toMatch(/^Order #\d+: 2 x sku-100 = \$25\.00 \(priced\)$/);
 expect(estate.unpriced.pageErrors).toEqual([{name:'UnpricedOrderError'}]);
 expect(new Set([estate.priced.trace,estate.unpriced.trace,estate.dark.trace]).size).toBe(3);
});

test('frontend to gateway to API to PostgreSQL and the dependency: one tree of eight real spans, three dependency boundaries, a path that adds up',async()=>{
 const p=await open(estate.priced.trace);
 const t=await table(p);
 expect(t.map((r)=>r.operation)).toEqual(['ui.action (internal)','http.call (client)','request (server)','http.call (client)','request (server)','db.execute (client)','db.execute (client)','http.call (client)']);
 expect(t.map((r)=>r.level)).toEqual([1,2,3,4,5,6,6,6]);
 await expect(p.getByTestId('path-counts')).toContainText('8 spans were read. 8 are on a critical path; 0 are off every path');
 await expect(p.getByText(/^Tree \d+:/)).toHaveCount(1);
 await expect(p.getByText(/^Tree 1: a span without a parent/)).toBeVisible();
 // The instrumented hops (page -> gateway, gateway -> API) are spans on both sides; only the database (twice) and the uninstrumented dependency end at a boundary.
 expect(t.map((r)=>r.note===BOUNDARY)).toEqual([false,false,false,false,false,true,true,true]);
 expect(t.slice(0,5).every((r)=>r.note==='No limit reported for this span.')).toBe(true);
 await expect(limits(p).locator('[data-limit="dependency_boundary"]')).toContainText('3 dependency calls end at the dependency boundary');
 await expect(limits(p).locator('[data-limit="unlike_clock_domains"]')).toContainText('never subtracted');
 await expect(limits(p).locator('[data-limit="unlike_clock_domains"]')).toContainText('largest stated uncertainty: unknown (no bound stated)');
 await expect(limits(p).locator('[data-limit="unlike_clock_domains"]')).not.toContainText('4611686018');
 await expect(limits(p).locator('[data-limit="none_reported"]')).toHaveCount(0);
 // The page's own arithmetic over the numbers it prints: the observed duration of the trace is the root span's, never a sum of the children, and the
 // time on the path itself of every segment adds up to it (a serial chain: nothing counted twice, nothing dropped).
 const root=t[0] as Row;
 await expect(p.getByTestId('observed-duration')).toContainText(`exactly `);
 expect(ms((await p.getByTestId('observed-duration').innerText()))).toBeCloseTo(root.observed,3);
 expect(t.reduce((n,r)=>n+r.self,0)).toBeCloseTo(root.observed,1);
 for(const [i,r] of t.entries())if(i>0)expect(r.observed,`${r.operation} fits inside the root`).toBeLessThanOrEqual(root.observed);
 // The two ends of the real work are the page's action and the dependency call; the database calls are shorter than the API request that made them.
 expect((t[5] as Row).observed+(t[6] as Row).observed+(t[7] as Row).observed).toBeLessThanOrEqual((t[4] as Row).observed);
});

test('the same page in front of an API that produced no telemetry (an unavailable producer): four spans, the call to the API is the boundary, nothing is shown inside it',async()=>{
 const p=await open(estate.dark.trace);
 const t=await table(p);
 expect(t.map((r)=>r.operation)).toEqual(['ui.action (internal)','http.call (client)','request (server)','http.call (client)']);
 await expect(p.getByTestId('path-counts')).toContainText('4 spans were read. 4 are on a critical path; 0 are off every path');
 expect(t.map((r)=>r.note===BOUNDARY)).toEqual([false,false,false,true]);
 await expect(limits(p).locator('[data-limit="dependency_boundary"]')).toContainText('1 dependency call ends at the dependency boundary');
 await expect(p.getByText('db.execute')).toHaveCount(0);
 // The boundary call is the one made to the API (alias api); the API's own request span and its database spans do not exist and are not drawn.
 await path(p).getByRole('button',{name:'Show details of span http.call, client, level 4'}).click();
 await expect(p.getByTestId('span-details')).toContainText(/Dependency\s*api/);
 await expect(p.getByTestId('span-details')).toContainText('Limits of this span');
 await expect(p.getByTestId('span-details')).toContainText(BOUNDARY);
 await expect(rows(p)).toHaveCount(4);
});

test('a span is linked to the Logs window of its own recorded time, from the real trace read',async()=>{
 const p=await open(estate.priced.trace);
 const view=await postJson(page,'/api/v1/traces/view',{org:estate.org,project:estate.project,trace:estate.priced.trace,window:ESTATE_WINDOW});
 expect(view.status).toBe(200);
 const spans=field(field(view.json,'path'),'spans') as {span_id:string;operation:string;start_wall_ns:string;end_wall_ns:string;dependency_alias?:string}[];
 expect(spans).toHaveLength(8);
 const gatewayCall=spans.find((s)=>s.operation==='http.call'&&s.dependency_alias==='api');
 expect(gatewayCall,'the gateway call to the API').toBeDefined();
 const call=gatewayCall as {span_id:string;start_wall_ns:string;end_wall_ns:string};
 await path(p).getByRole('button',{name:'Show details of span http.call, client, level 4'}).click();
 const link=p.getByTestId('span-details').getByRole('link',{name:'Logs in the window of this span'});
 const q=new URLSearchParams((await link.getAttribute('href')??'').replace(/^#/,''));
 expect(q.get('view')).toBe('logs');
 expect(q.get('org')).toBe(estate.org);
 expect(q.get('projects')).toBe(estate.project);
 expect(BigInt(q.get('start')??'0')).toBe(BigInt(call.start_wall_ns)-1_000_000_000n);
 expect(BigInt(q.get('end')??'0')).toBe(BigInt(call.end_wall_ns)+1_000_000_000n+1n);
 await expect(p.getByTestId('span-details')).toContainText(call.span_id);
});

test('the failure the real page threw is an error occurrence on the page\'s own action span, linked to its issue, and no other span claims it',async()=>{
 const p=await open(estate.unpriced.trace);
 const t=await table(p);
 expect(t).toHaveLength(8);
 const action=path(p).getByRole('button',{name:'Show details of span ui.action, internal, level 1'});
 await action.click();
 const details=p.getByTestId('span-details');
 await expect(details).toContainText('error');
 const target=details.locator('[data-target-kind="error"][data-target-available="yes"]');
 await expect(target).toHaveCount(1);
 await expect(target).toContainText(estate.occurrence);
 await expect(details.getByRole('link',{name:'Open the issue holding this occurrence'})).toHaveAttribute('href',/view=issues/);
 // No other span of the trace carries that occurrence: select the API's request span and look.
 await path(p).getByRole('button',{name:'Show details of span request, server, level 5'}).click();
 await expect(p.getByTestId('span-details').locator('[data-target-kind="error"]')).toHaveCount(0);
 // The priced order threw nothing: its action span has no error occurrence.
 const q=await open(estate.priced.trace);
 await path(q).getByRole('button',{name:'Show details of span ui.action, internal, level 1'}).click();
 await expect(q.getByTestId('span-details').locator('[data-target-kind="error"]')).toHaveCount(0);
});
