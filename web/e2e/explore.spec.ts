// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type APIRequestContext,type BrowserContext,type Locator,type Page,type Request} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {at,createReader,id,login,owner,seedExplore,setGrant,type ExploreSeed} from './support/real';
// Real server, real Chrome. Every number, nanosecond and label below was admitted through the real ingest route and is
// read back through the real C06 query, discovery, exemplar, format, investigate and export routes by a real reader who
// holds telemetry.read on two projects. Nothing in this file fakes a server answer.
const origin=new URL(process.env.SOUNDPOST_TEST_ORIGIN??'').origin;
const PROM_310='promql-prometheus-3.1.0',PROM_3135='promql-prometheus-3.13.5';
test.describe.configure({mode:'serial'});
let seed:ExploreSeed,ctx:BrowserContext,owners:Page,api:APIRequestContext;

const hashFor=(org:string,projects:string[],view='explore'):string=>`#${new URLSearchParams({org,projects:projects.join(','),start:String(at(0)),end:String(at(70)),tz:'UTC',view})}`;
async function open(projects:string[]=[seed.p1,seed.p2],org=seed.org):Promise<Page>{
 const page=await ctx.newPage();
 await page.goto(`/${hashFor(org,projects)}`);
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 return page;
}
const results=(page:Page):Locator=>page.getByTestId('results');
const panel=(page:Page,project:string):Locator=>results(page).locator(`[data-project="${project}"]`);
async function settled(page:Page):Promise<void>{
 await expect(page.getByTestId('evaluated-with')).toBeVisible();
 await expect(results(page).locator('[data-state="loading"]')).toHaveCount(0);
}
async function run(page:Page,expression:string):Promise<void>{
 await page.getByLabel('Query expression').fill(expression);
 await page.getByRole('button',{name:'Run query',exact:true}).click();
 await settled(page);
}
const only=async(page:Page,project:string,others:string[])=>{for(const o of others)await page.getByRole('checkbox',{name:o}).uncheck();await expect(page.getByRole('checkbox',{name:project})).toBeChecked();};
const rowOf=(scope:Locator,text:string):Locator=>scope.locator('[data-series]').filter({hasText:text});

test.beforeAll(async({browser})=>{
 test.setTimeout(300_000);
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 api=await pwRequest.newContext();
 seed=await seedExplore(owners,api);
 ctx=await browser.newContext();
 const page=await ctx.newPage();
 await login(page,seed.reader.email,seed.reader.password);
 await page.close();
});
test.afterEach(async()=>{for(const p of ctx.pages())await p.close();});

test('scalar, string, vector and a project with nothing: each project is its own panel with its own state',async()=>{
 const page=await open();
 await run(page,'1+1');
 await expect(results(page).locator('[data-project]')).toHaveCount(2);
 await expect(results(page).locator('[data-result="scalar"] [data-kind="finite"]')).toHaveText(['2','2']);
 await run(page,'"hello"');
 await expect(results(page).getByTestId('string-value')).toHaveText(['hello','hello']);
 await run(page,'explore_gauge');
 await expect(panel(page,seed.p1)).toHaveAttribute('data-state','ready');
 await expect(rowOf(panel(page,seed.p1),'explore_gauge').locator('[data-kind]')).toHaveText('48');
 await expect(panel(page,seed.p1).locator('[data-series]')).toHaveCount(1);
 // P2 has no such series: complete and empty, said in words, never a zero.
 await expect(panel(page,seed.p2)).toHaveAttribute('data-state','empty');
 await expect(panel(page,seed.p2)).toContainText('Complete and empty');
 await expect(panel(page,seed.p2).locator('[data-series]')).toHaveCount(0);
 await expect(page.getByTestId('evaluated-with')).toContainText(PROM_310);
 await expect(page.getByTestId('evaluated-with')).toContainText('partial results not allowed');
 // The server's own formatter, through the format route.
 await page.getByLabel('Query expression').fill('sum   by (job)(rate(explore_requests[5m]))');
 await page.getByRole('button',{name:'Format expression',exact:true}).click();
 await expect(page.getByTestId('formatted-text')).toHaveText('sum by (job)(rate(explore_requests[5m]))');
 await page.getByRole('button',{name:'Replace the expression with the formatted text',exact:true}).click();
 await expect(page.getByLabel('Query expression')).toHaveValue('sum by (job)(rate(explore_requests[5m]))');
});

test('the same metric and labels in two projects are two named panels, never merged or labelled with a project',async()=>{
 const page=await open();
 await run(page,'explore_shared');
 const p1=panel(page,seed.p1),p2=panel(page,seed.p2);
 await expect(p1.locator('[data-series]')).toHaveCount(1);
 await expect(p2.locator('[data-series]')).toHaveCount(1);
 await expect(rowOf(p1,'explore_shared').locator('[data-kind]')).toHaveText('1');
 await expect(rowOf(p2,'explore_shared').locator('[data-kind]')).toHaveText('2');
 for(const p of [p1,p2]){await expect(p).toHaveAttribute('data-state','ready');await expect(p).not.toContainText('project=');}
 await expect(p1).not.toContainText(seed.p2);
 await expect(p2).not.toContainText(seed.p1);
 await expect(results(page).locator('[data-project]')).toHaveCount(2);
});

test('a missing sample is a gap in the line, never a zero',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await page.getByRole('radio',{name:'Range over the selected window',exact:true}).check();
 await page.getByLabel('Step (seconds)').fill('10');
 await run(page,'explore_stale');
 const series=panel(page,seed.p1).locator('[data-series]');
 await expect(series).toHaveCount(1);
 const chart=series.locator('svg.series-chart');
 await expect(chart).toHaveAttribute('data-segments','2');
 await expect(chart).toHaveAttribute('data-gap-count','1');
 await expect(chart.locator('[data-gap]')).toHaveAttribute('data-after',String(at(20)));
 await expect(chart.locator('[data-gap]')).toHaveAttribute('data-before',String(at(60)));
 await expect(series.locator('.gap-list')).toContainText('no sample for 3 evaluation steps');
 await expect(series.locator('.gap-list')).toContainText('A missing sample is absent, not zero.');
 await series.locator('summary').filter({hasText:'Data table'}).click();
 await expect(series.locator('tr[data-sample]')).toHaveCount(5);
 await expect(series.locator('tr[data-sample] [data-kind]')).toHaveText(['10','11','12','20','20']);
 await expect(series.locator('tr[data-gap]')).toHaveCount(1);
 // No sample anywhere is a zero.
 await expect(series.locator('tr[data-sample] [data-kind="finite"]').filter({hasText:/^0$/})).toHaveCount(0);
});

test('ordinary NaN, infinities and negative zero are values; a stale marker is the absence of one',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await run(page,'{__name__=~"explore_(nan|inf|neginf|negzero)"}');
 const p1=panel(page,seed.p1);
 const nan=rowOf(p1,'explore_nan').locator('[data-bits]');
 await expect(nan).toHaveAttribute('data-kind','nan');
 await expect(nan).toHaveAttribute('data-bits','7ff8000000000001');
 await expect(nan).toContainText('NaN');
 await expect(nan).toContainText('not a number: a real value, not a missing one');
 await expect(rowOf(p1,'explore_inf').locator('[data-bits]')).toHaveAttribute('data-kind','pos_inf');
 await expect(rowOf(p1,'explore_inf').locator('[data-bits]')).toContainText('+Inf');
 await expect(rowOf(p1,'explore_neginf').locator('[data-bits]')).toHaveAttribute('data-kind','neg_inf');
 const zero=rowOf(p1,'explore_negzero').locator('[data-bits]');
 await expect(zero).toHaveAttribute('data-bits','8000000000000000');
 await expect(zero).toHaveAttribute('data-kind','finite');
 await expect(zero).toHaveText('-0');
 // A range query draws NaN as a mark on a broken line, not as a gap and not as a number.
 await page.getByRole('radio',{name:'Range over the selected window',exact:true}).check();
 await page.getByLabel('Step (seconds)').fill('10');
 await run(page,'explore_nan');
 const chart=panel(page,seed.p1).locator('svg.series-chart');
 await expect(chart).toHaveAttribute('data-nan-count','7');
 await expect(chart).toHaveAttribute('data-gap-count','0');
 // Instant at +40s: the stale marker at +30s ended `explore_stale`; the answer is empty, not NaN and not 0.
 await page.getByRole('radio',{name:'Instant',exact:true}).check();
 await page.getByLabel('Evaluation time').fill(String(at(40)));
 await run(page,'explore_stale');
 await expect(panel(page,seed.p1)).toHaveAttribute('data-state','empty');
 await expect(panel(page,seed.p1).locator('[data-result="vector-empty"]')).toBeVisible();
 await expect(panel(page,seed.p1).locator('[data-kind="nan"]')).toHaveCount(0);
});

test('a native histogram is shown bucket by bucket, and mixed float and histogram input is a visible warning',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await run(page,'explore_hist');
 const hist=panel(page,seed.p1).locator('details.histogram');
 await expect(hist.locator('summary')).toHaveText('Native histogram (float variant): count 4, sum 5.5, schema 0');
 await hist.locator('summary').click();
 await expect(hist).toContainText('count 1, threshold 0');
 await expect(hist.locator('table tbody tr')).toHaveCount(2);
 await expect(hist.locator('table tbody tr').nth(0)).toHaveText('02');
 await expect(hist.locator('table tbody tr').nth(1)).toHaveText('11');
 await run(page,'sum(explore_mixed)');
 const warning=panel(page,seed.p1).getByTestId('diagnostics').locator('[data-severity="warning"]');
 await expect(warning).toHaveCount(1);
 await expect(warning).toContainText('encountered a mix of histograms and floats');
 await expect(warning).toHaveAttribute('data-code','MixedFloatsHistogramsWarning');
 await expect(warning.locator('mark')).toHaveText('sum(explore_mixed)');
});

test('language errors are typed and located; a disabled feature is refused until it is registered and enabled; the profile is never switched',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await run(page,'sum(');
 const alert=results(page).locator('[data-state="error"]');
 await expect(alert).toHaveAttribute('data-code','language');
 await expect(alert.getByTestId('language-detail')).toHaveText('expected expression');
 await expect(alert).toContainText('Category syntax');
 await expect(alert.getByTestId('expression-range')).toContainText('characters 4 to 4');
 await expect(results(page).locator('[data-project]')).toHaveCount(0);
 await run(page,'mad_over_time(explore_gauge[1m])');
 await expect(alert.getByTestId('language-detail')).toContainText('promql-experimental-functions');
 await expect(alert).toContainText('function.feature-disabled');
 await expect(alert.getByTestId('expression-mark')).toHaveText('mad_over_time');
 await page.getByRole('checkbox',{name:'promql-experimental-functions',exact:true}).check();
 await expect(page.getByTestId('feature-set')).toContainText('179fdd6cfed03b91edcd310dd974c0547bf495d308888cbbee4d1a78a06be6e3');
 await run(page,'mad_over_time(explore_gauge[1m])');
 await expect(panel(page,seed.p1)).toHaveAttribute('data-state','ready');
 await expect(panel(page,seed.p1).locator('[data-series] [data-kind="finite"]')).toHaveCount(1);
 await expect(page.getByTestId('evaluated-with')).toContainText('179fdd6cfed03b91edcd310dd974c0547bf495d308888cbbee4d1a78a06be6e3');
 await expect(page.getByTestId('evaluated-with')).toContainText('promql-experimental-functions');
 // Selecting another pinned profile resets the features and the result says which profile answered.
 await page.getByLabel('Pinned profile').selectOption(PROM_3135);
 await expect(page.getByRole('checkbox',{name:'promql-experimental-functions',exact:true})).not.toBeChecked();
 await run(page,'1+1');
 await expect(page.getByTestId('evaluated-with')).toContainText(PROM_3135);
 await expect(page.getByTestId('evaluated-with')).not.toContainText(PROM_310);
 // LogQL: a syntax error and a gated feature, then the same gate opened.
 await page.getByRole('radio',{name:'LogQL',exact:true}).check();
 await run(page,'{app=');
 await expect(alert).toHaveAttribute('data-code','language');
 await expect(alert).toContainText('syntax.unexpected-token');
 const variants='variants(count_over_time({app="web"}[1m]),bytes_over_time({app="web"}[1m])) of ({app="web"}[1m])';
 await run(page,variants);
 await expect(alert.getByTestId('language-detail')).toHaveText('multi-variant queries are disabled');
 await page.getByRole('checkbox',{name:'multi-variant-queries',exact:true}).check();
 await run(page,variants);
 await expect(panel(page,seed.p1)).toHaveAttribute('data-state','ready');
 await expect(panel(page,seed.p1)).toContainText('__variant__');
});

test('a query over budget is a typed quota error: no panel, no shortened answer',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await page.getByRole('radio',{name:'Range over the selected window',exact:true}).check();
 await page.getByLabel('Step (seconds)').fill('10');
 await page.getByLabel('Result budget').fill('1');
 await run(page,'explore_gauge');
 const alert=results(page).locator('[data-state="error"]');
 await expect(alert).toHaveAttribute('data-code','quota');
 await expect(alert.getByTestId('fault-words')).toContainText('refused rather than shortened');
 await expect(results(page).locator('[data-project]')).toHaveCount(0);
 await expect(results(page).locator('[data-series]')).toHaveCount(0);
 await page.getByLabel('Result budget').fill('100');
 await run(page,'explore_gauge');
 await expect(panel(page,seed.p1)).toHaveAttribute('data-state','ready');
});

test('log entries keep exact nanoseconds, duplicate nanoseconds and the language order; log text is only text',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await page.getByRole('radio',{name:'LogQL',exact:true}).check();
 await page.getByLabel('Log order').selectOption('forward');
 await run(page,'{app="web"}');
 const entries=panel(page,seed.p1).locator('tr[data-entry]');
 await expect(entries).toHaveCount(6);
 const expected=['1','2','3','3','4','5'].map((n)=>String(at(0)+BigInt(n)));
 expect(await entries.evaluateAll((els)=>els.map((e)=>e.getAttribute('data-time')))).toEqual(expected);
 expect(await entries.evaluateAll((els)=>els.map((e)=>e.getAttribute('data-index')))).toEqual(['0','1','2','3','4','5']);
 // Two entries one nanosecond apart stay distinguishable; two at the same nanosecond are two rows.
 expect(expected[0]).not.toBe(expected[1]);
 expect(expected[2]).toBe(expected[3]);
 await expect(entries.nth(0)).toContainText('1730000000000000001');
 await expect(entries.nth(1)).toContainText('1730000000000000002');
 // Stream labels and structured metadata are separate cells; metadata is empty here and says so.
 await expect(entries.nth(0).locator('[data-cell="stream-labels"]')).toHaveText('{app="web"}');
 await expect(entries.nth(0).locator('[data-cell="structured-metadata"]')).toHaveText('none');
 // The canary is the template text, an allowed field value and an allowed stream label: all of it is text.
 await expect(entries.nth(0).locator('[data-line]')).toHaveText('<img src=x onerror="window.__pwn=1"> user alice signed in & <b>x</b>');
 await expect(entries.nth(4).locator('[data-line]')).toContainText('<script>window.__pwn=1</script>');
 await expect(entries.nth(5).locator('[data-cell="stream-labels"]')).toContainText('canary="<img src=x onerror=window.__pwn=2>"');
 expect(await page.locator('.log-table img, .log-table script, .log-table b').count()).toBe(0);
 expect(await page.evaluate(()=>(window as unknown as {__pwn?:number}).__pwn)).toBeUndefined();
 // An explicit page size returns exactly the first part and says that more exist.
 await page.getByLabel('Log page size').fill('2');
 await run(page,'{app="web"}');
 await expect(panel(page,seed.p1).locator('tr[data-entry]')).toHaveCount(2);
 await expect(panel(page,seed.p1).getByTestId('limit-reached')).toContainText('Log page limit reached');
 // Without a page size an over-budget log result is refused, never trimmed.
 await page.getByLabel('Log page size').fill('');
 await page.getByLabel('Result budget').fill('1');
 await run(page,'{app="web"}');
 await expect(results(page).locator('[data-state="error"]')).toHaveAttribute('data-code','quota');
 await expect(results(page).locator('tr[data-entry]')).toHaveCount(0);
 // A LogQL metric query over the same logs is a vector of two series with exact counts.
 await page.getByLabel('Result budget').fill('1000');
 await page.getByRole('radio',{name:'Instant',exact:true}).check();
 await page.getByLabel('Evaluation time').fill(String(at(10)));
 await run(page,'count_over_time({app="web"}[1m])');
 await expect(panel(page,seed.p1).locator('[data-series]')).toHaveCount(2);
 await expect(rowOf(panel(page,seed.p1),'canary=').locator('[data-kind]')).toHaveText('1');
 await expect(rowOf(panel(page,seed.p1),'{app="web"}').locator('[data-kind]')).toHaveText('5');
});

test('exemplars link to a trace only through the scope-resolved link route',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await page.getByLabel('Query expression').fill('explore_requests');
 await page.getByRole('button',{name:'Find exemplars',exact:true}).click();
 const table=page.getByTestId('exemplar-table');
 await expect(table.locator('tr[data-exemplar]')).toHaveCount(2);
 // Before the server resolves anything there is no link at all.
 await expect(page.locator('[data-link]')).toHaveCount(0);
 await expect(table.locator('a[href*="trace"]')).toHaveCount(0); // the exemplar table: the section nav now has a Traces link (05.06), which is not an exemplar link
 const real=table.locator(`tr[data-trace="${seed.trace.ingested}"]`),missing=table.locator(`tr[data-trace="${seed.trace.missing}"]`);
 await real.getByRole('button',{name:'Check trace link',exact:true}).click();
 await expect(real.locator('[data-link="available"]')).toContainText(`trace ${seed.trace.ingested}`);
 await missing.getByRole('button',{name:'Check trace link',exact:true}).click();
 await expect(missing.locator('[data-link="not-found"]')).toContainText('Not found');
 await expect(missing).not.toContainText('Trace link authorized');
 await expect(real.locator('td').nth(0)).toContainText('5');
 await expect(missing.locator('td').nth(0)).toContainText('6');
});

test('discovery pages are exact: every name once, the cursor is bound to its parameters',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 await page.getByLabel('Kind').selectOption('metric_names');
 await page.getByLabel('Page size (1 to 1000)').fill('4');
 await page.getByRole('button',{name:'List names',exact:true}).click();
 const items=page.getByTestId('discovery-items').locator('li code');
 await expect(items).toHaveCount(4);
 const more=page.getByRole('button',{name:/Load the next page/});
 for(let guard=0;guard<6&&await more.count()>0;guard++){const before=await items.count();await more.click();await expect(items).not.toHaveCount(before);}
 await expect(items).toHaveText(['explore_gauge','explore_hist','explore_inf','explore_mixed','explore_nan','explore_neginf','explore_negzero','explore_requests','explore_shared','explore_stale']);
 await expect(more).toHaveCount(0);
 // Changing a parameter forgets the list and its cursor.
 await page.getByLabel('Kind').selectOption('label_values');
 await expect(page.getByTestId('discovery-items')).toHaveCount(0);
 await page.getByLabel('Label name (for label values)').fill('job');
 await page.getByRole('button',{name:'List names',exact:true}).click();
 await expect(items).toHaveText(['api']);
 // An item can be inserted into the query as text.
 await page.getByLabel('Query expression').fill('up{job=');
 await page.getByRole('button',{name:'Insert into the query'}).click();
 await expect(page.getByLabel('Query expression')).toHaveValue('up{job="api"');
});

test('a slower older response never paints after a newer query: abort plus latest-only in the real page',async()=>{
 const page=await open();
 await only(page,seed.p1,[seed.p2]);
 let heldRelease=():void=>{};
 const barrier=new Promise<void>((r)=>{heldRelease=r;});
 let held=0;
 await page.route('**/api/v1/query',async(route)=>{
  const body=route.request().postDataJSON() as {expression:string};
  if(body.expression!=='explore_gauge'||held>0){await route.continue();return;}
  held++;
  const real=await route.fetch();
  await barrier;
  await route.fulfill({response:real}).catch(()=>undefined);
 });
 await page.getByLabel('Query expression').fill('explore_gauge');
 await page.getByRole('button',{name:'Run query',exact:true}).click();
 await expect(results(page).locator('[data-state="loading"]')).toBeVisible();
 // Ctrl+Enter starts a newer query while the older one is still held by the network layer.
 await page.getByLabel('Query expression').fill('explore_shared');
 await page.getByLabel('Query expression').press('Control+Enter');
 await expect(rowOf(panel(page,seed.p1),'explore_shared')).toBeVisible();
 heldRelease();
 await page.waitForTimeout(1500);
 await expect(panel(page,seed.p1).locator('[data-series]')).toHaveCount(1);
 await expect(rowOf(panel(page,seed.p1),'explore_shared')).toBeVisible();
 await expect(results(page)).not.toContainText('explore_gauge');
 await expect(results(page).locator('[data-kind]')).toHaveText(['1']);
});

test('a denied project and a missing organization are the same Not found, and nothing else is learned',async()=>{
 const foreignProject=id(),foreignOrg=id();
 const texts:string[]=[];
 for(const [org,projects] of [[seed.org,[foreignProject]],[foreignOrg,[seed.p1]],[seed.org,[seed.p1,foreignProject]]] as const){
  const page=await open([...projects],org);
  await run(page,'explore_gauge');
  const state=results(page).locator('[data-state="unauthorized"]');
  await expect(state).toHaveCount(1);
  await expect(state).toContainText('Not found');
  await expect(results(page).locator('[data-project], [data-series]')).toHaveCount(0);
  texts.push((await state.innerText()).replace(/Request [0-9a-f]{32}\./,'').trim());
  await page.close();
 }
 expect(new Set(texts).size).toBe(1);
 expect(texts[0]).toBe('Not found This selection was not found or is not available to this account.');
});

test('the query text lives only in the page: POST bodies to this origin, no URL, storage, cookie or polling',async()=>{
 const page=await open();
 const secret='explore_gauge{job="api"} # canary-query-text';
 const urls:string[]=[],posts:Request[]=[];
 page.on('request',(r)=>{urls.push(r.url());if(r.method()==='POST'&&r.url().endsWith('/api/v1/query'))posts.push(r);});
 await page.getByLabel('Query expression').fill('explore_gauge{job="api"} # canary-query-text');
 await page.getByRole('button',{name:'Run query',exact:true}).click();
 await settled(page);
 await page.waitForTimeout(3000);
 expect(posts).toHaveLength(1);
 expect(urls.every((u)=>u.startsWith(origin))).toBe(true);
 expect(urls.filter((u)=>u.includes('canary-query-text')||u.includes('explore_gauge')||u.includes(encodeURIComponent('explore_gauge')))).toEqual([]);
 expect(page.url()).not.toMatch(/explore_gauge|canary-query-text|expression|csrf|token/i);
 expect((posts[0]!.postDataJSON() as {expression:string}).expression).toBe(secret);
 expect(await page.evaluate(()=>({local:Object.keys(localStorage),session:Object.keys(sessionStorage),cookie:document.cookie}))).toEqual({local:[],session:[],cookie:''});
 await expect(results(page)).toContainText('48');
});

test('partial results are requested only after an explicit opt-in',async()=>{
 const page=await open();
 const bodies:{allow_partial:boolean;profile:string;feature_set:string;projects:string[]}[]=[];
 page.on('request',(r)=>{if(r.method()==='POST'&&r.url().endsWith('/api/v1/query'))bodies.push(r.postDataJSON() as (typeof bodies)[number]);});
 await run(page,'1+1');
 await page.getByLabel('Allow partial results').check();
 await run(page,'1+1');
 expect(bodies.map((b)=>b.allow_partial)).toEqual([false,true]);
 expect(new Set(bodies.map((b)=>b.profile))).toEqual(new Set([PROM_310]));
 expect(bodies[0]!.projects).toEqual([seed.p1,seed.p2]);
});

test('saved views are an explicit not-available state and nothing is stored in the browser',async()=>{
 const page=await open();
 const saved=page.locator('[data-section="saved-views"]');
 await expect(saved).toContainText('Not available');
 await expect(saved.locator('[data-state="unsupported"]')).toBeVisible();
 await expect(saved).toContainText('Nothing is saved, in this browser or on the server');
 await run(page,'explore_gauge');
 expect(await page.evaluate(()=>({local:Object.keys(localStorage).length,session:Object.keys(sessionStorage).length}))).toEqual({local:0,session:0});
});

test('an export completes, downloads the exact records, and an export revoked before download yields no bytes',async({browser})=>{
 test.setTimeout(240_000);
 const reader=await createReader(owners,seed.org,[seed.p1]);
 const rctx=await browser.newContext();
 const page=await rctx.newPage();
 await login(page,reader.email,reader.password);
 await page.goto(`/${hashFor(seed.org,[seed.p1])}`);
 await expect(page.getByRole('heading',{name:'Explore',exact:true})).toBeVisible();
 const exportPanel=page.locator('[data-section="export"]');
 await exportPanel.getByLabel('Signal').selectOption('log');
 await exportPanel.getByRole('button',{name:'Start export',exact:true}).click();
 await expect(exportPanel.getByTestId('export-status')).toContainText('Complete:',{timeout:30_000});
 const [download]=await Promise.all([page.waitForEvent('download'),exportPanel.getByRole('button',{name:'Download the export',exact:true}).click()]);
 const path=await download.path();
 const text=readFileSync(path,'utf8');
 const lines=text.trim().split('\n').map((l)=>JSON.parse(l) as {time_ns:string;project:string;payload:{fields?:{name?:string}}});
 expect(lines).toHaveLength(6);
 expect(lines.every((l)=>l.project===seed.p1)).toBe(true);
 expect(lines.map((l)=>l.time_ns).sort()).toEqual(seed.logs.lines.map((l)=>l.at).sort());
 await expect(exportPanel.getByTestId('export-status')).toContainText(`Downloaded ${Buffer.byteLength(text)} bytes`);
 // A second export completes, then the reader is revoked: the download is refused and no file is produced.
 await exportPanel.getByRole('button',{name:'Start export',exact:true}).click();
 await expect(exportPanel.getByTestId('export-status')).toContainText('Complete:',{timeout:30_000});
 await setGrant(owners,seed.org,reader.id,seed.p1,false);
 let downloads=0;
 page.on('download',()=>{downloads++;});
 await exportPanel.getByRole('button',{name:'Download the export',exact:true}).click();
 await expect(exportPanel.getByTestId('export-not-found')).toContainText('Not found');
 await page.waitForTimeout(1500);
 expect(downloads).toBe(0);
 // The revoked reader sees nothing of this scope any more.
 await page.getByLabel('Query expression').fill('explore_gauge');
 await page.getByRole('button',{name:'Run query',exact:true}).click();
 await expect(page.locator('[data-testid="results"] [data-state="unauthorized"]')).toContainText('Not found');
 await rctx.close();
});
