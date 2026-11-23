// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type APIRequestContext,type BrowserContext,type Locator,type Page} from '@playwright/test';
import {adminCommand,at,createOrg,createProject,createReader,id,ingestError,ingestJobAttempt,login,onboardErrorSource,onboardJobSource,owner,spanId,type Reader} from './support/real';
import {NATIVE_PROFILE,onboardReplaySource,seedProfiles,seedReplays,setPermissions} from './support/replay';
import {ANCHOR,domain,ingestSpanLoss,ingestTrace,onboardSpanSource,seedTraces,type TraceSeed} from './support/trace';
// Real server, real Chrome. Every span below was admitted through the real ingest route with a real source credential and is
// read back through the real POST /api/v1/traces/view route (the real storage scan) by a real reader holding telemetry.read
// on one project. Nothing here fakes a server answer. The committed ingest refuses an end in another clock domain, an end
// before its start and an open span that is not cancelled/incomplete, so those shapes are covered by the Go unit tests only.
test.describe.configure({mode:'serial'});
let ctx:BrowserContext,owners:Page,api:APIRequestContext,org:string,p1:string,p2:string,reader:Reader,seed:TraceSeed;

const hashFor=(trace:string,project=p1,start=at(0),end=at(70)):string=>`#${new URLSearchParams({org,projects:project,start:String(start),end:String(end)  ,tz:'UTC',view:'traces',target:`${project}:${trace}`})}`;
async function open(trace:string,project=p1,start=at(0),end=at(70)):Promise<Page>{
 const page=await ctx.newPage();
 await page.goto(`/${hashFor(trace,project,start,end)}`);
 await expect(page.getByRole('heading',{name:/^Trace /})).toBeVisible();
 await expect(page.locator('[data-state="loading"]')).toHaveCount(0);
 return page;
}
const path=(page:Page):Locator=>page.getByTestId('critical-path');
const limits=(page:Page):Locator=>page.getByTestId('limits');
const rowIds=(page:Page):Promise<(string|null)[]>=>page.locator('table.path-table tbody tr').evaluateAll((rows)=>rows.map((r)=>r.getAttribute('data-span')));
const ms=(n:number):bigint=>BigInt(n)*1_000_000n;

test.beforeAll(async({browser})=>{
 test.setTimeout(240_000);
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 api=await pwRequest.newContext();
 org=await createOrg(owners,'critical path e2e org');
 p1=await createProject(owners,org,'trace P1');p2=await createProject(owners,org,'trace P2');
 reader=await createReader(owners,org,[p1]); // telemetry.read on P1 only
 const source=await onboardSpanSource(owners,org,p1);
 seed=await seedTraces(api,source);
 ctx=await browser.newContext();
 const page=await ctx.newPage();
 await login(page,reader.email,reader.password);
 await page.close();
});
test.afterEach(async()=>{for(const p of ctx.pages())await p.close();});

test('frontend to API to PostgreSQL with overlapping work: the path follows the longest branch and the duration is exact, not a sum',async()=>{
 const page=await open(seed.clean.trace);
 await expect(page.getByTestId('observed-duration')).toHaveText('Observed duration of this trace: exactly 100 ms.');
 expect(await rowIds(page)).toEqual([seed.clean.frontend,seed.clean.api,seed.clean.query]);
 const row=(id:string):Locator=>path(page).locator(`tr[data-span="${id}"]`);
 await expect(row(seed.clean.api)).toContainText('exactly 30 ms'); // 90 ms minus the 60 ms query branch, not minus 90 ms of both branches
 await expect(row(seed.clean.frontend)).toContainText('exactly 10 ms');
 await expect(row(seed.clean.query)).toContainText('dependency boundary: internals not captured');
 await expect(row(seed.clean.api)).toContainText('1 sibling ran in parallel or could not be ordered, off the path');
 // The 30 ms cache call ran in parallel: listed as off-path work, never added to the path.
 await expect(page.getByTestId('off-path').locator(`li[data-span="${seed.clean.cache}"]`)).toContainText('op.cache');
 await expect(page.getByTestId('path-counts')).toContainText('4 spans were read. 3 are on a critical path; 1 is off every path');
 await expect(page.getByText('110 ms')).toHaveCount(0);
 // Dependency calls end at the boundary: stated as a visibility limit, with a count.
 await expect(limits(page).locator('[data-limit="dependency_boundary"]')).toContainText('2 dependency calls end at the dependency boundary');
 await expect(limits(page).locator('[data-limit="unlike_clock_domains"]')).toContainText('never subtracted');
 await expect(limits(page).locator('[data-limit="none_reported"]')).toHaveCount(0);
});

test('selecting a span shows its recorded details as text, moves focus to them, and links to the Logs and Metrics windows of that span',async()=>{
 const page=await open(seed.clean.trace);
 const api=path(page).getByRole('button',{name:'Show details of span op.api, server, level 2'});
 await api.focus();
 await page.keyboard.press('Enter');
 const details=page.getByTestId('span-details');
 await expect(details.getByRole('heading',{name:'Selected span'})).toBeFocused();
 await expect(details).toContainText('op.api');
 await expect(details).toContainText(seed.clean.api);
 await expect(details).toContainText('exactly 90 ms');
 await expect(path(page).locator(`tr[data-span="${seed.clean.api}"]`)).toHaveAttribute('aria-selected','true');
 await expect(api).toHaveAttribute('aria-pressed','true');
 const link=details.getByRole('link',{name:'Logs in the window of this span'});
 const target=new URLSearchParams((await link.getAttribute('href'))!.slice(1));
 expect(BigInt(target.get('start')!)).toBe(ANCHOR+ms(5)-1_000_000_000n);
 expect(BigInt(target.get('end')!)).toBe(ANCHOR+ms(95)+1_000_000_001n);
 expect(target.get('view')).toBe('logs');
 const metricsLink=new URLSearchParams(((await details.getByRole('link',{name:'Metrics in the window of this span'}).getAttribute('href'))!).slice(1));
 expect(metricsLink.get('view')).toBe('metrics');
 expect(metricsLink.get('start')).toBe(target.get('start'));
 await link.click();
 await expect(page.getByRole('heading',{level:1,name:'Logs',exact:true})).toBeVisible();
});

test('gateway to dependency: the dependency boundary is stated, and an asynchronous job link never extends the request',async()=>{
 const page=await open(seed.gateway.trace);
 await expect(page.getByTestId('observed-duration')).toContainText('exactly 50 ms');
 expect(await rowIds(page)).toEqual([seed.gateway.gateway,seed.gateway.dependency]);
 await expect(limits(page).locator('[data-limit="dependency_boundary"]')).toContainText('1 dependency call ends at the dependency boundary');
 await page.close();
 const job=await open(seed.gateway.job.trace);
 await expect(job.getByTestId('observed-duration')).toContainText('exactly 100 ms');
 await expect(limits(job).locator('[data-limit="link_foreign_trace"]')).toContainText('a span of another trace');
 await job.getByRole('button',{name:'Show details of span op.job, consumer, level 1'}).click();
 const detail=job.getByTestId('span-details');
 await expect(detail).toContainText(`${seed.gateway.gateway} in trace ${seed.gateway.trace}`);
 await expect(detail).toContainText('asynchronous reference, not part of the duration');
});

test('cross-host clock skew is reported as uncertainty and never reorders causality or creates a negative duration',async()=>{
 const page=await open(seed.skew.trace);
 expect(await rowIds(page)).toEqual([seed.skew.root,seed.skew.child]); // the parent edge decides, not wall-clock time
 await expect(limits(page).locator('[data-limit="clock_uncertain"]')).toContainText('never reorders cause and effect');
 await expect(limits(page).locator('[data-limit="unlike_clock_domains"]')).toContainText('10 ms');
 await expect(limits(page).locator('[data-limit="clock_violation"]')).toHaveCount(0);
 await expect(path(page).locator(`tr[data-span="${seed.skew.child}"]`)).toContainText('exactly 55 ms'); // its own domain's monotonic elapsed time
 await expect(path(page).locator(`tr[data-span="${seed.skew.root}"]`)).toContainText('exactly 45 ms');
 await path(page).getByRole('button',{name:'Show details of span op.skewed, server, level 2'}).click();
 await expect(page.getByTestId('span-details')).toContainText('starts before its parent: may be clock skew within 10 ms (unlike clock domains)');
 await expect(path(page)).not.toContainText(/-\d/); // no negative duration anywhere
});

test('a missing parent, an orphan and a second root: separate trees, duration only as bounds',async()=>{
 const page=await open(seed.broken.trace);
 await expect(page.getByTestId('observed-duration')).toContainText('between 100 ms and 130 ms');
 await expect(page.getByTestId('observed-duration')).toContainText('no single total is shown');
 await expect(limits(page).locator('[data-limit="missing_parent"]')).toContainText('1 span names a parent that is not in the data');
 await expect(limits(page).locator('[data-limit="multiple_roots"]')).toContainText('2 spans have no parent');
 await expect(path(page).locator('table.path-table')).toHaveCount(3);
 await expect(path(page).locator('table[data-orphan="yes"] caption')).toContainText('Orphan tree 3: its parent is missing or ambiguous, so it is not part of the root');
 await expect(path(page).locator('table[data-orphan="no"]').first().locator(`tr[data-span="${seed.broken.root}"]`)).toContainText('exactly 100 ms');
});

test('a parent cycle is corrupt data, excluded from every path, and the page stays responsive',async()=>{
 const page=await open(seed.cycle.trace);
 await expect(limits(page).locator('[data-limit="cycle"]')).toContainText('2 spans in a cycle');
 await expect(limits(page).locator('[data-limit="cycle"]')).toContainText('excluded from every path');
 expect(await rowIds(page)).toEqual([seed.cycle.root]);
 await expect(page.getByTestId('observed-duration')).toContainText('exactly 100 ms');
 await expect(path(page).locator('table.path-table')).not.toContainText('op.cycle');
 await expect(page.getByTestId('off-path').locator('li')).toHaveCount(2);
 await expect(page.getByTestId('off-path')).toContainText('in a parent cycle');
});

test('a span ID recorded twice is excluded from the path and listed with its limit',async()=>{
 const page=await open(seed.dup.trace);
 await expect(limits(page).locator('[data-limit="duplicate_span_id"]')).toContainText('Every copy is excluded from the causal path');
 expect(await rowIds(page)).toEqual([seed.dup.root]);
 await expect(page.getByTestId('off-path').locator('li')).toHaveCount(2);
});

test('head sampling is stated in words with the lowest probability',async()=>{
 const page=await open(seed.sampled.trace);
 await expect(limits(page).locator('[data-limit="head_sampled"]')).toContainText('lowest probability 0.25');
 await expect(limits(page).locator('[data-limit="head_sampled"]')).toContainText('only part of the work');
});

test('outside the scope or the window: a project the reader does not hold is the one "Not found"; an empty window says it proves nothing',async()=>{
 const denied=await open(seed.clean.trace,p2);
 await expect(denied.locator('.status')).toHaveAttribute('data-state','unauthorized');
 await expect(denied.locator('.status')).toContainText('Not found');
 await expect(denied.getByTestId('critical-path')).toHaveCount(0);
 const guessed=await open(seed.clean.trace,'e'.repeat(32));
 const words=async(p:Page):Promise<string>=>(await p.locator('.status').innerText()).replace(/\s*Request\s+\S+\.?/,'').trim();
 expect(await words(guessed)).toBe(await words(denied)); // a held project and a guessed one are indistinguishable
 await guessed.close();await denied.close();
 const late=await open(seed.clean.trace,p1,at(200),at(260));
 await expect(late.locator('.status')).toHaveAttribute('data-state','empty');
 await expect(late.getByTestId('critical-path')).toHaveCount(0);
 await expect(late.getByText('not proof that the trace does not exist')).toBeVisible();
 const unknown=await open(seed.absent);
 await expect(unknown.locator('.status')).toHaveAttribute('data-state','empty');
});

test('a span reported long after it ended and a loss its producer reported are limits of the trace, in words, never repairs',async()=>{
 test.setTimeout(120_000);
 // A second source of its own: a loss record is attributed to the producers that sent a span of the trace, so the other traces stay untouched.
 const source=await onboardSpanSource(owners,org,p1,true);
 const d=domain();
 const late={trace:id(),root:spanId(),child:spanId()};
 await ingestTrace(api,source,late.trace,[
  {span:late.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d},
  {span:late.child,parent:late.root,kind:'internal',operation:'op.api',startMs:10,endMs:60,observedMs:30_060,domain:d},
 ]);
 const lossy={trace:id(),root:spanId()};
 await ingestTrace(api,source,lossy.trace,[{span:lossy.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d}]);
 await ingestSpanLoss(api,source,{startMs:20,endMs:30,reason:'transport',count:5});

 const page=await open(late.trace);
 await expect(limits(page).locator('[data-limit="late_spans"]')).toContainText('1 span was reported more than five seconds after it ended (the latest by 30 s)');
 await expect(page.getByTestId('late-spans')).toContainText('30000000000 ns later.');
 expect(await rowIds(page)).toEqual([late.root,late.child]); // the late span stays on the path exactly as recorded
 await expect(path(page).locator(`tr[data-span="${late.child}"]`)).toContainText('exactly 50 ms');
 await expect(path(page).locator(`tr[data-span="${late.child}"]`)).toContainText('reported more than five seconds after it ended');
 await path(page).getByRole('button',{name:'Show details of span op.api, internal, level 2'}).click();
 await expect(page.getByTestId('span-details')).toContainText('Reported by its producer');
 await expect(page.getByTestId('span-details')).toContainText('(late)');
 // The producer's own loss record covers this trace's time (and only for the producers that sent it a span).
 const lost=await open(lossy.trace);
 await expect(lost.getByTestId('producer-gaps')).toContainText(`5 spans lost by producer ${source.producer} of source ${source.id}`);
 await expect(lost.getByTestId('producer-gaps')).toContainText('reason transport.');
 await expect(limits(lost).locator('[data-limit="producer_loss"]')).toContainText('5 spans never reached storage');
 await expect(limits(lost).locator('[data-limit="producer_loss"]')).toContainText('spans may be missing from this trace');
 await expect(limits(lost).locator('[data-limit="none_reported"]')).toHaveCount(0);
 await expect(lost.getByTestId('late-spans')).toHaveCount(0);
 // The same producer's loss is a gap on its late trace too (its time overlaps), but a trace of the first source shows none.
 await expect(page.getByTestId('producer-gaps')).toContainText('5 spans lost');
 const clean=await open(seed.clean.trace);
 await expect(clean.getByTestId('producer-gaps')).toHaveCount(0);
 await expect(clean.getByTestId('late-spans')).toHaveCount(0);
});

test('a selected span links to its job, replay, profile and error through the server\'s authorized resolution: an anchor opens the target, one outside the reader\'s grants is one generic sentence',async({browser})=>{
 test.setTimeout(240_000);
 // Real records of every kind, each admitted through the real ingest route by a source of its own.
 const spans=await onboardSpanSource(owners,org,p1);
 const jobs=await onboardJobSource(owners,org,p1);
 const errors=await onboardErrorSource(owners,org,p1);
 const replaySource=await onboardReplaySource(owners,org,p1);
 const replays=await seedReplays(api,replaySource);
 await seedProfiles(api,replaySource);
 const job=id(),neverRecorded=id();
 const recent=String(BigInt(Date.now()-120_000)*1_000_000n);
 await ingestJobAttempt(api,jobs,{job,run:id(),attempt:id(),occurrence:'trace-link-1',ordinal:1,epoch:id(),sequence:1,state:'succeeded',observed:recent,terminal:recent});
 const d=domain();
 const t={trace:id(),root:spanId(),child:spanId(),third:spanId()};
 await ingestTrace(api,spans,t.trace,[
  {span:t.root,kind:'server',operation:'op.frontend',startMs:0,endMs:100,domain:d,job},
  {span:t.child,parent:t.root,kind:'internal',operation:'op.api',startMs:10,endMs:60,domain:d,replay:replays.clean.replay,profile:NATIVE_PROFILE},
  {span:t.third,parent:t.child,kind:'internal',operation:'op.query',startMs:20,endMs:50,domain:d,job:neverRecorded}, // the only branch: it is on the path, so its button exists
 ]);
 const occurrence=await ingestError(api,errors,{at:at(20),trace:t.trace,span:t.child});
 const selectSpan=async(page:Page,name:string):Promise<Locator>=>{
  await path(page).getByRole('button',{name}).click();
  return page.getByTestId('span-details');
 };
 const target=(details:Locator,kind:string,available:'yes'|'no'):Locator=>details.locator(`[data-target-kind="${kind}"][data-target-available="${available}"]`);

 // A reader that holds telemetry.read only: the job and the error are theirs to read, the replay and the profile need their own grants.
 const page=await open(t.trace);
 let details=await selectSpan(page,'Show details of span op.api, internal, level 2');
 await expect(target(details,'error','yes')).toContainText(occurrence);
 // The occurrence is grouped into an issue by the background producer: once it is, the occurrence is an anchor to that issue, which checks the scope again.
 const openIssue=details.getByRole('link',{name:'Open the issue holding this occurrence'});
 await expect(async()=>{
  await page.reload();
  details=await selectSpan(page,'Show details of span op.api, internal, level 2');
  await expect(openIssue).toBeVisible({timeout:2_000});
 }).toPass({timeout:90_000});
 await openIssue.click();
 await expect(page).toHaveURL(new RegExp(`view=issues&target=${p1}%3A[0-9a-f]{32}`));
 const issueHeading=page.locator('h1[data-issue]');
 await expect(issueHeading).toBeVisible();
 await expect(issueHeading).toHaveAttribute('data-issue',/^[0-9a-f]{32}$/);
 // Persisted issue evidence is a project reader's read (D92, under the caller's own scope; the issue view takes no time window: it lists every stored occurrence): a reader holding telemetry.read only lands on the issue and reads the occurrence the span names.
 await expect(page.locator(`tr[data-occurrence="${occurrence}"]`)).toBeVisible();
 await expect(page.locator('tr[data-occurrence]')).toHaveCount(1);
 await expect(page.getByText('can only be read by an organization administrator')).toHaveCount(0);
 await page.goBack();
 details=await selectSpan(page,'Show details of span op.api, internal, level 2');
 await expect(target(details,'replay','no')).toContainText('not available to this account.');
 await expect(target(details,'profile','no')).toContainText('not available to this account.');
 await expect(details.getByRole('link',{name:/^Open this (replay|profile)$/})).toHaveCount(0);
 // A job nothing recorded is the same sentence as a target the reader may not read.
 details=await selectSpan(page,'Show details of span op.query, internal, level 3');
 await expect(target(details,'job','no')).toContainText('not available to this account.');
 await expect(details.getByRole('link',{name:'Open this job'})).toHaveCount(0);
 // The job of the root opens in the Jobs view, which checks the scope again.
 details=await selectSpan(page,'Show details of span op.frontend, server, level 1');
 await expect(target(details,'job','yes')).toContainText('Access is checked again when it opens.');
 await details.getByRole('link',{name:'Open this job'}).click();
 await expect(page.getByTestId('job-heading')).toHaveAttribute('data-job',job);
 await expect(page.locator(`h1[data-job="${job}"]`)).toBeVisible();
 await page.close();

 // A reader that also holds replay.read and profiles.read: the same references resolve, and each opens in its own view.
 const rich=await createReader(owners,org,[p1]);
 await setPermissions(owners,org,rich.id,p1,true,['telemetry.read','replay.read','profiles.read']);
 const rctx=await browser.newContext();
 const rp=await rctx.newPage();
 await login(rp,rich.email,rich.password);
 await rp.goto(`/${hashFor(t.trace)}`);
 await expect(rp.getByRole('heading',{name:/^Trace /})).toBeVisible();
 details=await selectSpan(rp,'Show details of span op.api, internal, level 2');
 await expect(target(details,'replay','yes')).toContainText(replays.clean.replay);
 await expect(target(details,'profile','yes')).toContainText(NATIVE_PROFILE);
 await details.getByRole('link',{name:'Open this replay'}).click();
 await expect(rp).toHaveURL(new RegExp(`view=replays&target=${p1}%3A${replays.clean.replay}`));
 await expect(rp.getByRole('heading',{name:/^Replay/i}).first()).toBeVisible();
 await rp.goBack();
 await expect(rp.getByRole('heading',{name:/^Trace /})).toBeVisible();
 details=await selectSpan(rp,'Show details of span op.api, internal, level 2');
 await details.getByRole('link',{name:'Open this profile'}).click();
 await expect(rp).toHaveURL(new RegExp(`view=profiles&target=${p1}%3A${NATIVE_PROFILE}`));
 // The same link, followed by an organization administrator who also holds telemetry.read, lists the very occurrence the span names.
 await adminCommand(owners,org,'org_admin',{user_id:rich.id,enabled:true});
 await rp.goto(`/${hashFor(t.trace)}`);
 await expect(rp.getByRole('heading',{name:/^Trace /})).toBeVisible();
 details=await selectSpan(rp,'Show details of span op.api, internal, level 2');
 await details.getByRole('link',{name:'Open the issue holding this occurrence'}).click();
 await expect(rp).toHaveURL(new RegExp(`view=issues&target=${p1}%3A[0-9a-f]{32}`));
 await expect(rp.locator(`[data-section="occurrences"] tr[data-occurrence="${occurrence}"]`)).toBeVisible();
 await expect(rp.locator('[data-section="occurrences"] tr[data-occurrence]')).toHaveCount(1);
 await rctx.close();
});
