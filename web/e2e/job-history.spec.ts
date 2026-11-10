// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect,type Browser,type BrowserContext,type Page} from '@playwright/test';
import {adminCommand,createOrg,createProject,createReader,field,id,login,owner,postJson,setGrant,type Reader} from './support/real';

// Real server, real Chrome, real HTTPS, real sessions and the real POST /api/v1/jobs/list and /api/v1/jobs/view routes reading the
// committed DURABLE control job books. What this proves and what it does NOT:
//  - PROVEN: the READ path (handlers, scope, reducer verdicts, browser rendering) over real durable job state that was committed through the
//    committed jobs.Service (ApplyAttempt, ObserveSchedule, Correct), including attempt start -> failure -> retry -> success, the next
//    schedule, a late old completion, cancellation, an observer outage, DST fold and skipped local times, overlap and a correction.
//  - NOT PROVEN: the SDK-to-backend path. No committed worker turns ingested job_attempt records into job books (grep: nothing outside
//    internal/jobs calls ApplyAttempt/ObserveSchedule), so this spec seeds through an E2E-ONLY seed route (POST /e2e/jobs/seed, wired
//    temporarily in a checkout, NEVER committed) that calls the same committed service methods as a journal worker would and lets the test
//    set the service clock. Without that route (SOUNDPOST_E2E_JOB_SEED unset) the whole file is skipped and says why.
// The brief's `--headed` smoke (real scheduler/retry fixture with an interrupted exporter) cannot run in this headless environment.
const SEED=process.env.SOUNDPOST_E2E_JOB_SEED;
test.skip(SEED!=='1','needs the e2e-only job seed route (SOUNDPOST_E2E_JOB_SEED=1): no committed production path writes job books from SDK attempts');
test.describe.configure({mode:'serial'});

let br:Browser,rctx:BrowserContext,owners:Page,writer:Page,org:string,p1:string,reader:Reader,writerUser:string;

const ns=(iso:string):string=>String(BigInt(Date.parse(iso))*1_000_000n);
const WINDOW={start:'1',end:'1800000000000000000'};
const hash=(o:string,p:string,view='jobs'):string=>`#${new URLSearchParams({org:o,projects:p,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view})}`;
type Op=Record<string,unknown>;
const clock=(iso:string):Op=>({op:'clock',at_ns:ns(iso)});
const def=(schedule:{cron:string;timezone:string}|null,from:string):Record<string,unknown>=>({revision:'1',effective_from_ns:ns(from),...(schedule?{schedule}:{}),grace_ns:'0',max_runtime_ns:'0',observer_stale_after_ns:'0',overlap:'allow'});
const observe=(job:string,observed:string,complete:string,definition:Record<string,unknown>|null,healthy=true):Op=>({op:'observe',job,observer:'07'.repeat(16),observed_ns:ns(observed),complete_through_ns:ns(complete),healthy,...(definition?{definition}:{})});
const attempt=(o:{job:string;run:string;attempt:string;schedule?:string;occurrence?:{timezone:string;at_ns:string;fold:number};ordinal:number;sequence:number;state:'started'|'failed'|'succeeded'|'cancelled';observed:string;terminal?:string;cause_trace?:string;cause_error?:string}):Op=>({op:'attempt',job:o.job,run:o.run,attempt:o.attempt,...(o.schedule?{schedule:o.schedule}:{}),...(o.occurrence?{occurrence:o.occurrence}:{}),ordinal:String(o.ordinal),sequence:String(o.sequence),state:o.state,observed_ns:ns(o.observed),...(o.terminal?{terminal_ns:ns(o.terminal)}:{}),...(o.cause_trace?{cause_trace:o.cause_trace}:{}),...(o.cause_error?{cause_error:o.cause_error}:{})});
const occ=(timezone:string,iso:string,fold=0)=>({timezone,at_ns:ns(iso),fold});

async function seed(ops:Op[]):Promise<string[]>{
 const r=await postJson(writer,'/e2e/jobs/seed',{org,project:p1,ops});
 if(r.status!==200)throw Error(`seed: HTTP ${r.status} ${r.text}`);
 return field(r.json,'outcomes') as string[];
}
async function open(who:Page,view='jobs'):Promise<void>{
 await who.goto(`/${hash(org,p1,view)}`);
 await expect(who.getByRole('heading',{name:'Jobs',exact:true})).toBeVisible();
}
const row=(page:Page,job:string)=>page.locator(`[data-testid=job-row][data-job="${job}"]`);
const run=(page:Page,r:string)=>page.locator(`[data-testid=run-row][data-run="${r}"]`);
async function openJob(page:Page,job:string):Promise<void>{
 await row(page,job).getByRole('button',{name:`Open job ${job}`}).click();
 await expect(page.getByRole('heading',{name:`Job ${job}`})).toBeVisible();
}
async function loggedIn(who:Reader):Promise<Page>{
 const c=await br.newContext();
 const page=await c.newPage();
 await login(page,who.email,who.password);
 return page;
}

test.beforeAll(async({browser})=>{
 test.setTimeout(240_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 org=await createOrg(owners,'job history e2e org');
 p1=await createProject(owners,org,'jobs P1');
 reader=await createReader(owners,org,[p1]);
 // The seeding principal needs both grants: policy.write to commit evidence, telemetry.read to read the version it corrects.
 const w:Reader={id:id(),email:`writer-${id().slice(0,8)}@example.test`,password:`job writer password ${id().slice(0,8)}`};
 await adminCommand(owners,org,'create_user',{id:w.id,email:w.email,password:w.password});
 await adminCommand(owners,org,'membership',{user_id:w.id,enabled:true});
 await adminCommand(owners,org,'grant',{user_id:w.id,project_id:p1,enabled:true,permissions:['policy.write','telemetry.read']});
 writerUser=w.id;
 writer=await (await browser.newContext()).newPage();
 await login(writer,w.email,w.password);
 rctx=await browser.newContext();
 const page=await rctx.newPage();
 await login(page,reader.email,reader.password);
 await page.close();
});
test.afterEach(async()=>{for(const p of rctx.pages())await p.close();});

const A={job:id(),run0:id(),run1:id(),run2:id(),att0:id(),att1:id(),att2:id(),att3:id(),trace:id(),error:id()};

test('start, failure, retry, success, the next schedule, then a late old completion: failed history stays, recovery and health are separate, health is never overwritten',async()=>{
 const hourly=def({cron:'0 * * * *',timezone:'UTC'},'2026-11-01T00:00:00Z');
 const o0=occ('UTC','2026-11-10T09:00:00Z'),o1=occ('UTC','2026-11-10T10:00:00Z'),o2=occ('UTC','2026-11-10T11:00:00Z');
 const outcomes=await seed([
  clock('2026-11-10T11:30:00Z'),
  observe(A.job,'2026-11-10T11:30:00Z','2026-11-10T11:30:00Z',hourly),
  // occurrence 0: a long run that has only started so far
  attempt({job:A.job,run:A.run0,attempt:A.att0,occurrence:o0,ordinal:1,sequence:1,state:'started',observed:'2026-11-10T09:00:05Z'}),
  // occurrence 1: attempt 1 fails (with a cause trace and error), the retry succeeds: the RUN recovers
  attempt({job:A.job,run:A.run1,attempt:A.att1,occurrence:o1,ordinal:1,sequence:1,state:'started',observed:'2026-11-10T10:00:05Z'}),
  attempt({job:A.job,run:A.run1,attempt:A.att1,occurrence:o1,ordinal:1,sequence:2,state:'failed',observed:'2026-11-10T10:00:05Z',terminal:'2026-11-10T10:00:15Z',cause_trace:A.trace,cause_error:A.error}),
  attempt({job:A.job,run:A.run1,attempt:A.att2,occurrence:o1,ordinal:2,sequence:1,state:'started',observed:'2026-11-10T10:01:00Z'}),
  attempt({job:A.job,run:A.run1,attempt:A.att2,occurrence:o1,ordinal:2,sequence:2,state:'succeeded',observed:'2026-11-10T10:01:00Z',terminal:'2026-11-10T10:01:30Z'}),
  // the next schedule succeeds
  attempt({job:A.job,run:A.run2,attempt:A.att3,occurrence:o2,ordinal:1,sequence:1,state:'started',observed:'2026-11-10T11:00:05Z'}),
  attempt({job:A.job,run:A.run2,attempt:A.att3,occurrence:o2,ordinal:1,sequence:2,state:'succeeded',observed:'2026-11-10T11:00:05Z',terminal:'2026-11-10T11:00:20Z'}),
  // redelivery of an applied (epoch, sequence) under a new journal record: counted nowhere
  attempt({job:A.job,run:A.run1,attempt:A.att1,occurrence:o1,ordinal:1,sequence:2,state:'failed',observed:'2026-11-10T10:00:05Z',terminal:'2026-11-10T10:00:15Z',cause_trace:A.trace,cause_error:A.error}),
  // the late old completion: occurrence 0's attempt fails only now, after occurrence 2 already succeeded
  attempt({job:A.job,run:A.run0,attempt:A.att0,occurrence:o0,ordinal:1,sequence:2,state:'failed',observed:'2026-11-10T09:00:05Z',terminal:'2026-11-10T11:20:00Z'}),
 ]);
 expect(outcomes.filter((x)=>x==='duplicate')).toHaveLength(1);

 const page=await rctx.newPage();
 let pwn=0;await page.exposeFunction('__jobsPwn',()=>{pwn++;});
 await open(page);
 await expect(row(page,A.job)).toContainText('Succeeded');
 await expect(row(page,A.job)).toContainText('Complete');
 await openJob(page,A.job);

 // Current job health comes from the newest occurrence and is not overwritten by the late old failure.
 const health=page.getByTestId('job-health');
 await expect(health).toContainText('Current job health: Succeeded');
 await expect(health).not.toContainText('Recovered');
 await expect(health).not.toContainText('Failed');
 await expect(page.getByTestId('job-source')).toContainText('Committed source version 9');
 await expect(page.getByTestId('job-source')).toContainText(/Origin cursor of the newest attempt evidence: e20{30}:\d+/);
 const def1=page.getByTestId('job-definition');
 await expect(def1).toContainText('UTC');
 await expect(def1).toContainText('0 * * * *');
 await expect(def1).toContainText('Grace: 5 minutes');
 await expect(def1).toContainText('allow');
 await expect(page.getByTestId('job-observer')).toContainText('Schedule observer: fresh');

 // Runs, newest first.
 const rows=page.locator('[data-testid=run-row]');
 await expect(rows).toHaveCount(3);
 await expect(rows.nth(0)).toHaveAttribute('data-run',A.run2);
 await expect(rows.nth(1)).toHaveAttribute('data-run',A.run1);
 await expect(rows.nth(2)).toHaveAttribute('data-run',A.run0);
 await expect(run(page,A.run2)).toContainText('basis of current job health');
 // Run recovery is its own label: run 1 recovered after a failed first attempt that stays counted as failed.
 await expect(run(page,A.run1)).toContainText('Run recovery: Recovered after retry');
 await expect(run(page,A.run1)).toContainText('1 failed of 2 attempts');
 await expect(run(page,A.run1)).not.toContainText('Current job health');
 // The late old failure: superseded history, status failed, never the basis of health.
 await expect(run(page,A.run0)).toContainText('Failed');
 await expect(run(page,A.run0)).toContainText('Superseded by newer occurrence');
 await expect(run(page,A.run0)).toContainText('did not change current job health');
 await expect(run(page,A.run0)).not.toContainText('basis of current job health');
 // Overlap in words: the long old run spans both later runs.
 await expect(run(page,A.run0)).toContainText('Overlaps with 2 other runs');

 // Run 1: attempt 1 stays failed and visible, with ID-only cause links; duplicates are not counted.
 await run(page,A.run1).getByRole('button',{name:`Open run ${A.run1}`}).click();
 await expect(page.getByRole('heading',{name:`Run ${A.run1}`})).toBeVisible();
 await expect(page.getByTestId('run-recovery')).toContainText('Run recovery: Recovered after retry');
 await expect(page.getByTestId('run-health-basis')).toContainText('Current job health: Succeeded');
 await expect(page.getByTestId('run-health-basis')).toContainText('is not the basis');
 const attempts=page.locator('[data-testid=attempt-row]');
 await expect(attempts).toHaveCount(2);
 await expect(attempts.nth(0)).toHaveAttribute('data-attempt',A.att1);
 await expect(attempts.nth(0)).toHaveAttribute('data-state','failed');
 await expect(attempts.nth(0)).toContainText('Attempt 1: Failed');
 await expect(attempts.nth(1)).toHaveAttribute('data-state','succeeded');
 await expect(page.getByTestId('run-dedup')).toContainText('2 distinct attempts counted');
 await expect(page.getByTestId('run-dedup')).toContainText('4 events accepted');
 const causes=page.getByTestId('cause-links');
 await expect(causes).toContainText(A.trace);
 await expect(causes).toContainText(A.error);
 await expect(causes.getByRole('link')).toHaveAttribute('href',new RegExp(`view=traces.*target=`));
 await expect(page.getByText('Cancelled',{exact:true})).toHaveCount(0);

 // Refresh keeps the selected run, the failed history and the committed source version while the new answer is pending.
 let release:()=>void=()=>{};
 const gate=new Promise<void>((resolve)=>{release=resolve;});
 await page.route('**/api/v1/jobs/view',async(route)=>{await gate;await route.continue();});
 await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.getByRole('heading',{name:`Run ${A.run1}`})).toBeVisible();
 await expect(attempts.nth(0)).toHaveAttribute('data-state','failed');
 await expect(page.getByTestId('refreshing').first()).toContainText('Refreshing');
 release();
 await expect(page.getByRole('heading',{name:`Run ${A.run1}`})).toBeVisible();
 await expect(attempts).toHaveCount(2);
 await expect(attempts.nth(0)).toHaveAttribute('data-state','failed');
 await expect(page.getByTestId('job-source')).toContainText('Committed source version 9');
 await page.unrouteAll({behavior:'wait'});

 // The late completion of occurrence 0 is shown as late and never as current health.
 await page.getByRole('button',{name:'Back to job'}).click();
 await run(page,A.run0).getByRole('button',{name:`Open run ${A.run0}`}).click();
 const late=page.locator('[data-testid=attempt-row]').first();
 await expect(late).toHaveAttribute('data-state','failed');
 await expect(late).toContainText('Completed after a newer occurrence started');
 await expect(late).toContainText('late result for an older occurrence');
 await expect(page.getByTestId('run-health-basis')).toContainText('Current job health: Succeeded');
 expect(pwn).toBe(0);
});

test('explicit cancellation is never rendered as success',async()=>{
 const J={job:id(),run:id(),att:id()};
 await seed([clock('2026-11-10T12:00:00Z'),attempt({job:J.job,run:J.run,attempt:J.att,schedule:'manual.cancelled',ordinal:1,sequence:1,state:'cancelled',observed:'2026-11-10T11:59:00Z',terminal:'2026-11-10T11:59:30Z'})]);
 const page=await rctx.newPage();
 await open(page);
 await expect(row(page,J.job)).toContainText('Cancelled');
 await expect(row(page,J.job)).not.toContainText('Succeeded');
 await openJob(page,J.job);
 await expect(page.getByTestId('job-health')).toContainText('Current job health: Cancelled');
 await expect(page.getByTestId('job-health')).not.toContainText('Succeeded');
 await run(page,J.run).getByRole('button',{name:`Open run ${J.run}`}).click();
 const a=page.locator('[data-testid=attempt-row]');
 await expect(a).toHaveAttribute('data-state','cancelled');
 await expect(a).toContainText('Attempt 1: Cancelled');
 await expect(a).not.toContainText('Succeeded');
 await expect(page.getByTestId('run-recovery')).not.toContainText('Recovered');
});

test('missed needs external observer evidence; an outage and missing records read unknown, never recovered or missed by assumption',async()=>{
 const hourly=def({cron:'0 * * * *',timezone:'UTC'},'2026-11-01T00:00:00Z');
 const C=id(),D=id();
 await seed([
  clock('2026-11-10T12:30:00Z'),
  // C: the observer is healthy, fresh and attests the data path complete through now; no run reached it: missed WITH observer evidence.
  observe(C,'2026-11-10T12:30:00Z','2026-11-10T12:30:00Z',hourly),
  // D: the observer is fresh but the data path has been down for three hours: absence cannot be proven.
  observe(D,'2026-11-10T12:30:00Z','2026-11-10T09:30:00Z',hourly),
 ]);
 const page=await rctx.newPage();
 await open(page);
 await expect(row(page,C)).toContainText('Missed (external schedule observer evidence)');
 await expect(row(page,D)).toContainText('Unknown');
 await expect(row(page,D)).not.toContainText('Missed');
 await expect(row(page,D)).not.toContainText('Succeeded');
 await expect(row(page,D)).toContainText('Incomplete evidence');
 await openJob(page,D);
 await expect(page.getByTestId('job-health')).toContainText('Current job health: Unknown');
 await expect(page.getByTestId('job-health')).not.toContainText('Missed');
 await expect(page.getByTestId('job-observer')).toContainText('Schedule observer: fresh');
 await expect(page.getByTestId('job-observer')).toContainText('recovered or missed by assumption');
 await expect(page.locator('[data-testid=run-row]')).toHaveCount(0);
 await openJob(page,C);
 await expect(page.getByTestId('job-health')).toContainText('Current job health: Missed');
 await expect(page.getByTestId('job-observer')).toContainText('external');
});

test('a repeated local time (clock moved back) is a separate second occurrence, in words',async()=>{
 const E={job:id(),a:id(),b:id(),att1:id(),att2:id()};
 const ny='America/New_York';
 await seed([
  clock('2026-11-01T08:00:00Z'),
  observe(E.job,'2026-11-01T08:00:00Z','2026-11-01T08:00:00Z',def({cron:'30 1 * * *',timezone:ny},'2026-10-01T00:00:00Z')),
  // 2026-11-01 01:30 America/New_York happens twice: 05:30Z (EDT) and 06:30Z (EST)
  attempt({job:E.job,run:E.a,attempt:E.att1,occurrence:occ(ny,'2026-11-01T05:30:00Z',0),ordinal:1,sequence:1,state:'succeeded',observed:'2026-11-01T05:30:05Z',terminal:'2026-11-01T05:30:20Z'}),
  attempt({job:E.job,run:E.b,attempt:E.att2,occurrence:occ(ny,'2026-11-01T06:30:00Z',1),ordinal:1,sequence:1,state:'succeeded',observed:'2026-11-01T06:30:05Z',terminal:'2026-11-01T06:30:20Z'}),
 ]);
 const page=await rctx.newPage();
 await open(page);
 await openJob(page,E.job);
 await expect(page.getByTestId('job-definition')).toContainText(ny);
 await expect(run(page,E.b)).toContainText('Second occurrence of a repeated local time');
 await expect(run(page,E.a)).not.toContainText('Second occurrence of a repeated local time');
 await expect(page.getByTestId('job-health')).toContainText('Current job health: Succeeded');
});

test('a local time that does not exist (clock moved forward) is reported as skipped, not as a missed run',async()=>{
 const F={job:id(),run:id(),att:id()};
 const ny='America/New_York';
 await seed([
  clock('2026-03-08T12:00:00Z'),
  observe(F.job,'2026-03-08T12:00:00Z','2026-03-08T12:00:00Z',def({cron:'30 2 * * *',timezone:ny},'2026-03-01T00:00:00Z')),
  attempt({job:F.job,run:F.run,attempt:F.att,occurrence:occ(ny,'2026-03-07T07:30:00Z',0),ordinal:1,sequence:1,state:'succeeded',observed:'2026-03-07T07:30:05Z',terminal:'2026-03-07T07:30:20Z'}),
 ]);
 const page=await rctx.newPage();
 await open(page);
 await openJob(page,F.job);
 await expect(page.getByTestId('job-health')).toContainText('Current job health: Succeeded');
 await expect(page.getByTestId('job-health')).toContainText('does not exist');
 await expect(page.getByTestId('job-skipped')).toContainText('Skipped: local time');
 await expect(page.getByTestId('job-skipped')).toContainText('does not exist in America/New_York');
 await expect(page.getByTestId('job-health')).not.toContainText('Missed');
});

test('overlapping runs are recorded, never dropped or merged, and say so',async()=>{
 const G={job:id(),x:id(),y:id(),ax:id(),ay:id()};
 await seed([
  clock('2026-11-10T12:00:00Z'),
  observe(G.job,'2026-11-10T12:00:00Z','2026-11-10T12:00:00Z',def(null,'2026-11-01T00:00:00Z')),
  attempt({job:G.job,run:G.x,attempt:G.ax,schedule:'manual.x',ordinal:1,sequence:1,state:'started',observed:'2026-11-10T10:00:00Z'}),
  attempt({job:G.job,run:G.y,attempt:G.ay,schedule:'manual.y',ordinal:1,sequence:1,state:'started',observed:'2026-11-10T10:10:00Z'}),
  attempt({job:G.job,run:G.y,attempt:G.ay,schedule:'manual.y',ordinal:1,sequence:2,state:'succeeded',observed:'2026-11-10T10:10:00Z',terminal:'2026-11-10T10:15:00Z'}),
  attempt({job:G.job,run:G.x,attempt:G.ax,schedule:'manual.x',ordinal:1,sequence:2,state:'succeeded',observed:'2026-11-10T10:00:00Z',terminal:'2026-11-10T10:20:00Z'}),
 ]);
 const page=await rctx.newPage();
 await open(page);
 await openJob(page,G.job);
 await expect(page.getByTestId('job-definition')).toContainText('allow: a run that starts while another runs is recorded, never dropped or merged');
 await expect(page.getByTestId('job-definition')).toContainText('No calendar schedule');
 await expect(page.locator('[data-testid=run-row]')).toHaveCount(2);
 await expect(run(page,G.x)).toContainText('Overlaps with 1 other run');
 await expect(run(page,G.y)).toContainText('Overlaps with 1 other run');
});

test('a correction keeps the original failed result visible with its audit; reason text is inert',async()=>{
 const H={job:id(),run:id(),att:id()};
 const canary='<img src=x onerror="window.__pwn=1"> verified by hand & <b>ok</b>';
 await seed([
  clock('2026-11-10T12:00:00Z'),
  attempt({job:H.job,run:H.run,attempt:H.att,schedule:'manual.h',ordinal:1,sequence:1,state:'failed',observed:'2026-11-10T11:00:00Z',terminal:'2026-11-10T11:00:10Z'}),
  {op:'correct',job:H.job,attempt:H.att,version:'1',state:'succeeded',reason:canary},
 ]);
 const page=await rctx.newPage();
 await page.addInitScript(()=>{(window as unknown as {__pwn?:number}).__pwn=0;});
 await open(page);
 await openJob(page,H.job);
 await run(page,H.run).getByRole('button',{name:`Open run ${H.run}`}).click();
 const a=page.locator('[data-testid=attempt-row]');
 await expect(a).toContainText('Original result: Failed');
 const c=page.getByTestId('correction');
 await expect(c).toHaveCount(1);
 await expect(c).toContainText('Corrected to Succeeded');
 await expect(c).toContainText(canary);
 await expect(page.locator('img[src=x]')).toHaveCount(0);
 expect(await page.evaluate(()=>(window as unknown as {__pwn?:number}).__pwn)).toBe(0);
});

test('a reader without access, or in another organization, sees Not found; revoking the grant clears the page on refresh',async()=>{
 const stranger:Reader=await (async()=>{
  const other=await createOrg(owners,'job other org');
  const op=await createProject(owners,other,'other P');
  return createReader(owners,other,[op]);
 })();
 const sp=await loggedIn(stranger);
 await open(sp);
 await expect(sp.locator('[data-testid=job-row]')).toHaveCount(0);
 await expect(sp.getByText('Not found',{exact:false}).first()).toBeVisible();
 await sp.context().close();

 const page=await rctx.newPage();
 await open(page);
 await expect(page.locator('[data-testid=job-row]').first()).toBeVisible();
 await setGrant(owners,org,reader.id,p1,false);
 await page.getByRole('button',{name:'Refresh',exact:true}).click();
 await expect(page.locator('[data-testid=job-row]')).toHaveCount(0);
 await expect(page.getByText('Not found',{exact:false}).first()).toBeVisible();
 await setGrant(owners,org,reader.id,p1,true);
 void writerUser;
});
