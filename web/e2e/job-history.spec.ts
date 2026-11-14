// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {test,expect,type APIRequestContext,type Browser,type BrowserContext,type Page} from '@playwright/test';
import {createOrg,createProject,createReader,field,id,ingestJobAttempt,login,onboardJobSource,owner,postJson,setGrant,type JobAttemptInput,type Reader,type Source} from './support/real';

// Real server, real Chrome, real HTTPS, real sessions, real routes only. The job data is produced the product's own way:
//   source credential -> POST /ingest/v1/batches (kind job_attempt) -> the leader-only background runner (`soundpost serve`, its job
//   producer, acting as the in-process system principal) -> durable job books -> POST /api/v1/jobs/list and /api/v1/jobs/view -> the UI.
// The test waits (polls the real /api/v1/jobs/view) until the runner has applied every ingested event; nothing writes a job book but the runner.
//
// Assertions REMOVED because the real path cannot reproduce them (no committed source of job/schedule definitions exists, so the runner
// never calls ObserveSchedule or Correct; a scheduled job reads `unknown / no_schedule_observer`, a job with only attempt evidence reads
// "No job definition has been reported"):
//  - a schedule definition's grace, time zone and cron text, and "Schedule observer: fresh";
//  - missed WITH external observer evidence, and an observer outage / incomplete data path reading Unknown, never missed;
//  - a local time that does not exist (skipped by DST) reported as skipped, and the schedule-derived expected occurrences;
//  - overlap policy and the overlap text derived from a definition ("allow: ..."): the per-run overlap sentence from attempt times IS kept;
//  - a correction (Correct) keeping the original failed result with its audit and the inert reason text.
// KEPT (all through ingest): start -> failure -> retry -> success, the next occurrence, redelivery counted nowhere, a late old completion
// that never overwrites current health, cancellation never success, ID-only cause links, Refresh keeping the selection, the repeated local
// time (fold 1) carried by the occurrence key itself, overlap sentences, scope and revocation.
test.describe.configure({mode:'serial',timeout:150_000});

let br:Browser,rctx:BrowserContext,owners:Page,org:string,p1:string,reader:Reader,src:Source,ingestApi:APIRequestContext,api:Page;

const ns=(ms:number):string=>String(BigInt(ms)*1_000_000n);
const WINDOW={start:'1',end:'1800000000000000000'};
const hash=(o:string,p:string,view='jobs'):string=>`#${new URLSearchParams({org:o,projects:p,start:WINDOW.start,end:WINDOW.end,tz:'UTC',view})}`;
// All event times are real recent instants, anchored on the wall clock of the test run (ingest admission bounds event time). The runner's
// job producer reads a project's journal ordered by the attempt's start time (every event of an attempt carries it), then record ID, and a
// row that reaches the journal BEHIND the newest row it has covered is only found by its periodic sweep (minutes apart). Every event is
// therefore ingested in (attempt start, record ID) order, also across the tests (attempt starts: test 1 minutes 0-120, cancellation 150,
// repeated local time 160-220, overlap 230-240); the terminal instants inside the events still tell the true story (a late old completion).
const BASE=Math.floor(Date.now()/60_000)*60_000-5*3600_000;
const at=(minutes:number,seconds=0):number=>BASE+minutes*60_000+seconds*1000;
// internal/jobs/reducer.go OccurrenceKey: "s.<scheduled UTC ns>.f<fold>.<first 4 bytes of sha256(\"soundpost.jobs.zone\\0\"+tz) as hex>".
const occurrenceKey=(tz:string,ms:number,fold:0|1):string=>`s.${ns(ms)}.f${fold}.${createHash('sha256').update(`soundpost.jobs.zone\0${tz}`).digest().subarray(0,4).toString('hex')}`;

type Ev=Omit<JobAttemptInput,'epoch'|'observed'|'terminal'>&{observed:number;terminal?:number};
const EPOCH=id();
async function send(e:Ev):Promise<void>{
 const {observed,terminal,...rest}=e;
 await ingestJobAttempt(ingestApi,src,{...rest,epoch:EPOCH,observed:ns(observed),...(terminal!==undefined?{terminal:ns(terminal)}:{})});
}
/** Poll the real /api/v1/jobs/view as the reader until every run holds exactly the accepted event count the runner must reach. */
async function applied(job:string,runs:Record<string,number>):Promise<void>{
 await expect.poll(async()=>{
  const out:Record<string,number>={};
  for(const run of Object.keys(runs)){
   const r=await postJson(api,'/api/v1/jobs/view',{org,project:p1,job,run});
   const attempts=field(field(r.json,'run'),'attempts');
   out[run]=Array.isArray(attempts)?attempts.reduce((n:number,a:unknown)=>n+(Number(field(a,'events_accepted'))||0),0):0;
  }
  return out;
 },{timeout:90_000,intervals:[250,500,1000]}).toEqual(runs);
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

test.beforeAll(async({browser,playwright})=>{
 test.setTimeout(240_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 org=await createOrg(owners,'job history e2e org');
 p1=await createProject(owners,org,'jobs P1');
 reader=await createReader(owners,org,[p1]);
 src=await onboardJobSource(owners,org,p1);
 ingestApi=await playwright.request.newContext();
 api=await loggedIn(reader);
 rctx=await browser.newContext();
 const page=await rctx.newPage();
 await login(page,reader.email,reader.password);
 await page.close();
});
test.afterAll(async()=>{await ingestApi.dispose();});
test.afterEach(async()=>{for(const p of rctx.pages())await p.close();});

const A={job:id(),run0:id(),run1:id(),run2:id(),att0:id(),att1:id(),att2:id(),att3:id(),trace:id(),error:id()};

test('start, failure, retry, success, the next occurrence, then a late old completion: failed history stays, recovery and health are separate, health is never overwritten',async()=>{
 const o0='manual.old',o1='manual.retry',o2='manual.next';
 // occurrence 0: a long run whose only attempt starts first and completes (fails) late, after occurrence 2 already succeeded
 await send({job:A.job,run:A.run0,attempt:A.att0,occurrence:o0,ordinal:1,sequence:1,state:'started',observed:at(0,5)});
 await send({job:A.job,run:A.run0,attempt:A.att0,occurrence:o0,ordinal:1,sequence:2,state:'failed',observed:at(0,5),terminal:at(140)});
 // occurrence 1: attempt 1 fails (with a cause trace and error), the retry succeeds: the RUN recovers
 await send({job:A.job,run:A.run1,attempt:A.att1,occurrence:o1,ordinal:1,sequence:1,state:'started',observed:at(60,5)});
 const failed:Ev={job:A.job,run:A.run1,attempt:A.att1,occurrence:o1,ordinal:1,sequence:2,state:'failed',observed:at(60,5),terminal:at(60,15),causeTrace:A.trace,causeError:A.error};
 await send(failed);
 // redelivery of an applied (epoch, sequence) under a new record: counted nowhere
 await send(failed);
 await send({job:A.job,run:A.run1,attempt:A.att2,occurrence:o1,ordinal:2,sequence:1,state:'started',observed:at(61)});
 await send({job:A.job,run:A.run1,attempt:A.att2,occurrence:o1,ordinal:2,sequence:2,state:'succeeded',observed:at(61),terminal:at(61,30)});
 // the next occurrence succeeds
 await send({job:A.job,run:A.run2,attempt:A.att3,occurrence:o2,ordinal:1,sequence:1,state:'started',observed:at(120,5)});
 await send({job:A.job,run:A.run2,attempt:A.att3,occurrence:o2,ordinal:1,sequence:2,state:'succeeded',observed:at(120,5),terminal:at(120,20)});
 await applied(A.job,{[A.run0]:2,[A.run1]:4,[A.run2]:2});

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
 await expect(page.getByTestId('job-source')).toContainText(/Committed source version \d+/);
 await expect(page.getByTestId('job-source')).toContainText(/Origin cursor of the newest attempt evidence: [0-9a-f]{32}:\d+/);
 // No schedule-definition source is committed: the job reads as attempt evidence only.
 await expect(page.getByTestId('job-definition')).toContainText('No job definition has been reported');

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
 await expect(page.getByTestId('job-source')).toContainText(/Committed source version \d+/);
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
 await send({job:J.job,run:J.run,attempt:J.att,occurrence:'manual.cancelled',ordinal:1,sequence:1,state:'started',observed:at(150)});
 await send({job:J.job,run:J.run,attempt:J.att,occurrence:'manual.cancelled',ordinal:1,sequence:2,state:'cancelled',observed:at(150),terminal:at(150,30)});
 await applied(J.job,{[J.run]:2});
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

test('a repeated local time (clock moved back) is a separate second occurrence, in words',async()=>{
 // The occurrence key itself carries the scheduled instant and the fold, so this needs no definition: two runs for the same America/New_York
 // wall time, one hour apart, the second with fold 1.
 const E={job:id(),a:id(),b:id(),att1:id(),att2:id()};
 const ny='America/New_York';
 const ka=occurrenceKey(ny,at(160),0),kb=occurrenceKey(ny,at(220),1);
 await send({job:E.job,run:E.a,attempt:E.att1,occurrence:ka,ordinal:1,sequence:1,state:'started',observed:at(160,5)});
 await send({job:E.job,run:E.a,attempt:E.att1,occurrence:ka,ordinal:1,sequence:2,state:'succeeded',observed:at(160,5),terminal:at(160,20)});
 await send({job:E.job,run:E.b,attempt:E.att2,occurrence:kb,ordinal:1,sequence:1,state:'started',observed:at(220,5)});
 await send({job:E.job,run:E.b,attempt:E.att2,occurrence:kb,ordinal:1,sequence:2,state:'succeeded',observed:at(220,5),terminal:at(220,20)});
 await applied(E.job,{[E.a]:2,[E.b]:2});
 const page=await rctx.newPage();
 await open(page);
 await openJob(page,E.job);
 await expect(run(page,E.b)).toContainText('Second occurrence of a repeated local time');
 await expect(run(page,E.a)).not.toContainText('Second occurrence of a repeated local time');
 await expect(run(page,E.a)).toContainText('Scheduled for');
 await expect(page.getByTestId('job-health')).toContainText('Current job health:');
});

test('overlapping runs are recorded, never dropped or merged, and say so',async()=>{
 const G={job:id(),x:id(),y:id(),ax:id(),ay:id()};
 await send({job:G.job,run:G.x,attempt:G.ax,occurrence:'manual.x',ordinal:1,sequence:1,state:'started',observed:at(230)});
 await send({job:G.job,run:G.x,attempt:G.ax,occurrence:'manual.x',ordinal:1,sequence:2,state:'succeeded',observed:at(230),terminal:at(250)});
 await send({job:G.job,run:G.y,attempt:G.ay,occurrence:'manual.y',ordinal:1,sequence:1,state:'started',observed:at(240)});
 await send({job:G.job,run:G.y,attempt:G.ay,occurrence:'manual.y',ordinal:1,sequence:2,state:'succeeded',observed:at(240),terminal:at(245)});
 await applied(G.job,{[G.x]:2,[G.y]:2});
 const page=await rctx.newPage();
 await open(page);
 await openJob(page,G.job);
 await expect(page.getByTestId('job-definition')).toContainText('No job definition has been reported');
 await expect(page.locator('[data-testid=run-row]')).toHaveCount(2);
 await expect(run(page,G.x)).toContainText('Overlaps with 1 other run');
 await expect(run(page,G.y)).toContainText('Overlaps with 1 other run');
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
});
