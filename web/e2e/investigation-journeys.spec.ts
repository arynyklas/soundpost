// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type Browser,type Locator,type Page} from '@playwright/test';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {login,owner} from './support/real';
import {focusLinkByKeyboard,tabReachesLinks} from './support/audit';
import {deepLink,realLink,seedJourney,seedRealJourney,type JourneySeed,type RealJourneySeed} from './support/journey';

// Real server, real Chrome, real data. Two readers work through the investigation with the KEYBOARD ONLY (real Tab, Space, Enter and
// typed characters; the only non-keyboard navigation is the first address of a leg group, which is how a person opens a pasted deep link).
// The organization, project and time window stay visible on every leg and are compared to the window the deep link carried.
//
// Organization A (a telemetry/replay/profile reader): sign-in form, trace (frontend -> API -> database, overlapping branches), trace
// (gateway -> dependency), log, metric, replay, profile.
// Organization B (an organization administrator who also holds telemetry and artifact reads; every record is made by a real route):
//  - queue -> incident: the incident the leader-only runner opened from an ingested error is a link in the queue, and the keyboard follows it;
//  - trace -> failure -> issue -> mapped frame: three real spans (frontend, API, PostgreSQL), the real failure of a real minified bundle
//    recorded in the API span, the issue the runner's producer made of it, and its frames mapped by the REAL source map the real
//    symbolication worker reads (original function and line); this needs the symbolication sandbox (h.sh E2E_SANDBOX=1);
//  - release: the release the occurrence ran in, registered through the real registration route, with its artifact binding and ancestry;
//  - job: a run the real Python SDK produced (attempt 1 raises, the retry succeeds), read as recovered with its captured error as the cause.
//    The SDK records a manual execution (no schedule definition is reported by the SDK); schedule-derived evidence is job-history.spec.ts.
test.describe.configure({mode:'serial'});
let br:Browser,owners:Page,seed:JourneySeed,real:RealJourneySeed,page:Page,windowText='',scope={org:'',project:'',start:'',end:''};
const shots=process.env.SOUNDPOST_SHOT_DIR;
const evidenceFile=process.env.SOUNDPOST_EVIDENCE_FILE;
const evidence:Record<string,unknown>[]=[];

let linkTab:boolean|undefined;
/** Presses Tab (or Shift+Tab when the target lies before the focused element, as a person would) until `target` holds focus. The
 * keyboard is the only way the page moves. */
async function keyTo(target:Locator,max=200):Promise<number>{
 await expect(target).toBeVisible();
 linkTab??=await tabReachesLinks(page);
 // Where Tab skips links (WebKit on macOS/Windows without the platform preference) a link is focused as that platform's own link key
 // does; everywhere else Tab itself must reach it.
 if(!linkTab&&await target.evaluate((e)=>e.tagName==='A'))await focusLinkByKeyboard(page,target);
 for(let i=0;i<max;i++){
  const where=await target.evaluate((e)=>{const a=document.activeElement;if(e===a)return 'here';if(!a||a===document.body)return 'forward';return (e.compareDocumentPosition(a)&Node.DOCUMENT_POSITION_FOLLOWING)!==0?'back':'forward';});
  if(where==='here')return i;
  await page.keyboard.press(where==='back'?'Shift+Tab':'Tab');
 }
 throw Error('keyboard never reached the target');
}
/** Enter on a control the keyboard has reached. */
async function activate(target:Locator):Promise<void>{await keyTo(target);await page.keyboard.press('Enter');}
async function typeInto(target:Locator,text:string):Promise<void>{await keyTo(target);await page.keyboard.press('Control+A');await page.keyboard.type(text);}
const section=(name:string):Locator=>page.getByRole('navigation',{name:'Investigation sections'}).getByRole('link',{name,exact:true});
async function goTo(name:string):Promise<void>{
 await activate(section(name));
 await expect(page.getByRole('heading',{level:2,name:`Investigation: ${name}`})).toBeFocused();
}
/** The sign-in form with the keyboard alone: typed characters and Enter. */
async function signIn(email:string,password:string):Promise<void>{
 await expect(page.getByRole('heading',{level:1,name:'Access your installation'})).toBeVisible();
 await typeInto(page.getByLabel('Email'),email);
 await keyTo(page.getByLabel('Password',{exact:true}));
 await page.keyboard.type(password);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:1,name:'Account access'})).toBeVisible();
}
/** The window the console must print for a start and end in nanoseconds: computed here from the seeded values, not by the console's own formatter. */
const windowWords=(start:string,end:string):string=>{
 const at=(ns:string):string=>new Intl.DateTimeFormat('en-GB',{timeZone:'UTC',dateStyle:'medium',timeStyle:'medium'}).format(new Date(Number(BigInt(ns)/1_000_000n)));
 return `${at(start)} to ${at(end)} (end excluded)`;
};
/** The organization, project and window are on screen, and the window is the one the deep link carried (the seeded start and end, both ends). */
async function scopeVisible():Promise<void>{
 await expect(page.getByTestId('visible-org')).toHaveText(scope.org);
 await expect(page.getByTestId('visible-projects')).toHaveText(scope.project);
 const win=page.getByRole('term').filter({hasText:'Window'}).locator('xpath=following-sibling::dd[1]');
 const text=(await win.innerText()).trim().replace(/\s+/g,' ');
 expect(text).toBe(windowWords(scope.start,scope.end));
 if(windowText==='')windowText=text;
 expect(text).toBe(windowText);
}
async function record(leg:string,detail:Record<string,unknown>):Promise<void>{
 await scopeVisible();
 let shot='';
 if(shots){shot=join(shots,`journey-${leg}.png`);await page.screenshot({path:shot,fullPage:true});}
 evidence.push({leg,url:page.url().replace(/#.*/,'#…'),window:windowText,screenshot:shot,...detail});
}

test.beforeAll(async({browser})=>{
 test.setTimeout(420_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 const api=await pwRequest.newContext();
 seed=await seedJourney(owners,api);
 real=await seedRealJourney(owners,browser,api);
 if(shots)mkdirSync(shots,{recursive:true});
});
test.afterAll(()=>{
 if(evidenceFile)writeFileSync(evidenceFile,JSON.stringify({ids:{org:seed.explore.org,project:seed.explore.p1,otherProject:seed.explore.p2,reader:seed.explore.reader.id,cleanTrace:seed.traces.clean.trace,gatewayTrace:seed.traces.gateway.trace,replay:seed.replays.clean.replay,profile:seed.profile,metricSource:seed.explore.metricP1.id,logSource:seed.explore.logP1.id,policyRevisions:{metric:seed.explore.metricP1.policyRevision,log:seed.explore.logP1.policyRevision},
  real:{org:real.ev.org,project:real.ev.project,reader:real.reader.id,incident:real.incident,trace:real.trace.trace,occurrence:real.trace.occurrence,issue:real.ev.real.issue,release:real.ev.real.release,artifact:real.ev.artifact,job:real.job.job,run:real.job.run}},legs:evidence},null,1));
});

test('sign in with the keyboard alone, then open a native deep link: the scope is on screen',async()=>{
 const ctx=await br.newContext();
 page=await ctx.newPage();
 scope={org:seed.explore.org,project:seed.explore.p1,start:String(seed.start),end:String(seed.end)};
 await page.goto('/');
 await signIn(seed.explore.reader.email,seed.explore.reader.password);
 // A deep link is an address, so opening it is the one step that is not a key press on the page.
 await page.goto(deepLink(seed,'queue'));
 await expect(page.getByRole('heading',{level:2,name:'Investigation: Queue'})).toBeFocused();
 await scopeVisible();
});

test('trace (frontend to API to database): overlapping branches give an exact duration and the dependency boundary is stated',async()=>{
 await goTo('Traces');
 await typeInto(page.getByLabel('Trace ID'),seed.traces.clean.trace);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Trace ${seed.traces.clean.trace}`})).toBeFocused();
 await expect(page.getByTestId('observed-duration')).toHaveText('Observed duration of this trace: exactly 100 ms.');
 await expect(page.getByTestId('limits').locator('[data-limit="dependency_boundary"]')).toContainText('dependency boundary');
 await record('trace-frontend-api-database',{state:'ready',trace:seed.traces.clean.trace});
});

test('trace (gateway to dependency): the dependency call ends at the boundary, stated in words',async()=>{
 await typeInto(page.getByLabel('Trace ID'),seed.traces.gateway.trace);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Trace ${seed.traces.gateway.trace}`})).toBeFocused();
 await expect(page.locator('table.path-table tbody tr[data-span]')).toHaveCount(2);
 await expect(page.getByTestId('limits').locator('[data-limit="dependency_boundary"]')).toContainText('1 dependency call ends at the dependency boundary');
 await record('trace-gateway-dependency',{state:'ready',trace:seed.traces.gateway.trace});
});

test('log: Explore with LogQL chosen by the keyboard returns the real ingested lines',async()=>{
 await goTo('Explore');
 await keyTo(page.getByRole('radio',{name:'PromQL',exact:true})); // Tab reaches only the checked radio of a group; the arrow key moves the choice
 await page.keyboard.press('ArrowRight');
 await expect(page.getByRole('radio',{name:'LogQL',exact:true})).toBeChecked();
 await typeInto(page.getByLabel('Query expression'),'{app="web"}');
 await activate(page.getByRole('button',{name:'Run query',exact:true}));
 await expect(page.getByTestId('evaluated-with')).toBeVisible();
 await expect(page.getByTestId('results')).toContainText('alice');
 await expect(page.getByTestId('results').locator('[data-project]').first()).toHaveAttribute('data-state','ready');
 await record('log',{state:'ready',evaluatedWith:(await page.getByTestId('evaluated-with').innerText()).replace(/\s+/g,' ').trim()});
});

test('metric: PromQL chosen by the keyboard returns the exact ingested sample',async()=>{
 await keyTo(page.getByRole('radio',{name:'LogQL',exact:true}));
 await page.keyboard.press('ArrowLeft');
 await expect(page.getByRole('radio',{name:'PromQL',exact:true})).toBeChecked();
 await keyTo(page.getByRole('radio',{name:'Range over the selected window',exact:true}));
 await page.keyboard.press('ArrowLeft');
 await expect(page.getByRole('radio',{name:'Instant',exact:true})).toBeChecked();
 await typeInto(page.getByLabel('Query expression'),'explore_gauge');
 await activate(page.getByRole('button',{name:'Run query',exact:true}));
 const panel=page.getByTestId('results').locator(`[data-project="${seed.explore.p1}"]`);
 await expect(panel).toHaveAttribute('data-state','ready',{timeout:20_000});
 await expect(panel.locator('[data-series]').locator('[data-kind]')).toHaveText('48');
 await record('metric',{state:'ready',value:'48',evaluatedWith:(await page.getByTestId('evaluated-with').innerText()).replace(/\s+/g,' ').trim()});
});

test('replay: the keyboard opens the masked replay and steps it; the viewer reports a real status',async()=>{
 await goTo('Replays');
 await typeInto(page.getByLabel('Replay ID'),seed.replays.clean.replay);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Replay ${seed.replays.clean.replay}`})).toBeFocused();
 await expect(page.getByTestId('replay-frame')).toBeVisible();
 await activate(page.getByRole('button',{name:'Step to the next event'}));
 await expect(page.getByTestId('viewer-status')).toHaveAttribute('data-status','ready');
 await expect(page.getByTestId('viewer-status')).toContainText('Events delivered to the viewer: 1');
 await record('replay',{state:'ready',replay:seed.replays.clean.replay,viewerStatus:await page.getByTestId('viewer-status').getAttribute('data-status'),chunks:'closed format; the real recorder path is replay-profile.spec.ts'});
});

test('profile: the keyboard opens the native profile with its measurement kinds kept apart',async()=>{
 await goTo('Profiles');
 await typeInto(page.getByLabel('Profile ID'),seed.profile);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Profile ${seed.profile}`})).toBeFocused();
 await expect(page.locator('main [data-state="measured"]').first()).toBeVisible();
 await expect(page.locator('main [data-state="not_measured"]').first()).toBeVisible();
 await record('profile',{state:'ready',profile:seed.profile});
});

test('the contextual scope never left the screen: the last address still carries the organization, project and window of the first',async()=>{
 const hash=new URLSearchParams(new URL(page.url()).hash.slice(1));
 expect(hash.get('org')).toBe(seed.explore.org);
 expect(hash.get('projects')).toBe(seed.explore.p1);
 expect(hash.get('start')).toBe(String(seed.start));
 expect(hash.get('end')).toBe(String(seed.end));
});

// ---- organization B: the journeys whose records are made by the runner, the release registry, the symbolication worker and the SDK ----

test('an organization administrator signs in with the keyboard alone and opens the queue of the real-journey organization',async()=>{
 const ctx=await br.newContext();
 page=await ctx.newPage();
 windowText='';
 scope={org:real.ev.org,project:real.ev.project,start:real.start,end:real.end};
 await page.goto('/');
 await signIn(real.reader.email,real.reader.password);
 await page.goto(realLink(real,'queue'));
 await expect(page.getByRole('heading',{level:2,name:'Investigation: Queue'})).toBeFocused();
 await scopeVisible();
});

test('queue to incident: the incident the runner opened from an ingested error is a link in the queue, and the keyboard follows it',async()=>{
 const row=page.locator(`tr[data-incident="${real.incident}"]`);
 await expect(row).toBeVisible();
 await activate(row.getByRole('link'));
 await expect(page.getByRole('heading',{level:2,name:`Incident ${real.incident}`})).toBeFocused();
 await expect(page.getByTestId('revision')).toBeVisible();
 await expect(page.getByTestId('source-badge')).toBeVisible();
 await record('queue-to-incident',{state:'ready',incident:real.incident,words:await page.getByTestId('response-words').innerText()});
});

test('trace to source: frontend, API and database in one trace, the real failure on the API span, its issue and its frames mapped by the real source map',async()=>{
 const {bundle}=real.ev.real;
 await goTo('Traces');
 await typeInto(page.getByLabel('Trace ID'),real.trace.trace);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Trace ${real.trace.trace}`})).toBeFocused();
 await expect(page.locator('table.path-table tbody tr[data-span]')).toHaveCount(3);
 await expect(page.getByTestId('limits').locator('[data-limit="dependency_boundary"]')).toContainText('dependency boundary');
 await activate(page.getByRole('button',{name:'Show details of span op.api, server, level 2'}));
 const details=page.getByTestId('span-details');
 await expect(details.locator('[data-target-kind="error"][data-target-available="yes"]')).toContainText(real.trace.occurrence);
 await activate(details.getByRole('link',{name:'Open the issue holding this occurrence'}));
 await expect(page.getByRole('heading',{level:2,name:`Issue ${real.ev.real.issue}`})).toBeFocused();
 await activate(page.getByRole('button',{name:`Show stored detail of occurrence ${real.trace.occurrence}`}));
 const frames=page.getByTestId('stored-frames').getByRole('article');
 await expect(frames).toHaveCount(2);
 for(const [i,f] of bundle.frames.entries()){
  await expect(frames.nth(i).getByTestId('frame-state')).toHaveText('Mapped');
  await expect(frames.nth(i).getByTestId('frame-original')).toContainText(`${real.ev.artifact}:${f.line}:${f.column} in ${f.function}`);
  await expect(frames.nth(i).getByTestId('frame-mapped')).toContainText(real.ev.mapHash);
 }
 await expect(frames.nth(0).getByTestId('frame-mapped')).toContainText(`${bundle.sourceFile}:${bundle.throwLine}:`);
 await expect(frames.nth(1).getByTestId('frame-mapped')).toContainText(`${bundle.sourceFile}:${bundle.callLine}:`);
 await expect(frames.nth(1).getByTestId('frame-mapped')).toContainText('in riskyCheckout');
 // The private source text the map carries is never shown to a reader without the sources grant.
 await expect(page.locator('body')).not.toContainText('PRIVATE-SOURCE-CANARY');
 await record('trace-to-mapped-frame',{state:'ready',trace:real.trace.trace,issue:real.ev.real.issue,occurrence:real.trace.occurrence,mapped:await frames.getByTestId('frame-mapped').allInnerTexts()});
});

test('release: the occurrence names the release it ran in; the keyboard opens the registered release with its artifact binding and its ancestry',async()=>{
 await activate(page.getByTestId('occ-release-link'));
 await expect(page.getByRole('heading',{level:2,name:`Release ${real.ev.real.release}`})).toBeFocused();
 await expect(page.getByTestId('release-label')).toContainText('v1.1');
 await expect(page.getByTestId('release-artifacts')).toContainText(real.ev.artifact);
 await expect(page.getByTestId('release-artifacts')).toContainText(real.ev.debugId);
 await expect(page.getByTestId('release-build')).toContainText(real.ev.build);
 await expect(page.getByTestId('release-parents').locator('li').first()).toContainText(real.ev.releases.root);
 await expect(page.getByTestId('release-parents').locator('li').first()).toContainText('registered');
 await record('release',{state:'ready',release:real.ev.real.release,parent:real.ev.releases.root,artifact:real.ev.artifact});
});

test('job: a run the real Python SDK produced (attempt 1 raised, the retry succeeded) reads as recovered with its captured error as the cause',async()=>{
 const {job,run}=real.job;
 await goTo('Jobs');
 const row=page.locator(`[data-testid=job-row][data-job="${job}"]`);
 await expect(row).toContainText('Succeeded');
 await activate(row.getByRole('button',{name:`Open job ${job}`}));
 await expect(page.getByRole('heading',{name:`Job ${job}`})).toBeVisible();
 await expect(page.getByTestId('job-health')).toContainText('Current job health: Succeeded');
 const runRow=page.locator(`[data-testid=run-row][data-run="${run}"]`);
 await expect(runRow).toContainText('Run recovery: Recovered after retry');
 await expect(runRow).toContainText('1 failed of 2 attempts');
 await activate(runRow.getByRole('button',{name:`Open run ${run}`}));
 await expect(page.getByRole('heading',{name:`Run ${run}`})).toBeVisible();
 const attempts=page.locator('[data-testid=attempt-row]');
 await expect(attempts).toHaveCount(2);
 await expect(attempts.nth(0)).toHaveAttribute('data-attempt',real.job.failedAttempt);
 await expect(attempts.nth(0)).toHaveAttribute('data-state','failed');
 await expect(attempts.nth(1)).toHaveAttribute('data-attempt',real.job.retryAttempt);
 await expect(attempts.nth(1)).toHaveAttribute('data-state','succeeded');
 await expect(page.getByTestId('cause-links')).toContainText(real.job.error);
 await record('job-retry',{state:'ready',job,run,failedAttempt:real.job.failedAttempt,retryAttempt:real.job.retryAttempt});
});

test('the contextual scope of the real-journey organization never left the screen: the last address carries its organization, project and window',async()=>{
 const hash=new URLSearchParams(new URL(page.url()).hash.slice(1));
 expect(hash.get('org')).toBe(real.ev.org);
 expect(hash.get('projects')).toBe(real.ev.project);
 expect(hash.get('start')).toBe(real.start);
 expect(hash.get('end')).toBe(real.end);
});

test('this spec drives the page with the keyboard only: no pointer or fill call appears outside the fixture',()=>{
 const source=readFileSync(fileURLToPath(import.meta.url),'utf8');
 const pointer=new RegExp(`\\.(${['click','dblclick','fill','check','uncheck','selectOption','hover','tap','dragTo','press'+'Sequentially','focus','blur','dispatchEvent'].join('|')})\\(`);
 expect(source.split('\n').filter((l)=>pointer.test(l))).toEqual([]);
});
