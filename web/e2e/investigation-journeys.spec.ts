// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect,request as pwRequest,type Browser,type Locator,type Page} from '@playwright/test';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {login,owner} from './support/real';
import {deepLink,seedJourney,type JourneySeed} from './support/journey';

// Real server, real Chrome, real data. One reader works through the investigation with the KEYBOARD ONLY (real Tab, Space, Enter and
// typed characters; the only non-keyboard navigation is the first address, which is how a person opens a pasted deep link): sign-in
// form, queue, incident, trace, log, metric, release, replay, profile and job. The organization, project and time window stay
// visible on every leg and are compared to the window the deep link carried.
//
// WHAT THIS DOES NOT SATISFY (each leg is recorded in docs/user/investigation-acceptance.md with its reason):
//  - queue -> incident: incidents have no committed create route, so the queue is really empty and has no incident link to follow;
//    the incident leg asserts the typed not-found answer for an incident that cannot exist.
//  - release: the release registry is readable only by an organization administrator and has no committed create route; the leg asserts
//    the typed not-available answer a telemetry reader really gets.
//  - job: no SDK-to-backend path creates job attempts and the seed route that does is not committed (SOUNDPOST_E2E_JOB_SEED); the leg
//    asserts the real empty state, so scheduled failure -> retry is NOT satisfied in the browser (the 07.04 smoke owns that journey).
//  - frontend -> API -> database with a real source map: no committed route renders a mapped frame without the uncommitted issue and release
//    seed routes; the overlapping-span trace is driven, the source-map part is NOT.
//  - replay: chunks are the closed format the Go validator accepts; real recorder chunks are refused by the committed validator.
test.describe.configure({mode:'serial'});
let br:Browser,owners:Page,seed:JourneySeed,page:Page,windowText='';
const shots=process.env.SOUNDPOST_SHOT_DIR;
const evidenceFile=process.env.SOUNDPOST_EVIDENCE_FILE;
const evidence:Record<string,unknown>[]=[];
const NONE='b'.repeat(32);

/** Presses Tab (or Shift+Tab when the target lies before the focused element, as a person would) until `target` holds focus. The
 * keyboard is the only way the page moves. */
async function keyTo(target:Locator,max=200):Promise<number>{
 await expect(target).toBeVisible();
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
/** The organization, project and window are on screen, and the window is the one the deep link carried. */
async function scopeVisible():Promise<void>{
 await expect(page.getByTestId('visible-org')).toHaveText(seed.explore.org);
 await expect(page.getByTestId('visible-projects')).toHaveText(seed.explore.p1);
 const win=page.getByRole('term').filter({hasText:'Window'}).locator('xpath=following-sibling::dd[1]');
 const text=(await win.innerText()).trim();
 if(windowText==='')windowText=text;
 expect(text).toBe(windowText);
 expect(text).toMatch(/ to /);
}
async function record(leg:string,detail:Record<string,unknown>):Promise<void>{
 await scopeVisible();
 let shot='';
 if(shots){shot=join(shots,`journey-${leg}.png`);await page.screenshot({path:shot,fullPage:true});}
 evidence.push({leg,url:page.url().replace(/#.*/,'#…'),window:windowText,screenshot:shot,...detail});
}
const statusWords=async():Promise<string>=>(await page.locator('main .status').first().innerText()).replace(/\s+/g,' ').trim();

test.beforeAll(async({browser})=>{
 test.setTimeout(280_000);
 br=browser;
 const o=owner();
 owners=await (await browser.newContext()).newPage();
 await login(owners,o.email,o.password);
 seed=await seedJourney(owners,await pwRequest.newContext());
 if(shots)mkdirSync(shots,{recursive:true});
});
test.afterAll(()=>{
 if(evidenceFile)writeFileSync(evidenceFile,JSON.stringify({ids:{org:seed.explore.org,project:seed.explore.p1,otherProject:seed.explore.p2,reader:seed.explore.reader.id,cleanTrace:seed.traces.clean.trace,gatewayTrace:seed.traces.gateway.trace,replay:seed.replays.clean.replay,profile:seed.profile,metricSource:seed.explore.metricP1.id,logSource:seed.explore.logP1.id,policyRevisions:{metric:seed.explore.metricP1.policyRevision,log:seed.explore.logP1.policyRevision}},legs:evidence},null,1));
});

test('sign in with the keyboard alone, then open a native deep link: the scope is on screen',async()=>{
 const ctx=await br.newContext();
 page=await ctx.newPage();
 await page.goto('/');
 await expect(page.getByRole('heading',{level:1,name:'Access your installation'})).toBeVisible();
 await typeInto(page.getByLabel('Email'),seed.explore.reader.email);
 await keyTo(page.getByLabel('Password',{exact:true}));
 await page.keyboard.type(seed.explore.reader.password);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:1,name:'Account access'})).toBeVisible();
 // A deep link is an address, so opening it is the one step that is not a key press on the page.
 await page.goto(deepLink(seed,'queue'));
 await expect(page.getByRole('heading',{level:2,name:'Investigation: Queue'})).toBeFocused();
 await scopeVisible();
});

test('queue: really empty, with the unbuilt parts said to be not available; no incident exists to follow (NOT satisfied: queue to incident link)',async()=>{
 await expect(page.locator('main .status[data-state="empty"]')).toBeVisible();
 await expect(page.locator('main [data-section="urgency"][data-state="not_available"]')).toBeVisible();
 await expect(page.locator('main tr[data-incident]')).toHaveCount(0);
 await record('queue',{state:'empty',words:await statusWords(),satisfied:'queue reached; the incident link cannot be followed because no incident can be created through a committed route'});
});

test('incident: the keyboard opens an incident ID form and an incident that cannot exist reads Not found',async()=>{
 await goTo('Incidents');
 await typeInto(page.getByLabel('Incident ID'),NONE);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Incident ${NONE}`})).toBeFocused();
 await expect(page.locator('main .status[data-state="unauthorized"]')).toContainText('Not found');
 await record('incident',{state:'unauthorized (not found)',words:await statusWords(),satisfied:false,reason:'no committed incident create route'});
});

test('trace (frontend to API to database): overlapping branches give an exact duration and the dependency boundary is stated',async()=>{
 await goTo('Traces');
 await typeInto(page.getByLabel('Trace ID'),seed.traces.clean.trace);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Trace ${seed.traces.clean.trace}`})).toBeFocused();
 await expect(page.getByTestId('observed-duration')).toHaveText('Observed duration of this trace: exactly 100 ms.');
 await expect(page.getByTestId('limits').locator('[data-limit="dependency_boundary"]')).toContainText('dependency boundary');
 await record('trace-frontend-api-database',{state:'ready',trace:seed.traces.clean.trace,sourceMap:'NOT satisfied: no mapped frame without uncommitted seed routes'});
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

test('release: a telemetry reader gets the typed not-available answer for the release registry (NOT satisfied: no committed release create route)',async()=>{
 await goTo('Releases');
 await typeInto(page.getByLabel('Release ID'),NONE);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Release ${NONE}`})).toBeFocused();
 await expect(page.locator('main .status[data-state="unsupported"]')).toContainText('organization administrator');
 await record('release',{state:'unsupported (not available)',words:await statusWords(),satisfied:false,reason:'registry is administrator-only and has no committed create route'});
});

test('replay: the keyboard opens the masked replay and steps it; the viewer reports a real status',async()=>{
 await goTo('Replays');
 await typeInto(page.getByLabel('Replay ID'),seed.replays.clean.replay);
 await page.keyboard.press('Enter');
 await expect(page.getByRole('heading',{level:2,name:`Replay ${seed.replays.clean.replay}`})).toBeFocused();
 await expect(page.getByTestId('replay-frame')).toBeVisible();
 await activate(page.getByRole('button',{name:'Step to the next event'}));
 await expect(page.getByTestId('viewer-status')).not.toHaveAttribute('data-status','none');
 await record('replay',{state:'ready',replay:seed.replays.clean.replay,viewerStatus:await page.getByTestId('viewer-status').getAttribute('data-status'),chunks:'closed format, not recorder chunks'});
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

test('job: the real jobs read is empty and says so (NOT satisfied: scheduled failure to retry needs job attempts no committed route can create)',async()=>{
 await goTo('Jobs');
 await expect(page.locator('main .status[data-state="empty"]')).toBeVisible();
 await expect(page.getByText('This project has no jobs. Nothing is missing.')).toBeVisible();
 await record('job',{state:'empty',words:await statusWords(),satisfied:false,reason:'no SDK-to-backend job attempt path; the seed route is not committed'});
});

test('the contextual scope never left the screen: the last address still carries the organization, project and window of the first',async()=>{
 const hash=new URLSearchParams(new URL(page.url()).hash.slice(1));
 expect(hash.get('org')).toBe(seed.explore.org);
 expect(hash.get('projects')).toBe(seed.explore.p1);
 expect(hash.get('start')).toBe(String(seed.start));
 expect(hash.get('end')).toBe(String(seed.end));
});

test('this spec drives the page with the keyboard only: no pointer or fill call appears outside the fixture',()=>{
 const source=readFileSync(fileURLToPath(import.meta.url),'utf8');
 const pointer=new RegExp(`\\.(${['click','dblclick','fill','check','uncheck','selectOption','hover','tap','dragTo','press'+'Sequentially'].join('|')})\\(`);
 expect(source.split('\n').filter((l)=>pointer.test(l))).toEqual([]);
});
